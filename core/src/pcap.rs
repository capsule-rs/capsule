/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use crate::dpdk::{CoreId, DpdkError, PortId, RxTxQueue};
use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::{debug, error};
use failure::{Fail, Fallible};
use std::fmt;
use std::os::raw;
use std::ptr::NonNull;

// DLT_EN10MB; LINKTYPE_ETHERNET=1; 10MB is historical
const DLT_EN10MB: raw::c_int = 1;
const PCAP_SNAPSHOT_LEN: raw::c_int = ffi::RTE_MBUF_DEFAULT_BUF_SIZE as raw::c_int;

/// An error generated in `libpcap`.
///
/// When an FFI call fails, either a specified error message or an `errno` is
/// translated into a `PcapError`.
#[derive(Debug, Fail)]
#[fail(display = "{}", _0)]
struct PcapError(String);

impl PcapError {
    /// Returns the `PcapError` with the given error message.
    #[inline]
    fn new(msg: &str) -> Self {
        PcapError(msg.into())
    }

    /// Returns the `PcapError` pertaining to the last `libpcap` error.
    #[inline]
    fn get_error(handle: NonNull<ffi::pcap_t>) -> Self {
        let msg = unsafe { ffi::pcap_geterr(handle.as_ptr()) };
        PcapError::new((msg as *const raw::c_char).as_str())
    }
}

/// Packet Capture (`pcap`) writer/dumper for packets
struct Pcap {
    path: String,
    handle: NonNull<ffi::pcap_t>,
    dumper: NonNull<ffi::pcap_dumper_t>,
}

impl Pcap {
    /// Creates a file for dumping packets into from a given file path.
    fn create(path: &str) -> Fallible<Pcap> {
        unsafe {
            let handle = ffi::pcap_open_dead(DLT_EN10MB, PCAP_SNAPSHOT_LEN)
                .to_result(|_| PcapError::new("Cannot create packet capture handle."))?;
            let dumper = ffi::pcap_dump_open(handle.as_ptr(), path.to_cstring().as_ptr())
                .to_result(|_| PcapError::get_error(handle))
                .map_err(|err| {
                    ffi::pcap_close(handle.as_ptr());
                    err
                })?;

            debug!("PCAP file {} created", path);

            Ok(Pcap {
                path: path.to_string(),
                handle,
                dumper,
            })
        }
    }

    /// Append to already-existing file for dumping packets into from a given
    /// file path.
    fn append(path: &str) -> Fallible<Pcap> {
        unsafe {
            let handle = ffi::pcap_open_dead(DLT_EN10MB, PCAP_SNAPSHOT_LEN)
                .to_result(|_| PcapError::new("Cannot create packet capture handle."))?;
            let dumper = ffi::pcap_dump_open_append(handle.as_ptr(), path.to_cstring().as_ptr())
                .to_result(|_| PcapError::get_error(handle))
                .map_err(|err| {
                    ffi::pcap_close(handle.as_ptr());
                    err
                })?;

            Ok(Pcap {
                path: path.to_string(),
                handle,
                dumper,
            })
        }
    }

    /// Write packets to `pcap` file handler.
    unsafe fn write(&self, ptrs: &[*mut ffi::rte_mbuf]) -> Fallible<()> {
        ptrs.iter().try_for_each(|&p| self.dump_packet(p))?;

        self.flush()
    }

    unsafe fn dump_packet(&self, ptr: *mut ffi::rte_mbuf) -> Fallible<()> {
        let mut pcap_hdr = ffi::pcap_pkthdr::default();
        pcap_hdr.len = (*ptr).data_len as u32;
        pcap_hdr.caplen = pcap_hdr.len;

        // If this errors, we'll still want to write packet(s) to the pcap,
        let _ = libc::gettimeofday(
            &mut pcap_hdr.ts as *mut ffi::timeval as *mut libc::timeval,
            std::ptr::null_mut(),
        );

        ffi::pcap_dump(
            self.dumper.as_ptr() as *mut raw::c_uchar,
            &pcap_hdr,
            ((*ptr).buf_addr as *mut u8).offset((*ptr).data_off as isize),
        );

        Ok(())
    }

    fn flush(&self) -> Fallible<()> {
        unsafe {
            ffi::pcap_dump_flush(self.dumper.as_ptr())
                .to_result(|_| PcapError::new("Cannot flush packets to packet capture"))
                .map(|_| ())
        }
    }
}

impl<'a> fmt::Debug for Pcap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("pcap").field("path", &self.path).finish()
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        unsafe {
            ffi::pcap_dump_close(self.dumper.as_ptr());
            ffi::pcap_close(self.handle.as_ptr());
        }
    }
}

/// Default formatting for pcap files.
fn format_pcap_file(port_name: &str, core_id: usize, tx_or_rx: &str) -> String {
    format!("port-{}-core{}-{}.pcap", port_name, core_id, tx_or_rx)
}

/// Generate PCAP files for rx/tx queues per port and per core.
pub(crate) fn capture_queue(
    port_id: PortId,
    port_name: &str,
    core: CoreId,
    q: RxTxQueue,
) -> Fallible<()> {
    match q {
        RxTxQueue::Rx(rxq) => {
            Pcap::create(&format_pcap_file(port_name, core.raw(), "rx"))?;
            unsafe {
                ffi::rte_eth_add_rx_callback(
                    port_id.raw(),
                    rxq.raw(),
                    Some(append_and_write_rx),
                    port_name.to_cstring().into_raw() as *mut raw::c_void,
                )
                .to_result(|_| DpdkError::new())?;
            }
        }
        RxTxQueue::Tx(txq) => {
            Pcap::create(&format_pcap_file(port_name, core.raw(), "tx"))?;
            unsafe {
                ffi::rte_eth_add_tx_callback(
                    port_id.raw(),
                    txq.raw(),
                    Some(append_and_write_tx),
                    port_name.to_cstring().into_raw() as *mut raw::c_void,
                )
                .to_result(|_| DpdkError::new())?;
            }
        }
    }

    Ok(())
}

/// Callback fn passed to `rte_eth_add_rx_callback`, which is called on RX
/// with a burst of packets that have been received on a given port and queue.
unsafe extern "C" fn append_and_write_rx(
    _port_id: u16,
    _queue_id: u16,
    pkts: *mut *mut ffi::rte_mbuf,
    num_pkts: u16,
    _max_pkts: u16,
    user_param: *mut raw::c_void,
) -> u16 {
    append_and_write(
        (user_param as *const raw::c_char).as_str(),
        "rx",
        std::slice::from_raw_parts_mut(pkts, num_pkts as usize),
    );
    num_pkts
}

/// Callback fn passed to `rte_eth_add_tx_callback`, which is called on TX
/// with a burst of packets immediately before the packets are put onto
/// the hardware queue for transmission.
unsafe extern "C" fn append_and_write_tx(
    _port_id: u16,
    _queue_id: u16,
    pkts: *mut *mut ffi::rte_mbuf,
    num_pkts: u16,
    user_param: *mut raw::c_void,
) -> u16 {
    append_and_write(
        (user_param as *const raw::c_char).as_str(),
        "tx",
        std::slice::from_raw_parts_mut(pkts, num_pkts as usize),
    );
    num_pkts
}

/// Executed within the rx/tx callback functions for writing out to pcap
/// file(s).
fn append_and_write(port: &str, tx_or_rx: &str, ptrs: &[*mut ffi::rte_mbuf]) {
    let path = format_pcap_file(port, CoreId::current().raw(), tx_or_rx);
    if let Err(err) = Pcap::append(path.as_str()).and_then(|pcap| unsafe { pcap.write(&ptrs) }) {
        error!(
            message = "Cannot write/append to pcap file.",
            pcap = path.as_str(),
            ?err
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testils::byte_arrays::IPV4_UDP_PACKET;
    use crate::Mbuf;
    use std::fs;
    use std::ptr;

    fn read_pcap_plen(path: &str) -> u32 {
        let mut errbuf = [0i8; ffi::RTE_MBUF_DEFAULT_BUF_SIZE as usize];
        let handle =
            unsafe { ffi::pcap_open_offline(path.to_cstring().as_ptr(), errbuf.as_mut_ptr()) };

        let mut header: *mut ffi::pcap_pkthdr = ptr::null_mut();
        let mut buf: *const libc::c_uchar = ptr::null();

        let mut ret = 0;

        while let 1 = unsafe { ffi::pcap_next_ex(handle, &mut header, &mut buf) } {
            ret += unsafe { (*header).caplen }
        }

        unsafe {
            ffi::pcap_close(handle);
        }

        ret
    }

    fn cleanup(path: &str) {
        fs::remove_file(path).unwrap();
    }

    #[capsule::test]
    fn create_pcap_and_write_packet() {
        let writer = Pcap::create("foo.pcap").unwrap();
        let udp = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let data_len = udp.data_len();

        let res = unsafe { writer.write(&[udp.into_ptr()]) };

        assert!(res.is_ok());
        let len = read_pcap_plen("foo.pcap");
        assert_eq!(data_len as u32, len);
        cleanup("foo.pcap");
    }

    #[capsule::test]
    fn create_pcap_and_write_packets() {
        let writer = Pcap::create("foo1.pcap").unwrap();
        let udp = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let data_len1 = udp.data_len();
        let udp2 = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let data_len2 = udp2.data_len();

        let packets = vec![udp.into_ptr(), udp2.into_ptr()];
        let res = unsafe { writer.write(&packets) };
        assert!(res.is_ok());
        let len = read_pcap_plen("foo1.pcap");
        assert_eq!((data_len1 + data_len2) as u32, len);
        cleanup("foo1.pcap");
    }

    #[capsule::test]
    fn append_to_pcap_and_write_packet() {
        let open = Pcap::create("foo2.pcap");
        assert!(open.is_ok());

        let udp = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let data_len = udp.data_len();

        let writer = Pcap::append("foo2.pcap").unwrap();
        let res = unsafe { writer.write(&[udp.into_ptr()]) };

        assert!(res.is_ok());
        let len = read_pcap_plen("foo2.pcap");
        assert_eq!(data_len as u32, len);
        cleanup("foo2.pcap");
    }

    #[capsule::test]
    fn append_to_wrong_pcap() {
        let open = Pcap::create("foo3.pcap");
        assert!(open.is_ok());

        // fails on append to uninitiated pcap
        let res = Pcap::append("foo4.pcap");
        assert!(res.is_err());

        cleanup("foo3.pcap");
    }
}
