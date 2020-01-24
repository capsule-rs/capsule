use crate::dpdk::{CoreId, PortId};
use crate::ffi::{self, ToCString, ToResult};
use crate::packets::Packet;
use crate::{debug, Result};
use libc;
use std::fmt;
use std::os::raw;
use std::ptr::NonNull;

/// DLT_EN10MB; LINKTYPE_ETHERNET=1; 10MB is historical
const DLT_EN10MB: raw::c_int = 1;
const PCAP_SNAPSHOT_LEN: raw::c_int = ffi::RTE_MBUF_DEFAULT_BUF_SIZE as raw::c_int;

/// Pcap Writer for packets
#[derive(Debug)]
pub struct Pcap {
    path: String,
    handle: NonNull<ffi::pcap_t>,
    dumper: NonNull<ffi::pcap_dumper_t>,
}

impl Pcap {
    /// Create file for dumping packets into from given file a path.
    pub fn create(path: &str) -> Result<Pcap> {
        unsafe {
            let handle = ffi::pcap_open_dead(DLT_EN10MB, PCAP_SNAPSHOT_LEN).to_result()?;
            let dumper = ffi::pcap_dump_open(handle.as_ptr(), path.to_cstring().as_ptr())
                .to_result()
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
    pub fn append(path: &str) -> Result<Pcap> {
        unsafe {
            let handle = ffi::pcap_open_dead(DLT_EN10MB, PCAP_SNAPSHOT_LEN).to_result()?;
            let dumper = ffi::pcap_dump_open_append(handle.as_ptr(), path.to_cstring().as_ptr())
                .to_result()
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

    /// Write packets to PCAP file handler
    pub fn write_packets<T: Packet + fmt::Debug>(&self, packets: &[T]) {
        packets.iter().for_each(|p| {
            if let Err(err) = self.write(p) {
                debug!(
                    "Error - {} - writing {:?} to PCAP file {}",
                    err, p, self.path
                )
            }
        })
    }

    /// Write (single) packet to PCAP file handler
    pub fn write<T: Packet>(&self, packet: &T) -> Result<()> {
        let mut pcap_hdr = ffi::pcap_pkthdr::default();
        pcap_hdr.len = packet.mbuf().data_len() as u32;
        pcap_hdr.caplen = pcap_hdr.len;

        unsafe {
            libc::gettimeofday(
                &mut pcap_hdr.ts as *mut ffi::timeval as *mut libc::timeval,
                std::ptr::null_mut(),
            )
            .to_result()?;

            ffi::pcap_dump(
                self.dumper.as_ptr() as *mut raw::c_uchar,
                &pcap_hdr,
                packet.mbuf().data_address(0),
            );

            ffi::pcap_dump_flush(self.dumper.as_ptr())
                .to_result()
                .map(|_| ())
        }
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

/// Generate PCAP files for rx/tx queues per port and per core.
pub(crate) fn create_for_queues(port: PortId, core: CoreId) -> Result<()> {
    Pcap::create(format!("{:?}-{:?}-rx.pcap", port, core).as_str())?;
    Pcap::create(format!("{:?}-{:?}-tx.pcap", port, core).as_str())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::{Ethernet, Udp, UDP_PACKET};
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

        ret
    }

    fn cleanup(path: &str) {
        fs::remove_file(path).unwrap();
    }

    #[nb2::test]
    fn create_pcap_and_write_packet() {
        let writer = Pcap::create("foo.pcap").unwrap();
        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let data_len = packet.data_len();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ipv4.parse::<Udp<Ipv4>>().unwrap();

        let res = writer.write(&udp);

        assert!(res.is_ok());
        let len = read_pcap_plen("foo.pcap");
        assert_eq!(data_len as u32, len);
        cleanup("foo.pcap");
    }

    #[nb2::test]
    fn create_pcap_and_write_packets() {
        let writer = Pcap::create("foo1.pcap").unwrap();
        let udp = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let data_len1 = udp.data_len();
        let udp2 = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let data_len2 = udp2.data_len();

        let packets = vec![udp, udp2];
        writer.write_packets(&packets);
        let len = read_pcap_plen("foo1.pcap");
        assert_eq!((data_len1 + data_len2) as u32, len);
        cleanup("foo1.pcap");
    }

    #[nb2::test]
    fn append_to_pcap_and_write_packet() {
        let open = Pcap::create("foo2.pcap");
        assert!(open.is_ok());

        let packet = Mbuf::from_bytes(&UDP_PACKET).unwrap();
        let data_len = packet.data_len();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ipv4.parse::<Udp<Ipv4>>().unwrap();

        let writer = Pcap::append("foo2.pcap").unwrap();
        let res = writer.write(&udp);

        assert!(res.is_ok());
        let len = read_pcap_plen("foo2.pcap");
        assert_eq!(data_len as u32, len);
        cleanup("foo2.pcap");
    }
}
