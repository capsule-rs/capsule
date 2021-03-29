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

use super::{LcoreMap, PortMap};
use crate::ffi::dpdk::{self, MbufPtr, RxTxCallbackGuard};
use crate::ffi::pcap::{self, DumperPtr, PcapPtr};
use crate::{info, warn};
use anyhow::{anyhow, Result};
use capsule_ffi as cffi;
use std::fs;
use std::os::raw;
use std::path::Path;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

/// Manages the lifecycle of a capture file.
struct CaptureFile {
    path: String,
    handle: PcapPtr,
    dumper: DumperPtr,
    guard: Option<RxTxCallbackGuard>,
}

impl CaptureFile {
    /// Creates a new pcap file.
    fn new(path: &str) -> Result<CaptureFile> {
        let mut handle = pcap::open_dead()?;
        let dumper = pcap::dump_open(&mut handle, path)?;
        info!(file = ?path, "file opened.");
        Ok(CaptureFile {
            path: path.to_string(),
            handle,
            dumper,
            guard: None,
        })
    }

    /// Sets the RAII guard.
    fn set_guard(&mut self, guard: RxTxCallbackGuard) {
        self.guard = Some(guard);
    }
}

impl Drop for CaptureFile {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            // unwires the rx/tx callback first.
            drop(guard);
        }

        pcap::dump_close(&mut self.dumper);
        pcap::close(&mut self.handle);
        info!(file = ?self.path, "file closed.");
    }
}

/// The pcap dump manager.
pub(crate) struct PcapDump {
    output_dir: String,
    captures: Vec<Box<CaptureFile>>,
}

impl PcapDump {
    /// Creates a new instance.
    pub(crate) fn new(data_dir: &str) -> Result<PcapDump> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = Path::new(data_dir)
            .join("pdump")
            .join(timestamp.to_string());
        fs::create_dir_all(path.clone())?;
        let output_dir = path
            .to_str()
            .ok_or_else(|| anyhow!("bad pdump output dir."))?
            .to_string();

        Ok(PcapDump {
            output_dir,
            captures: vec![],
        })
    }

    /// Creates a new capture file.
    fn new_capture(&mut self, filename: &str) -> Result<&mut Box<CaptureFile>> {
        let path = format!("{}/{}", self.output_dir, filename);
        let capture = CaptureFile::new(&path)?;
        self.captures.push(Box::new(capture));
        Ok(self.captures.last_mut().unwrap())
    }
}

/// Enables the pcap dump.
pub(crate) fn enable_pcap_dump(
    data_dir: &str,
    ports: &PortMap,
    lcores: &LcoreMap,
) -> Result<PcapDump> {
    info!("enabling pcap dump ...");

    let mut pcap_dump = PcapDump::new(data_dir)?;

    for port in ports.iter() {
        for (index, lcore_id) in port.rx_lcores().iter().enumerate() {
            let lcore = lcores.get(*lcore_id)?;
            let filename = format!("{}-rx-{:?}.pcap", port.name(), lcore.id());
            let capture = pcap_dump.new_capture(&filename)?;
            let guard = dpdk::eth_add_rx_callback(
                port.port_id(),
                index.into(),
                Some(rx_callback_fn),
                capture.as_mut(),
            )?;
            capture.set_guard(guard);
        }

        for (index, lcore_id) in port.tx_lcores().iter().enumerate() {
            let lcore = lcores.get(*lcore_id)?;
            let filename = format!("{}-tx-{:?}.pcap", port.name(), lcore.id());
            let capture = pcap_dump.new_capture(&filename)?;
            let guard = dpdk::eth_add_tx_callback(
                port.port_id(),
                index.into(),
                Some(tx_callback_fn),
                capture.as_mut(),
            )?;
            capture.set_guard(guard);
        }
    }

    Ok(pcap_dump)
}

fn dump_mbufs(dumper: &mut DumperPtr, mbufs: &[MbufPtr]) {
    for mbuf in mbufs {
        pcap::dump(dumper, mbuf);
    }

    if let Err(error) = pcap::dump_flush(dumper) {
        warn!(?error);
    }
}

unsafe extern "C" fn rx_callback_fn(
    _port_id: u16,
    _queue_id: u16,
    pkts: *mut *mut cffi::rte_mbuf,
    num_pkts: u16,
    _max_pkts: u16,
    user_param: *mut raw::c_void,
) -> u16 {
    let capture = Box::leak(Box::from_raw(user_param as *mut CaptureFile));
    let mbufs = slice::from_raw_parts_mut(pkts as *mut MbufPtr, num_pkts as usize);
    dump_mbufs(&mut capture.dumper, &mbufs);
    num_pkts
}

unsafe extern "C" fn tx_callback_fn(
    _port_id: u16,
    _queue_id: u16,
    pkts: *mut *mut cffi::rte_mbuf,
    num_pkts: u16,
    user_param: *mut raw::c_void,
) -> u16 {
    let capture = Box::leak(Box::from_raw(user_param as *mut CaptureFile));
    let mbufs = slice::from_raw_parts_mut(pkts as *mut MbufPtr, num_pkts as usize);
    dump_mbufs(&mut capture.dumper, &mbufs);
    num_pkts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::{IPV4_TCP_PACKET, IPV4_UDP_PACKET};

    #[capsule::test]
    fn dump_mbufs_to_file() -> Result<()> {
        let filename = "file.pcap";
        let mut capture = CaptureFile::new(filename)?;

        let tcp = Mbuf::from_bytes(&IPV4_TCP_PACKET)?;
        let udp = Mbuf::from_bytes(&IPV4_UDP_PACKET)?;

        dump_mbufs(
            &mut capture.dumper,
            &[tcp.into_easyptr(), udp.into_easyptr()],
        );

        drop(capture);

        // reads the packets from file and assert they are the same.
        let mut h2 = pcap::open_offline(filename)?;
        let packet = pcap::next(&mut h2)?;
        assert_eq!(&IPV4_TCP_PACKET, packet);
        let packet = pcap::next(&mut h2)?;
        assert_eq!(&IPV4_UDP_PACKET, packet);

        pcap::close(&mut h2);

        fs::remove_file(filename)?;

        Ok(())
    }
}
