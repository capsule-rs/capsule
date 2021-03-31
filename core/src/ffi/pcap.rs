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

use super::{AsStr, EasyPtr, ToCString, ToResult};
use crate::ffi::dpdk::MbufPtr;
use anyhow::Result;
use capsule_ffi as cffi;
use std::ops::DerefMut;
use std::os::raw;
use std::ptr;
use thiserror::Error;

// Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical.
const DLT_EN10MB: raw::c_int = 1;

// https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h#L152
#[allow(dead_code)]
const PCAP_ERRBUF_SIZE: usize = 256;

/// A `pcap_t` pointer.
pub(crate) type PcapPtr = EasyPtr<cffi::pcap_t>;

/// Creates a `libpcap` handle needed to call other functions.
pub(crate) fn open_dead() -> Result<PcapPtr> {
    let ptr = unsafe {
        cffi::pcap_open_dead(DLT_EN10MB, cffi::RTE_MBUF_DEFAULT_BUF_SIZE as raw::c_int)
            .into_result(|_| PcapError::new("Cannot create libpcap handle."))?
    };

    Ok(EasyPtr(ptr))
}

/// A `pcap_dumper_t` pointer.
pub(crate) type DumperPtr = EasyPtr<cffi::pcap_dumper_t>;

/// Opens a file to which to write packets.
pub(crate) fn dump_open<S: Into<String>>(handle: &mut PcapPtr, filename: S) -> Result<DumperPtr> {
    let filename: String = filename.into();
    let ptr = unsafe {
        cffi::pcap_dump_open(handle.deref_mut(), filename.into_cstring().as_ptr())
            .into_result(|_| PcapError::get_error(handle))?
    };

    Ok(EasyPtr(ptr))
}

/// Writes a packet to a capture file.
pub(crate) fn dump(dumper: &mut DumperPtr, mbuf: &MbufPtr) {
    let mut pkthdr = cffi::pcap_pkthdr::default();
    pkthdr.len = mbuf.data_len as u32;
    pkthdr.caplen = pkthdr.len;

    unsafe {
        // If this errors, we'll still want to write packet(s) to the pcap,
        let _ = libc::gettimeofday(
            &mut pkthdr.ts as *mut cffi::timeval as *mut libc::timeval,
            ptr::null_mut(),
        );

        cffi::pcap_dump(
            dumper.deref_mut() as *mut cffi::pcap_dumper_t as *mut raw::c_uchar,
            &pkthdr,
            (mbuf.buf_addr as *mut u8).offset(mbuf.data_off as isize),
        );
    }
}

/// Flushes to a savefile packets dumped.
pub(crate) fn dump_flush(dumper: &mut DumperPtr) -> Result<()> {
    unsafe {
        cffi::pcap_dump_flush(dumper.deref_mut())
            .into_result(|_| PcapError::new("Cannot flush packets to capture file."))
            .map(|_| ())
    }
}

/// Closes a savefile being written to.
pub(crate) fn dump_close(dumper: &mut DumperPtr) {
    unsafe {
        cffi::pcap_dump_close(dumper.deref_mut());
    }
}

/// Closes a capture device or savefile
pub(crate) fn close(handle: &mut PcapPtr) {
    unsafe {
        cffi::pcap_close(handle.deref_mut());
    }
}

/// Opens a saved capture file for reading.
#[cfg(test)]
pub(crate) fn open_offline<S: Into<String>>(filename: S) -> Result<PcapPtr> {
    let filename: String = filename.into();
    let mut errbuf: [raw::c_char; PCAP_ERRBUF_SIZE] = [0; PCAP_ERRBUF_SIZE];

    let ptr = unsafe {
        cffi::pcap_open_offline(filename.into_cstring().as_ptr(), errbuf.as_mut_ptr())
            .into_result(|_| PcapError::new(errbuf.as_str()))?
    };

    Ok(EasyPtr(ptr))
}

/// Reads the next packet from a `pcap_t` handle.
#[cfg(test)]
pub(crate) fn next(handle: &mut PcapPtr) -> Result<&[u8]> {
    let mut pkthdr: *mut cffi::pcap_pkthdr = ptr::null_mut();
    let mut pktdata: *const raw::c_uchar = ptr::null();

    unsafe {
        match cffi::pcap_next_ex(handle.deref_mut(), &mut pkthdr, &mut pktdata) {
            1 => Ok(std::slice::from_raw_parts(
                pktdata,
                (*pkthdr).caplen as usize,
            )),
            _ => Err(PcapError::get_error(handle).into()),
        }
    }
}

/// An error generated in `libpcap`.
#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct PcapError(String);

impl PcapError {
    /// Returns the `PcapError` with the given error message.
    #[inline]
    fn new(msg: &str) -> Self {
        PcapError(msg.into())
    }

    /// Returns the `PcapError` pertaining to the last `libpcap` error.
    #[inline]
    fn get_error(handle: &mut PcapPtr) -> Self {
        let msg = unsafe { cffi::pcap_geterr(handle.deref_mut()) };
        PcapError::new((msg as *const raw::c_char).as_str())
    }
}
