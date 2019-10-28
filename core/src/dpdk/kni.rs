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

use super::{CoreId, PortId};
use crate::ffi::{self, AsStr, ToResult};
use crate::net::MacAddr;
use crate::{debug, error, Result};
use std::cmp;
use std::convert::From;
use std::mem;
use std::os::raw;
use std::ptr::{self, NonNull};

/// Kernel NIC interface.
///
/// KNI allows the DPDK application to exchange packets with the kernel
/// networking stack.
pub struct Kni {
    raw: NonNull<ffi::rte_kni>,
}

impl Kni {
    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub fn raw(&self) -> &ffi::rte_kni {
        unsafe { self.raw.as_ref() }
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub fn raw_mut(&mut self) -> &mut ffi::rte_kni {
        unsafe { self.raw.as_mut() }
    }

    /// Returns the name of the KNI device.
    #[inline]
    pub fn name(&self) -> String {
        unsafe { ffi::rte_kni_get_name(self.raw()).as_str().to_owned() }
    }
}

impl From<NonNull<ffi::rte_kni>> for Kni {
    #[inline]
    fn from(raw: NonNull<ffi::rte_kni>) -> Self {
        Kni { raw }
    }
}

impl Drop for Kni {
    fn drop(&mut self) {
        debug!("freeing {}.", self.name());

        if let Err(err) = unsafe { ffi::rte_kni_release(self.raw_mut()).to_result() } {
            error!(message = "failed to release KNI device.", ?err);
        }
    }
}

/// Builds a KNI device from the configuration values.
pub struct KniBuilder<'a> {
    mempool: &'a mut ffi::rte_mempool,
    conf: ffi::rte_kni_conf,
    ops: ffi::rte_kni_ops,
}

impl<'a> KniBuilder<'a> {
    /// Creates a new KNI device builder with the mempool for allocating
    /// new packets.
    pub fn new(mempool: &'a mut ffi::rte_mempool) -> Self {
        KniBuilder {
            mempool,
            conf: ffi::rte_kni_conf::default(),
            ops: ffi::rte_kni_ops::default(),
        }
    }

    pub fn name(&mut self, name: &String) -> &mut Self {
        unsafe {
            self.conf.name = mem::zeroed();
            ptr::copy(
                name.as_ptr(),
                self.conf.name.as_mut_ptr() as *mut u8,
                cmp::min(name.len(), self.conf.name.len()),
            );
        }
        self
    }

    pub fn core_id(&mut self, core_id: CoreId) -> &mut Self {
        self.conf.core_id = core_id.raw();
        self
    }

    pub fn port_id(&mut self, port_id: PortId) -> &mut Self {
        self.conf.group_id = port_id.raw();
        self.ops.port_id = port_id.raw();
        self
    }

    pub fn mac_addr(&mut self, mac: MacAddr) -> &mut Self {
        unsafe {
            self.conf.mac_addr = mem::transmute(mac);
        }
        self
    }

    pub fn finish(&mut self) -> Result<Kni> {
        unsafe {
            ffi::rte_kni_alloc(self.mempool, &self.conf, &mut self.ops)
                .to_result()
                .map(|raw| raw.into())
        }
    }
}

/// Initializes and preallocates the KNI subsystem.
pub fn kni_init(max: usize) -> Result<()> {
    unsafe {
        ffi::rte_kni_init(max as raw::c_uint)
            .to_result()
            .map(|_| ())
    }
}

/// Closes the KNI subsystem.
pub fn kni_close() {
    unsafe {
        ffi::rte_kni_close();
    }
}
