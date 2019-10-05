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

use crate::dpdk::{MBuf, Mempool};
use crate::ffi;
use failure::{format_err, Error};
use std::cmp::min;
use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr;

pub struct PmdPort {
    name: String,
    port_id: u16,
    dev_info: ffi::rte_eth_dev_info,
}

impl PmdPort {
    pub fn init(name: &str, pool: &mut Mempool) -> Result<Self, Error> {
        unsafe {
            let mut port_id = 0u16;
            let ret = ffi::rte_eth_dev_get_port_by_name(
                CString::from_vec_unchecked(name.into()).as_ptr(),
                &mut port_id,
            );
            if ret < 0 {
                return Err(format_err!("{} device '{}' not found.", ret, name));
            }

            let mut dev_info = ffi::rte_eth_dev_info::default();
            ffi::rte_eth_dev_info_get(port_id, &mut dev_info);

            let conf = ffi::rte_eth_conf::default();
            let ret = ffi::rte_eth_dev_configure(port_id, 1, 1, &conf);
            if ret != 0 {
                return Err(format_err!("{} device '{}' not configured.", ret, name));
            }

            let mut rxd_size = 1024;
            let mut txd_size = 1024;
            let ret = ffi::rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &mut rxd_size, &mut txd_size);
            if ret != 0 {
                return Err(format_err!("{} device descriptors not adjusted.", ret));
            }

            let socket_id = ffi::rte_eth_dev_socket_id(port_id) as raw::c_uint;
            println!("socket id {}", socket_id);

            let ret = ffi::rte_eth_rx_queue_setup(
                port_id,
                0,
                rxd_size,
                socket_id,
                ptr::null(),
                pool.as_mut(),
            );
            if ret < 0 {
                return Err(format_err!("{} rx queue not setup.", ret));
            }

            let ret = ffi::rte_eth_tx_queue_setup(port_id, 0, txd_size, socket_id, ptr::null());
            if ret < 0 {
                return Err(format_err!("{} tx queue not setup.", ret));
            }

            Ok(PmdPort {
                name: name.to_owned(),
                port_id,
                dev_info,
            })
        }
    }

    pub fn driver_name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.dev_info.driver_name)
                .to_str()
                .unwrap_or("unknown")
        }
    }

    pub fn start(&self) -> Result<(), Error> {
        unsafe {
            let ret = ffi::rte_eth_dev_start(self.port_id);
            if ret == 0 {
                Ok(())
            } else {
                Err(format_err!("{} device {} not started.", ret, self.name))
            }
        }
    }

    pub fn stop(&self) {
        unsafe {
            ffi::rte_eth_dev_stop(self.port_id);
        }
    }

    pub fn receive(&self) -> Vec<MBuf> {
        unsafe {
            let batch_size = 32;
            let mut buffer = Vec::with_capacity(batch_size);
            let len =
                ffi::_rte_eth_rx_burst(self.port_id, 0, buffer.as_mut_ptr(), batch_size as u16);
            println!("{} received.", len);
            buffer
                .iter()
                .take(len as usize)
                .map(|&ptr| MBuf::new(ptr))
                .collect::<Vec<_>>()
        }
    }

    pub fn send(&self, mbufs: Vec<MBuf>) {
        unsafe {
            let mut buffer = mbufs.iter().map(|mbuf| mbuf.raw_ptr()).collect::<Vec<_>>();
            let len = ffi::_rte_eth_tx_burst(
                self.port_id,
                0,
                buffer.as_mut_ptr(),
                min(mbufs.len(), 32) as u16,
            );
            println!("{} sent.", len);
        }
    }
}
