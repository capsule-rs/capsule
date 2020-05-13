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

use super::{Mempool, Port, PortId};
use crate::dpdk::DpdkError;
use crate::ffi::{self, AsStr, ToResult};
use crate::metrics::{labels, Key, Measurement};
use failure::Fallible;
use std::ptr::NonNull;

/// Port stats collector.
pub(crate) struct PortStats {
    id: PortId,
    name: String,
}

impl PortStats {
    /// Builds a collector from the port.
    pub(crate) fn build(port: &Port) -> Self {
        PortStats {
            id: port.id(),
            name: port.name().to_owned(),
        }
    }

    /// Returns the port name.
    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns a counter with port and direction labels.
    fn new_counter(&self, name: &'static str, value: u64, dir: &'static str) -> (Key, Measurement) {
        (
            Key::from_name_and_labels(
                name,
                labels!(
                    "port" => self.name.clone(),
                    "dir" => dir,
                ),
            ),
            Measurement::Counter(value),
        )
    }

    /// Collects the port stats tracked by DPDK.
    pub(crate) fn collect(&self) -> Fallible<Vec<(Key, Measurement)>> {
        let mut stats = ffi::rte_eth_stats::default();
        unsafe {
            ffi::rte_eth_stats_get(self.id.raw(), &mut stats).to_result(DpdkError::from_errno)?;
        }

        let mut values = Vec::new();

        values.push(self.new_counter("octets", stats.ibytes, "rx"));
        values.push(self.new_counter("octets", stats.obytes, "tx"));
        values.push(self.new_counter("dropped", stats.imissed, "rx"));
        values.push(self.new_counter("errors", stats.ierrors, "rx"));
        values.push(self.new_counter("errors", stats.oerrors, "tx"));
        values.push(self.new_counter("no_mbuf", stats.rx_nombuf, "rx"));

        Ok(values)
    }
}

/// Mempool stats collector.
pub(crate) struct MempoolStats {
    raw: NonNull<ffi::rte_mempool>,
}

impl MempoolStats {
    /// Builds a collector from the port.
    pub(crate) fn build(mempool: &Mempool) -> Self {
        MempoolStats {
            raw: unsafe {
                NonNull::new_unchecked(
                    mempool.raw() as *const ffi::rte_mempool as *mut ffi::rte_mempool
                )
            },
        }
    }

    fn raw(&self) -> &ffi::rte_mempool {
        unsafe { self.raw.as_ref() }
    }

    /// Returns the name of the `Mempool`.
    fn name(&self) -> &str {
        self.raw().name[..].as_str()
    }

    /// Returns a gauge.
    fn new_gauge(&self, name: &'static str, value: i64) -> (Key, Measurement) {
        (
            Key::from_name_and_labels(
                name,
                labels!(
                    "pool" => self.name().to_string(),
                ),
            ),
            Measurement::Gauge(value),
        )
    }

    /// Collects the mempool stats.
    pub(crate) fn collect(&self) -> Vec<(Key, Measurement)> {
        let used = unsafe { ffi::rte_mempool_in_use_count(self.raw()) as i64 };
        let free = self.raw().size as i64 - used;

        vec![self.new_gauge("used", used), self.new_gauge("free", free)]
    }
}

/// Send mempool stats across threads.
unsafe impl Send for MempoolStats {}
unsafe impl Sync for MempoolStats {}
