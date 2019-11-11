use super::{CoreId, Port, PortId};
use crate::ffi::{self, ToResult};
use crate::metrics::{labels, Key, Measurement};
use crate::Result;

/// Port stats collector.
pub struct PortStats {
    id: PortId,
    name: String,
    cores: Vec<CoreId>,
}

impl PortStats {
    /// Builds a collector from the port.
    pub fn build(port: &Port) -> Self {
        // sorts the core ids, so they are in the same order as the stats.
        let mut cores = port.queues().keys().copied().collect::<Vec<_>>();
        cores.sort();

        PortStats {
            id: port.id(),
            name: port.name().to_owned(),
            cores,
        }
    }

    /// Returns the port name.
    pub fn name(&self) -> &str {
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

    /// Returns a counter with port, direction and core labels.
    fn new_counter_for_core(
        &self,
        name: &'static str,
        value: u64,
        dir: &'static str,
        core_id: CoreId,
    ) -> (Key, Measurement) {
        (
            Key::from_name_and_labels(
                name,
                labels!(
                    "port" => self.name.clone(),
                    "dir" => dir,
                    "core" => core_id.raw().to_string(),
                ),
            ),
            Measurement::Counter(value),
        )
    }

    /// Collects the port stats tracked by DPDK.
    pub fn collect(&self) -> Result<Vec<(Key, Measurement)>> {
        let mut stats = ffi::rte_eth_stats::default();
        unsafe {
            ffi::rte_eth_stats_get(self.id.raw(), &mut stats).to_result()?;
        }

        let mut values = Vec::new();

        if ffi::RTE_ETHDEV_QUEUE_STAT_CNTRS >= self.cores.len() as u32 {
            // packet and byte counts are being tracked per core.
            self.cores.iter().enumerate().for_each(|(idx, core_id)| {
                values.push(self.new_counter_for_core(
                    "packets",
                    stats.q_ipackets[idx],
                    "rx",
                    *core_id,
                ));
                values.push(self.new_counter_for_core(
                    "packets",
                    stats.q_opackets[idx],
                    "tx",
                    *core_id,
                ));
                values.push(self.new_counter_for_core(
                    "octets",
                    stats.q_ibytes[idx],
                    "rx",
                    *core_id,
                ));
                values.push(self.new_counter_for_core(
                    "octets",
                    stats.q_obytes[idx],
                    "tx",
                    *core_id,
                ));
            });
        } else {
            // packet and byte counts are global
            values.push(self.new_counter("packets", stats.ipackets, "rx"));
            values.push(self.new_counter("packets", stats.opackets, "tx"));
            values.push(self.new_counter("octets", stats.ibytes, "rx"));
            values.push(self.new_counter("octets", stats.obytes, "tx"));
        }

        values.push(self.new_counter("dropped", stats.imissed, "rx"));
        values.push(self.new_counter("errors", stats.ierrors, "rx"));
        values.push(self.new_counter("errors", stats.oerrors, "tx"));
        values.push(self.new_counter("no_mbuf", stats.rx_nombuf, "rx"));

        Ok(values)
    }
}
