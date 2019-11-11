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
                values.push((
                    Key::from_name_and_labels(
                        "packets",
                        labels!(
                            "port" => self.name.clone(),
                            "dir" => "rx",
                            "core" => core_id.raw().to_string(),
                        ),
                    ),
                    Measurement::Counter(stats.q_ipackets[idx]),
                ));

                values.push((
                    Key::from_name_and_labels(
                        "packets",
                        labels!(
                            "port" => self.name.clone(),
                            "dir" => "tx",
                            "core" => core_id.raw().to_string(),
                        ),
                    ),
                    Measurement::Counter(stats.q_opackets[idx]),
                ));

                values.push((
                    Key::from_name_and_labels(
                        "octets",
                        labels!(
                            "port" => self.name.clone(),
                            "dir" => "rx",
                            "core" => core_id.raw().to_string(),
                        ),
                    ),
                    Measurement::Counter(stats.q_ibytes[idx]),
                ));

                values.push((
                    Key::from_name_and_labels(
                        "octets",
                        labels!(
                            "port" => self.name.clone(),
                            "dir" => "tx",
                            "core" => core_id.raw().to_string(),
                        ),
                    ),
                    Measurement::Counter(stats.q_obytes[idx]),
                ));
            });
        } else {
            // packet and byte counts are global
            values.push((
                Key::from_name_and_labels(
                    "packets",
                    labels!(
                        "port" => self.name.clone(),
                        "dir" => "rx"
                    ),
                ),
                Measurement::Counter(stats.ipackets),
            ));

            values.push((
                Key::from_name_and_labels(
                    "packets",
                    labels!(
                        "port" => self.name.clone(),
                        "dir" => "tx"
                    ),
                ),
                Measurement::Counter(stats.opackets),
            ));

            values.push((
                Key::from_name_and_labels(
                    "octets",
                    labels!(
                        "port" => self.name.clone(),
                        "dir" => "rx"
                    ),
                ),
                Measurement::Counter(stats.ibytes),
            ));

            values.push((
                Key::from_name_and_labels(
                    "octets",
                    labels!(
                        "port" => self.name.clone(),
                        "dir" => "tx"
                    ),
                ),
                Measurement::Counter(stats.obytes),
            ));
        }

        values.push((
            Key::from_name_and_labels(
                "dropped",
                labels!(
                    "port" => self.name.clone(),
                    "dir" => "rx"
                ),
            ),
            Measurement::Counter(stats.imissed),
        ));

        values.push((
            Key::from_name_and_labels(
                "errors",
                labels!(
                    "port" => self.name.clone(),
                    "dir" => "rx"
                ),
            ),
            Measurement::Counter(stats.ierrors),
        ));

        values.push((
            Key::from_name_and_labels(
                "errors",
                labels!(
                    "port" => self.name.clone(),
                    "dir" => "tx"
                ),
            ),
            Measurement::Counter(stats.oerrors),
        ));

        values.push((
            Key::from_name_and_labels(
                "no_mbuf",
                labels!(
                    "port" => self.name.clone(),
                    "dir" => "rx"
                ),
            ),
            Measurement::Counter(stats.rx_nombuf),
        ));

        Ok(values)
    }
}
