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

//! Toml-based configuration for use with Capsule applications.
//!
//! # Example
//!
//! A configuration from our [`pktdump`] example:
//!
//! ```
//! app_name = "pktdump"
//! main_core = 0
//! worker_cores = [0]
//!
//! [mempool]
//!     capacity = 65535
//!     cache_size = 256
//!
//! [[ports]]
//!     name = "eth1"
//!     device = "net_pcap0"
//!     args = "rx_pcap=tcp4.pcap,tx_iface=lo"
//!     rx_core = [0]
//!     tx_core = [0]
//!
//! [[ports]]
//!     name = "eth2"
//!     device = "net_pcap1"
//!     args = "rx_pcap=tcp6.pcap,tx_iface=lo"
//!     rx_core = [0]
//!     tx_core = [0]
//! ```
//!
//! [`pktdump`]: https://github.com/capsule-rs/capsule/tree/master/examples/pktdump

use anyhow::Result;
use capsule_ffi as cffi;
use clap::{clap_app, crate_version};
use regex::Regex;
use serde::Deserialize;
use std::fmt;
use std::fs;

/// Runtime configuration settings.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Application name. This must be unique if you want to run multiple
    /// DPDK applications on the same system.
    pub app_name: String,

    /// Indicating whether the process is a secondary process. Secondary
    /// process cannot initialize shared memory, but can attach to pre-
    /// initialized shared memory by the primary process and create objects
    /// in it. Defaults to `false`.
    #[serde(default)]
    pub secondary: bool,

    /// Application group name. Use this to group primary and secondary
    /// processes together in a multi-process setup; and allow them to share
    /// the same memory regions. The default value is the `app_name`. Each
    /// process works independently.
    #[serde(default)]
    pub app_group: Option<String>,

    /// The identifier of the main core. This is the core the main thread
    /// will run on.
    pub main_core: usize,

    /// Worker cores used for packet processing and general async task
    /// execution.
    pub worker_cores: Vec<usize>,

    /// The root data directory the application writes to.
    ///
    /// If unset, the default is `/var/capsule/{app_name}`.
    #[serde(default)]
    pub data_dir: Option<String>,

    /// Per mempool settings. On a system with multiple sockets, aka NUMA
    /// nodes, one mempool will be allocated for each socket the apllication
    /// uses.
    #[serde(default)]
    pub mempool: MempoolConfig,

    /// The ports to use for the application. Must have at least one.
    pub ports: Vec<PortConfig>,

    /// Additional DPDK [`parameters`] to pass on for EAL initialization. When
    /// set, the values are passed through as is without validation.
    ///
    /// [`parameters`]: https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html
    #[serde(default)]
    pub dpdk_args: Option<String>,
}

impl RuntimeConfig {
    fn other_cores(&self) -> Vec<usize> {
        let mut cores = vec![];
        cores.extend(&self.worker_cores);

        self.ports.iter().for_each(|port| {
            if !port.rx_cores.is_empty() {
                cores.extend(&port.rx_cores);
            }
            if !port.tx_cores.is_empty() {
                cores.extend(&port.tx_cores);
            }
        });

        cores.sort();
        cores.dedup();
        cores
    }

    /// Extracts the EAL arguments from runtime settings.
    pub(crate) fn to_eal_args(&self) -> Vec<String> {
        let mut eal_args = vec![];

        // adds the app name.
        eal_args.push(self.app_name.clone());

        // adds the proc type.
        let proc_type = if self.secondary {
            "secondary"
        } else {
            "primary"
        };
        eal_args.push("--proc-type".into());
        eal_args.push(proc_type.into());

        // adds the mem file prefix.
        let prefix = self.app_group.as_ref().unwrap_or(&self.app_name);
        eal_args.push("--file-prefix".into());
        eal_args.push(prefix.clone());

        // adds all the ports.
        let pcie = Regex::new(r"^\d{4}:\d{2}:\d{2}\.\d$").unwrap();
        self.ports.iter().for_each(|port| {
            if pcie.is_match(port.device.as_str()) {
                eal_args.push("--pci-whitelist".into());
                eal_args.push(port.device.clone());
            } else {
                let vdev = if let Some(args) = &port.args {
                    format!("{},{}", port.device, args)
                } else {
                    port.device.clone()
                };
                eal_args.push("--vdev".into());
                eal_args.push(vdev);
            }
        });

        let mut main = self.main_core;
        let others = self.other_cores();

        // if the main lcore is also used for other tasks, we will assign
        // another lcore to be the main, and set the affinity to the same
        // physical core/cpu. this is necessary because we need to be able
        // to run an executor for other tasks without blocking the main
        // application thread.
        if others.contains(&main) {
            main = cffi::RTE_MAX_LCORE as usize - 1;
        }

        // adds the main core.
        eal_args.push("--master-lcore".into());
        eal_args.push(main.to_string());

        // adds all the lcores.
        let mut cores = others
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        cores.push_str(&format!(",{}@{}", main, self.main_core));
        eal_args.push("--lcores".to_owned());
        eal_args.push(cores);

        // adds additional DPDK args.
        if let Some(args) = &self.dpdk_args {
            eal_args.extend(args.split_ascii_whitespace().map(ToString::to_string));
        }

        eal_args
    }

    /// Returns the data directory.
    #[allow(dead_code)]
    pub(crate) fn data_dir(&self) -> String {
        self.data_dir.clone().unwrap_or_else(|| {
            let base_dir = "/var/capsule";
            match &self.app_group {
                Some(group) => format!("{}/{}/{}", base_dir, group, self.app_name),
                None => format!("{}/{}", base_dir, self.app_name),
            }
        })
    }
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("RuntimeConfig");
        d.field("app_name", &self.app_name)
            .field("secondary", &self.secondary)
            .field(
                "app_group",
                self.app_group.as_ref().unwrap_or(&self.app_name),
            )
            .field("main_core", &self.main_core)
            .field("worker_cores", &self.worker_cores)
            .field("mempool", &self.mempool)
            .field("ports", &self.ports);
        if let Some(dpdk_args) = &self.dpdk_args {
            d.field("dpdk_args", dpdk_args);
        }
        d.finish()
    }
}

/// Mempool configuration settings.
#[derive(Clone, Deserialize)]
pub struct MempoolConfig {
    /// The maximum number of Mbufs the mempool can allocate. The optimum
    /// size (in terms of memory usage) is when n is a power of two minus
    /// one. Defaults to `65535` or `2 ^ 16 - 1`.
    #[serde(default = "default_capacity")]
    pub capacity: usize,

    /// The size of the per core object cache. If cache_size is non-zero,
    /// the library will try to limit the accesses to the common lockless
    /// pool. The cache can be disabled if the argument is set to 0. Defaults
    /// to `0`.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

fn default_capacity() -> usize {
    65535
}

fn default_cache_size() -> usize {
    0
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            capacity: default_capacity(),
            cache_size: default_cache_size(),
        }
    }
}

impl fmt::Debug for MempoolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MempoolConfig")
            .field("capacity", &self.capacity)
            .field("cache_size", &self.cache_size)
            .finish()
    }
}

/// Port configuration settings.
#[derive(Clone, Deserialize)]
pub struct PortConfig {
    /// The application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub name: String,

    /// The device name of the port. It can be the following formats,
    ///
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    pub device: String,

    /// Additional arguments to configure a virtual device.
    #[serde(default)]
    pub args: Option<String>,

    /// The lcores to receive packets on. When no lcore specified, the port
    /// will be TX only.
    #[serde(default)]
    pub rx_cores: Vec<usize>,

    /// The lcores to transmit packets on. When no lcore specified, the port
    /// will be RX only.
    #[serde(default)]
    pub tx_cores: Vec<usize>,

    /// The receive queue size. Defaults to `128`.
    #[serde(default = "default_port_rxqs")]
    pub rxqs: usize,

    /// The transmit queue size. Defaults to `128`.
    #[serde(default = "default_port_txqs")]
    pub txqs: usize,

    /// Whether promiscuous mode is enabled for this port. Defaults to `true`.
    #[serde(default = "default_promiscuous_mode")]
    pub promiscuous: bool,

    /// Whether multicast packet reception is enabled for this port. Defaults
    /// to `true`.
    #[serde(default = "default_multicast_mode")]
    pub multicast: bool,
}

fn default_port_rxqs() -> usize {
    128
}

fn default_port_txqs() -> usize {
    128
}

fn default_promiscuous_mode() -> bool {
    true
}

fn default_multicast_mode() -> bool {
    true
}

impl fmt::Debug for PortConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("PortConfig");
        d.field("name", &self.name);
        d.field("device", &self.device);
        if let Some(args) = &self.args {
            d.field("args", args);
        }
        if !self.rx_cores.is_empty() {
            d.field("rx_cores", &self.rx_cores);
        }
        if !self.tx_cores.is_empty() {
            d.field("tx_cores", &self.tx_cores);
        }
        d.field("rxqs", &self.rxqs)
            .field("txqs", &self.txqs)
            .field("promiscuous", &self.promiscuous)
            .field("multicast", &self.multicast)
            .finish()
    }
}

/// Loads the app config from a TOML file.
///
/// # Example
///
/// ```
/// home$ ./myapp -f config.toml
/// ```
pub fn load_config() -> Result<RuntimeConfig> {
    let matches = clap_app!(capsule =>
        (version: crate_version!())
        (@arg file: -f --file +required +takes_value "configuration file")
    )
    .get_matches();

    let path = matches.value_of("file").unwrap();
    let content = fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|err| err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() -> Result<()> {
        const CONFIG: &str = r#"
            app_name = "myapp"
            main_core = 0
            worker_cores = [1, 2]
            [[ports]]
                name = "eth0"
                device = "0000:00:01.0"
        "#;

        let config: RuntimeConfig = toml::from_str(CONFIG)?;

        assert_eq!(false, config.secondary);
        assert_eq!(None, config.app_group);
        assert_eq!(None, config.data_dir);
        assert_eq!(None, config.dpdk_args);
        assert_eq!(default_capacity(), config.mempool.capacity);
        assert_eq!(default_cache_size(), config.mempool.cache_size);
        assert_eq!(None, config.ports[0].args);
        assert!(config.ports[0].rx_cores.is_empty());
        assert!(config.ports[0].tx_cores.is_empty());
        assert_eq!(default_port_rxqs(), config.ports[0].rxqs);
        assert_eq!(default_port_txqs(), config.ports[0].txqs);
        assert_eq!(default_promiscuous_mode(), config.ports[0].promiscuous);
        assert_eq!(default_multicast_mode(), config.ports[0].multicast);

        assert_eq!("/var/capsule/myapp", &config.data_dir());

        Ok(())
    }

    #[test]
    fn config_to_eal_args() -> Result<()> {
        const CONFIG: &str = r#"
            app_name = "myapp"
            secondary = false
            app_group = "mygroup"
            main_core = 0
            worker_cores = [1, 2]
            dpdk_args = "-v --log-level eal:8"
            [mempool]
                capacity = 255
                cache_size = 16
            [[ports]]
                name = "eth0"
                device = "0000:00:01.0"
                rx_cores = [3]
                tx_cores = [0]
                rxqs = 32
                txqs = 32
            [[ports]]
                name = "eth1"
                device = "net_pcap0"
                args = "rx=lo,tx=lo"
                tx_cores = [4]
                rxqs = 32
                txqs = 32
        "#;

        let config: RuntimeConfig = toml::from_str(CONFIG)?;

        assert_eq!(
            &[
                "myapp",
                "--proc-type",
                "primary",
                "--file-prefix",
                "mygroup",
                "--pci-whitelist",
                "0000:00:01.0",
                "--vdev",
                "net_pcap0,rx=lo,tx=lo",
                "--master-lcore",
                "127",
                "--lcores",
                "0,1,2,3,4,127@0",
                "-v",
                "--log-level",
                "eal:8"
            ],
            config.to_eal_args().as_slice(),
        );

        Ok(())
    }
}
