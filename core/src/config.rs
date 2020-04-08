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
//! ```
//! app_name = "pktdump"
//! master_core = 0
//! duration = 5
//!
//! [mempool]
//!     capacity = 65535
//!     cache_size = 256
//!
//! [[ports]]
//!     name = "eth1"
//!     device = "net_pcap0"
//!     args = "rx_pcap=tcp4.pcap,tx_iface=lo"
//!     cores = [0]
//!
//! [[ports]]
//!     name = "eth2"
//!     device = "net_pcap1"
//!     args = "rx_pcap=tcp6.pcap,tx_iface=lo"
//!     cores = [0]
//! ```
//!
//! [`pktdump`]: https://github.com/capsule-rs/capsule/tree/master/examples/pktdump

use crate::dpdk::CoreId;
use crate::net::{Ipv4Cidr, Ipv6Cidr, MacAddr};
use clap::{clap_app, crate_version};
use failure::Fallible;
use regex::Regex;
use serde::{de, Deserialize, Deserializer};
use std::fmt;
use std::fs;
use std::str::FromStr;
use std::time::Duration;

// make `CoreId` serde deserializable.
impl<'de> Deserialize<'de> for CoreId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let i = usize::deserialize(deserializer)?;
        Ok(CoreId::new(i))
    }
}

// make `MacAddr` serde deserializable.
impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        MacAddr::from_str(&s).map_err(de::Error::custom)
    }
}

// make `Ipv4Cidr` serde deserializable.
impl<'de> Deserialize<'de> for Ipv4Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ipv4Cidr::from_str(&s).map_err(de::Error::custom)
    }
}

// make `Ipv6Cidr` serde deserializable.
impl<'de> Deserialize<'de> for Ipv6Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ipv6Cidr::from_str(&s).map_err(de::Error::custom)
    }
}

/// Deserializes a duration from seconds expressed as `u64`.
pub fn duration_from_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

/// Deserializes an option of duration from seconds expressed as `u64`.
pub fn duration_option_from_secs<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    // for now this is the cleanest way to deserialize an option, till a better
    // way is implemented, https://github.com/serde-rs/serde/issues/723
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "duration_from_secs")] Duration);

    let option = Option::deserialize(deserializer)?.and_then(|Wrapper(dur)| {
        if dur.as_secs() > 0 {
            Some(dur)
        } else {
            None
        }
    });
    Ok(option)
}

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

    /// The identifier of the master core. This is the core the main thread
    /// will run on.
    pub master_core: CoreId,

    /// Additional cores that are available to the application, and can be
    /// used for running general tasks. Packet pipelines cannot be run on
    /// these cores unless the core is also assigned to a port separately.
    /// Defaults to empty list.
    #[serde(default)]
    pub cores: Vec<CoreId>,

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

    /// If set, the application will stop after the duration expires. Useful
    /// for setting a timeout for integration tests.
    #[serde(default, deserialize_with = "duration_option_from_secs")]
    pub duration: Option<Duration>,
}

impl RuntimeConfig {
    /// Returns all the cores assigned to the runtime.
    pub(crate) fn all_cores(&self) -> Vec<CoreId> {
        let mut cores = vec![];
        cores.push(self.master_core);
        cores.extend(self.cores.iter());

        self.ports.iter().for_each(|port| {
            cores.extend(port.cores.iter());
        });

        cores.sort();
        cores.dedup();
        cores
    }

    /// Extracts the EAL arguments from runtime settings.
    pub(crate) fn to_eal_args(&self) -> Vec<String> {
        let mut eal_args = vec![];

        // adds the app name
        eal_args.push(self.app_name.clone());

        let proc_type = if self.secondary {
            "secondary".to_owned()
        } else {
            "primary".to_owned()
        };

        // adds the proc type
        eal_args.push("--proc-type".to_owned());
        eal_args.push(proc_type);

        // adds the mem file prefix
        let prefix = self.app_group.as_ref().unwrap_or(&self.app_name);
        eal_args.push("--file-prefix".to_owned());
        eal_args.push(prefix.clone());

        // adds all the ports
        let pcie = Regex::new(r"^\d{4}:\d{2}:\d{2}\.\d$").unwrap();
        self.ports.iter().for_each(|port| {
            if pcie.is_match(port.device.as_str()) {
                eal_args.push("--pci-whitelist".to_owned());
                eal_args.push(port.device.clone());
            } else {
                let vdev = if let Some(args) = &port.args {
                    format!("{},{}", port.device, args)
                } else {
                    port.device.clone()
                };
                eal_args.push("--vdev".to_owned());
                eal_args.push(vdev);
            }
        });

        // adds the master core
        eal_args.push("--master-lcore".to_owned());
        eal_args.push(self.master_core.raw().to_string());

        // limits the EAL to only the master core. actual threads are
        // managed by the runtime not the EAL.
        eal_args.push("-l".to_owned());
        eal_args.push(self.master_core.raw().to_string());

        // adds additional DPDK args
        if let Some(args) = &self.dpdk_args {
            eal_args.extend(args.split_ascii_whitespace().map(str::to_owned));
        }

        eal_args
    }

    /// Returns the number of KNI enabled ports
    pub(crate) fn num_knis(&self) -> usize {
        self.ports.iter().filter(|p| p.kni).count()
    }
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("runtime");
        d.field("app_name", &self.app_name)
            .field("secondary", &self.secondary)
            .field(
                "app_group",
                self.app_group.as_ref().unwrap_or(&self.app_name),
            )
            .field("master_core", &self.master_core)
            .field("cores", &self.cores)
            .field("mempool", &self.mempool)
            .field("ports", &self.ports);
        if let Some(dpdk_args) = &self.dpdk_args {
            d.field("dpdk_args", dpdk_args);
        }
        if let Some(duration) = &self.duration {
            d.field("duration", duration);
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
        f.debug_struct("mempool")
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

    /// The cores assigned to the port for running the pipelines. The values
    /// can overlap with the runtime cores.
    pub cores: Vec<CoreId>,

    /// The receive queue capacity. Defaults to `128`.
    #[serde(default = "default_port_rxd")]
    pub rxd: usize,

    /// The transmit queue capacity. Defaults to `128`.
    #[serde(default = "default_port_txd")]
    pub txd: usize,

    /// Whether promiscuous mode is enabled for this port. Defaults to `false`.
    #[serde(default)]
    pub promiscuous: bool,

    /// Whether multicast packet reception is enabled for this port. Defaults
    /// to `true`.
    #[serde(default = "default_multicast_mode")]
    pub multicast: bool,

    /// Whether kernel NIC interface is enabled for this port. with KNI, this
    /// port can exchange packets with the kernel networking stack. Defaults
    /// to `false`.
    #[serde(default)]
    pub kni: bool,
}

fn default_port_rxd() -> usize {
    128
}

fn default_port_txd() -> usize {
    128
}

fn default_multicast_mode() -> bool {
    true
}

impl fmt::Debug for PortConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("port");
        d.field("name", &self.name);
        d.field("device", &self.device);
        if let Some(args) = &self.args {
            d.field("args", args);
        }
        d.field("cores", &self.cores)
            .field("rxd", &self.rxd)
            .field("txd", &self.txd)
            .field("promiscuous", &self.promiscuous)
            .field("multicast", &self.multicast)
            .field("kni", &self.kni)
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
pub fn load_config() -> Fallible<RuntimeConfig> {
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
    fn config_defaults() {
        const CONFIG: &str = r#"
            app_name = "myapp"
            master_core = 0

            [[ports]]
                name = "eth0"
                device = "0000:00:01.0"
                cores = [2, 3]
        "#;

        let config: RuntimeConfig = toml::from_str(CONFIG).unwrap();

        assert_eq!(false, config.secondary);
        assert_eq!(None, config.app_group);
        assert!(config.cores.is_empty());
        assert_eq!(None, config.dpdk_args);
        assert_eq!(default_capacity(), config.mempool.capacity);
        assert_eq!(default_cache_size(), config.mempool.cache_size);
        assert_eq!(None, config.ports[0].args);
        assert_eq!(default_port_rxd(), config.ports[0].rxd);
        assert_eq!(default_port_txd(), config.ports[0].txd);
        assert_eq!(false, config.ports[0].promiscuous);
        assert_eq!(default_multicast_mode(), config.ports[0].multicast);
        assert_eq!(false, config.ports[0].kni);
    }

    #[test]
    fn config_to_eal_args() {
        const CONFIG: &str = r#"
            app_name = "myapp"
            secondary = false
            app_group = "mygroup"
            master_core = 0
            cores = [1]
            dpdk_args = "-v --log-level eal:8"

            [mempool]
                capacity = 255
                cache_size = 16

            [[ports]]
                name = "eth0"
                device = "0000:00:01.0"
                cores = [2, 3]
                rxd = 32
                txd = 32

            [[ports]]
                name = "eth1"
                device = "net_pcap0"
                args = "rx=lo,tx=lo"
                cores = [0, 4]
                rxd = 32
                txd = 32
        "#;

        let config: RuntimeConfig = toml::from_str(CONFIG).unwrap();

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
                "0",
                "-l",
                "0",
                "-v",
                "--log-level",
                "eal:8"
            ],
            config.to_eal_args().as_slice(),
        )
    }
}
