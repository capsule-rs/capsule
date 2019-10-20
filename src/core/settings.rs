use crate::dpdk::CoreId;
use clap::clap_app;
use config::{Config, ConfigError, File, FileFormat};
use regex::Regex;
use serde::Deserialize;
use std::fmt;

pub const DEFAULT_MEMPOOL_CAPACITY: usize = 65535;
pub const DEFAULT_PORT_RXD: usize = 128;
pub const DEFAULT_PORT_TXD: usize = 128;

/// Runtime settings.
#[derive(Deserialize)]
pub struct RuntimeSettings {
    /// Application name. This must be unique if you want to run multiple
    /// DPDK applications on the same system.
    pub app_name: String,

    /// The identifier of the master core. This is the core the main thread
    /// will run on. The default value is `0`.
    pub master_core: usize,

    /// Additional cores that are available to the application, and can be
    /// used for running general tasks. Packet pipelines cannot be run on
    /// these cores unless the core is also assigned to a port separately.
    /// The default is the empty list.
    pub cores: Vec<usize>,

    /// Per mempool settings. On a system with multiple sockets, aka NUMA
    /// nodes, one mempool will be allocated for each socket the apllication
    /// uses.
    pub mempool: MempoolSettings,

    /// The ports to use for the application. Must have at least one.
    pub ports: Vec<PortSettings>,

    /// Additional DPDK parameters to pass on for EAL initialization. When
    /// set, the values are passed through as is without validation.
    ///
    /// See https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html.
    pub dpdk_args: Option<String>,

    /// If set, the application will stop after the duration expires. Useful
    /// for setting a timeout for integration tests.
    pub duration: Option<u64>,
}

impl RuntimeSettings {
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

        cores.iter().map(|&i| CoreId::new(i)).collect::<Vec<_>>()
    }

    /// Extracts the EAL arguments from runtime settings.
    pub(crate) fn to_eal_args(&self) -> Vec<String> {
        let mut eal_args = vec![];

        // add the app name
        eal_args.push(self.app_name.clone());

        // add all the ports
        let pcie = Regex::new(r"^\d{4}:\d{2}:\d{2}\.\d$").unwrap();
        self.ports.iter().for_each(|port| {
            if pcie.is_match(port.name.as_str()) {
                eal_args.push("--pci-whitelist".to_owned());
                eal_args.push(port.name.clone());
            } else {
                let vdev = if let Some(args) = &port.args {
                    format!("{},{}", port.name, args)
                } else {
                    port.name.clone()
                };
                eal_args.push("--vdev".to_owned());
                eal_args.push(vdev);
            }
        });

        // add the master core
        eal_args.push("--master-lcore".to_owned());
        eal_args.push(self.master_core.to_string());

        // add the assigned cores
        let mut cores = self.all_cores();
        let acc = cores.remove(0).raw().to_string();
        let cores = cores
            .into_iter()
            .fold(acc, |acc, core| format!("{},{}", acc, core.raw()));
        eal_args.push("-l".to_owned());
        eal_args.push(cores);

        // add additional DPDK args
        if let Some(args) = &self.dpdk_args {
            eal_args.extend(args.split_ascii_whitespace().map(str::to_owned));
        }

        eal_args
    }
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        RuntimeSettings {
            app_name: Default::default(),
            master_core: 0,
            cores: vec![],
            mempool: Default::default(),
            ports: vec![],
            dpdk_args: None,
            duration: None,
        }
    }
}

impl fmt::Debug for RuntimeSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("");
        d.field("app_name", &self.app_name)
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

/// Mempool settings.
#[derive(Deserialize)]
pub struct MempoolSettings {
    /// The maximum number of Mbufs the mempool can allocate. The optimum
    /// size (in terms of memory usage) is when n is a power of two minus
    /// one. The default is `65535` or `2 ^ 16 - 1`.
    pub capacity: usize,

    /// The size of the per core object cache. If cache_size is non-zero,
    /// the library will try to limit the accesses to the common lockless
    /// pool. The cache can be disabled if the argument is set to 0. The
    /// default is `0`.
    pub cache_size: usize,
}

impl Default for MempoolSettings {
    fn default() -> Self {
        MempoolSettings {
            capacity: DEFAULT_MEMPOOL_CAPACITY,
            cache_size: 0,
        }
    }
}

impl fmt::Debug for MempoolSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("")
            .field("capacity", &self.capacity)
            .field("cache_size", &self.cache_size)
            .finish()
    }
}

/// Port settings.
#[derive(Deserialize)]
pub struct PortSettings {
    /// The device name of the port. It can be the following formats,
    ///
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    pub name: String,

    /// Additional arguments to configure a virtual device.
    pub args: Option<String>,

    /// The cores assigned to the port for running the pipelines. The values
    /// can overlap with the runtime cores. The default is [0].
    pub cores: Vec<usize>,

    /// The receive queue capacity. The default is 128.
    pub rxd: usize,

    /// The transmit queue capacity. The default is 128.
    pub txd: usize,
}

impl PortSettings {
    /// Returns the assigned cores.
    pub(crate) fn cores(&self) -> Vec<CoreId> {
        self.cores
            .iter()
            .map(|&i| CoreId::new(i))
            .collect::<Vec<_>>()
    }
}

impl Default for PortSettings {
    fn default() -> Self {
        PortSettings {
            name: Default::default(),
            args: None,
            cores: vec![0],
            rxd: DEFAULT_PORT_RXD,
            txd: DEFAULT_PORT_TXD,
        }
    }
}

impl fmt::Debug for PortSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("");
        d.field("name", &self.name);
        if let Some(args) = &self.args {
            d.field("args", args);
        }
        d.field("cores", &self.cores)
            .field("rxd", &self.rxd)
            .field("txd", &self.txd)
            .finish()
    }
}

// base config with app defaults
static DEFAULT_TOML: &str = r#"
    app_name = "nb2"
    master_core = 0
    cores = []
    ports = []
    [mempool]
      capacity = 65535
      cache_size = 0
"#;

/// Loads the app config from a TOML file.
///
/// # Example
///
/// ```
/// home$ ./myapp -f config.toml
/// ```
pub fn load_config() -> Result<RuntimeSettings, ConfigError> {
    let matches = clap_app!(app =>
        (version: "0.1.0")
        (@arg file: -f --file +required +takes_value "configuration file")
    )
    .get_matches();

    let filename = matches.value_of("file").unwrap();

    let mut config = Config::new();
    config.merge(File::from_str(DEFAULT_TOML, FileFormat::Toml))?;
    config.merge(File::with_name(filename))?;
    config.try_into()
}
