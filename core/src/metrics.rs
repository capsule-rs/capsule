//! Exposes the following framework metrics.
//!
//! # Port Metrics
//!
//! * `port.packets`, total number of successfully received or transmitted
//! packets.
//! * `port.octets`, total number of successfully received or transmitted
//! bytes.
//! * `port.dropped`, total number of packets dropped because the receive
//! or transmit queues are full.
//! * `port.errors`, total number of erroneous received packets or packets
//! failed to transmit.
//! * `port.no_mbuf`, total number of packets dropped due to mbuf allocation
//! failures.
//!
//! Each metric is labeled with the port name and a direction, which can be
//! either RX or TX. Optionally, `port.packets` and `port.octets` can be
//! labeled with the core id when they are tracked per core. The per core
//! metrics are available if the number of assigned cores to the port is less
//! than or equal to `RTE_ETHDEV_QUEUE_STAT_CNTRS`. Otherwise, only the
//! overall metrics are tracked.
//!
//!
//! # KNI Metrics
//!
//! * `kni.packets`, total number of successfully received or transmitted
//! packets.
//! * `kni.octets`, total number of successfully received or transmitted bytes.
//! * `kni.dropped`, total number of packets dropped because the transmit
//! queue is full.
//!
//! Each metric is labeled with the KNI interface name and a direction, which
//! can be either RX or TX.
//!
//!
//! # Mempool Metrics
//!
//! * `mempool.used`, total number of mbufs which have been allocated from
//! the mempool.
//! * `mempool.free`, total number of mbufs available for allocation.
//!
//! Each metric is labeled with the mempool name.
//!
//!
//! # Pipeline Metrics
//!
//! * `pipeline.processed`, total number of successfully processed packets.
//! * `pipeline.dropped`, total number of packets intentionally dropped.
//! * `pipeline.errors`, total number of packet dropped due to processing
//! errors.
//!
//! Each metric is labeled with the pipeline name. If the pipeline doesn't
//! have a name, it will be labeled as "default".

// re-export some metrics types to make feature gated imports easier.
pub(crate) use metrics_core::{labels, Key};
pub(crate) use metrics_runtime::data::Counter;
pub(crate) use metrics_runtime::Measurement;

use crate::dpdk::{Mempool, MempoolStats, Port};
use crate::{warn, Result};
use failure::format_err;
use metrics_runtime::{Receiver, Sink};
use once_cell::sync::{Lazy, OnceCell};

/// The metrics store.
static RECEIVER: OnceCell<Receiver> = OnceCell::new();

/// Safely initializes the metrics store. Because the receiver builder could
/// potentially fail, the `Lazy` convenience type is not safe.
///
/// Also very important that `init` is not called twice.
pub(crate) fn init() -> Result<()> {
    let receiver = Receiver::builder().build()?;

    RECEIVER
        .set(receiver)
        .map_err(|_| format_err!("already initialized."))?;
    Ok(())
}

/// Registers DPDK collected port stats with the metrics store.
pub(crate) fn register_port_stats(ports: &[Port]) {
    let stats = ports.iter().map(Port::stats).collect::<Vec<_>>();
    SINK.clone().proxy("port", move || {
        stats
            .iter()
            .flat_map(|s| {
                s.collect().unwrap_or_else(|err| {
                    warn!(message = "failed to collect stats.", port = s.name(), ?err);
                    Vec::new()
                })
            })
            .collect()
    });
}

/// Registers collected mempool stats with the metrics store.
pub(crate) fn register_mempool_stats(mempools: &[Mempool]) {
    let stats = mempools.iter().map(Mempool::stats).collect::<Vec<_>>();
    SINK.clone().proxy("mempool", move || {
        stats.iter().flat_map(MempoolStats::collect).collect()
    });
}

/// Returns the global metrics store.
///
/// Metrics are managed using [metrics-rs]. The application can use this to
/// access framework metrics or to add new application metrics.
///
/// # Panics
///
/// Panics if `Runtime::build` is not called first.
///
/// [metrics-rs]: https://github.com/metrics-rs
pub fn global() -> &'static Receiver {
    unsafe { RECEIVER.get_unchecked() }
}

/// The root sink for all framework metrics.
pub(crate) static SINK: Lazy<Sink> = Lazy::new(|| global().sink().scoped("nb2"));
