// alias for the test macro
#[cfg(test)]
extern crate self as nb2;

pub mod batch;
pub mod config;
mod dpdk;
mod ffi;
mod macros;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod net;
pub mod packets;
#[cfg(feature = "pcap-dump")]
pub mod pcap;
mod runtime;
#[cfg(any(test, feature = "testils"))]
pub mod testils;

pub use self::batch::{Batch, Pipeline, Poll};
pub use self::dpdk::{KniRx, KniTxQueue, Mbuf, PortQueue, SizeOf};
pub use self::runtime::{Runtime, UnixSignal};
pub use nb2_macros::SizeOf;
#[cfg(any(test, feature = "testils"))]
pub use nb2_macros::{bench, test};

/// A type alias of `std:result::Result` for convenience.
pub type Result<T> = std::result::Result<T, failure::Error>;
