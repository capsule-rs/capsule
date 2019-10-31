#![feature(specialization)]

// alias for the test macro
#[cfg(test)]
extern crate self as nb2;

pub mod batch;
mod dpdk;
mod ffi;
mod macros;
pub mod net;
pub mod packets;
mod runtime;
pub mod settings;
#[cfg(any(test, feature = "testils"))]
pub mod testils;

pub use self::batch::{Batch, Pipeline, Poll};
pub use self::dpdk::{KniRx, KniTxQueue, Mbuf, PortQueue, SizeOf};
pub use self::runtime::{Runtime, UnixSignal};
#[cfg(any(test, feature = "testils"))]
pub use nb2_macros::{bench, test};

/// A type alias of `std:result::Result` for convenience.
pub type Result<T> = std::result::Result<T, failure::Error>;
