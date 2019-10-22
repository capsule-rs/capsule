// alias for the test macro
#[cfg(test)]
extern crate self as nb2;

// make sure macros are defined before other mods
mod macros;

mod core_map;
mod dpdk;
mod ffi;
mod mempool_map;
pub mod net;
pub mod packets;
mod runtime;
pub mod settings;
#[cfg(any(test, feature = "testils"))]
pub mod testils;

pub use crate::dpdk::{Mbuf, SizeOf};
pub use crate::runtime::Runtime;
pub use nb2_macros::test;

/// A type alias of `std:result::Result` for convenience.
pub type Result<T> = std::result::Result<T, failure::Error>;
