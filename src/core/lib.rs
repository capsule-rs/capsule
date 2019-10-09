extern crate failure;
extern crate log;
extern crate nb2_ffi;

// make sure macros are defined before other mods
mod macros;

mod dpdk;
mod ffi;
mod runtime;

pub use crate::dpdk::Mbuf;
pub use crate::runtime::Runtime;

use failure::Error;
use std::result;

/// A type alias of `std:result::Result` for convenience.
pub type Result<T> = result::Result<T, Error>;
