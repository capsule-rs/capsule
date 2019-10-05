extern crate failure;
extern crate log;
extern crate nb2_ffi;

pub mod dpdk;
mod ffi;
mod runtime;

pub use crate::runtime::Runtime;

use failure::Error;
use std::result;

/// A type alias of `std:result::Result` for convenience.
pub type Result<T> = result::Result<T, Error>;
