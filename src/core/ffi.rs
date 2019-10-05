pub use nb2_ffi::*;

use crate::dpdk::DpdkError;
use crate::Result;
use log::warn;
use std::ffi::CStr;
use std::os::raw;

/// Simplify `*const c_char` to `&str` conversion
pub trait AsStr {
    #[inline]
    fn as_str(&self) -> &str;
}

impl AsStr for *const raw::c_char {
    fn as_str(&self) -> &str {
        unsafe {
            CStr::from_ptr(*self).to_str().unwrap_or_else(|_| {
                warn!("invalid UTF8 data");
                Default::default()
            })
        }
    }
}

/// Simplify `c_int` to `Result` conversion
pub trait ToResult {
    type T;

    #[inline]
    fn to_result(self) -> Result<Self::T>;
}

impl ToResult for raw::c_int {
    type T = u32;

    fn to_result(self) -> Result<Self::T> {
        if self < 0 {
            Err(DpdkError::new().into())
        } else {
            Ok(self as Self::T)
        }
    }
}
