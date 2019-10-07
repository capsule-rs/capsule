pub use nb2_ffi::*;

use crate::dpdk::DpdkError;
use crate::Result;
use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr::NonNull;

/// Simplify `*const c_char` or [c_char] to `&str` conversion.
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

impl AsStr for [raw::c_char] {
    fn as_str(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.as_ptr()).to_str().unwrap_or_else(|_| {
                warn!("invalid UTF8 data");
                Default::default()
            })
        }
    }
}

/// Simplify `String` and `&str` to `CString` conversion.
pub trait ToCString {
    fn to_cstring(self) -> CString;
}

impl ToCString for String {
    fn to_cstring(self) -> CString {
        CString::new(self).unwrap()
    }
}

impl ToCString for &str {
    fn to_cstring(self) -> CString {
        CString::new(self).unwrap()
    }
}

/// Simplify FFI binding's return to `Result` conversion.
pub trait ToResult {
    type Ok;

    #[inline]
    fn to_result(self) -> Result<Self::Ok>;
}

impl ToResult for raw::c_int {
    type Ok = u32;

    fn to_result(self) -> Result<Self::Ok> {
        match self {
            -1 => Err(DpdkError::new().into()),
            err if err < 0 => Err(DpdkError::new_with_errno(-err).into()),
            _ => Ok(self as u32),
        }
    }
}

impl<T> ToResult for *mut T {
    type Ok = NonNull<T>;

    fn to_result(self) -> Result<Self::Ok> {
        NonNull::new(self).ok_or_else(|| DpdkError::new().into())
    }
}
