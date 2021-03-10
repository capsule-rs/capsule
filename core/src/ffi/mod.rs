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

pub(crate) mod dpdk;

pub(crate) use capsule_ffi::*;

use crate::warn;
use anyhow::Result;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::ops::{Deref, DerefMut};
use std::os::raw;
use std::ptr::NonNull;

/// Simplify `*const c_char` or [c_char] to `&str` conversion.
pub(crate) trait AsStr {
    fn as_str(&self) -> &str;
}

impl AsStr for *const raw::c_char {
    #[inline]
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
    #[inline]
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
pub(crate) trait ToCString {
    fn into_cstring(self) -> CString;
}

impl ToCString for String {
    #[inline]
    fn into_cstring(self) -> CString {
        CString::new(self).unwrap()
    }
}

impl ToCString for &str {
    #[inline]
    fn into_cstring(self) -> CString {
        CString::new(self).unwrap()
    }
}

/// Simplify dpdk FFI binding's return to a `Result` type.
///
/// # Example
///
/// ```
/// ffi::rte_eth_add_tx_callback(..., ..., ..., ...)
///     .into_result(|_| {
///         DpdkError::new()
/// })?;
/// ```
pub(crate) trait ToResult {
    type Ok;

    fn into_result<E, F>(self, f: F) -> Result<Self::Ok>
    where
        E: Error + Send + Sync + 'static,
        F: FnOnce(Self) -> E,
        Self: Sized;
}

impl<T> ToResult for *mut T {
    type Ok = NonNull<T>;

    #[inline]
    fn into_result<E, F>(self, f: F) -> Result<Self::Ok>
    where
        E: Error + Send + Sync + 'static,
        F: FnOnce(Self) -> E,
    {
        NonNull::new(self).ok_or_else(|| f(self).into())
    }
}

impl<T> ToResult for *const T {
    type Ok = *const T;

    #[inline]
    fn into_result<E, F>(self, f: F) -> Result<Self::Ok>
    where
        E: Error + Send + Sync + 'static,
        F: FnOnce(Self) -> E,
    {
        if self.is_null() {
            Err(f(self).into())
        } else {
            Ok(self)
        }
    }
}

impl ToResult for raw::c_int {
    type Ok = u32;

    #[inline]
    fn into_result<E, F>(self, f: F) -> Result<Self::Ok>
    where
        E: Error + Send + Sync + 'static,
        F: FnOnce(Self) -> E,
    {
        if self >= 0 {
            Ok(self as u32)
        } else {
            Err(f(self).into())
        }
    }
}

/// Makes NonNull even easier to use with the downside that it hides the
/// unsafeness of the underlying pointer access.
pub(crate) struct EasyPtr<T>(NonNull<T>);

impl<T> Deref for EasyPtr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl<T> DerefMut for EasyPtr<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.as_mut() }
    }
}
