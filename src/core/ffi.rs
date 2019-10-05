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

pub use capsule_ffi::*;

use crate::dpdk::DpdkError;
use crate::Result;
use log::warn;
use std::ffi::{CStr, CString};
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

/// Simplify `String` and `&str` to raw pointer conversion
pub trait ToRaw {
    type Ptr;

    #[inline]
    fn to_raw(self) -> Self::Ptr;
}

impl ToRaw for &str {
    type Ptr = *const raw::c_char;

    fn to_raw(self) -> Self::Ptr {
        unsafe { CStr::from_bytes_with_nul_unchecked(self.as_bytes()).as_ptr() }
    }
}

impl ToRaw for String {
    type Ptr = *mut raw::c_char;

    fn to_raw(self) -> Self::Ptr {
        unsafe { CString::from_vec_unchecked(self.into_bytes()).into_raw() }
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
