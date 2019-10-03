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

use crate::ffi;

pub struct MBuf {
    raw: *mut ffi::rte_mbuf,
}

impl MBuf {
    pub unsafe fn new(raw: *mut ffi::rte_mbuf) -> Self {
        MBuf { raw }
    }

    unsafe fn raw(&self) -> &mut ffi::rte_mbuf {
        &mut (*self.raw)
    }

    pub unsafe fn raw_ptr(&self) -> *mut ffi::rte_mbuf {
        self.raw
    }

    pub fn data_len(&self) -> u16 {
        unsafe { self.raw().data_len }
    }
}
