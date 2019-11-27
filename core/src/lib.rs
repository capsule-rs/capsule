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

#![feature(specialization)]

// alias for the test macro
#[cfg(test)]
extern crate self as capsule;

pub mod batch;
pub mod config;
mod dpdk;
mod ffi;
mod macros;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod net;
pub mod packets;
mod runtime;
#[cfg(any(test, feature = "testils"))]
pub mod testils;

pub use self::batch::{Batch, Pipeline, Poll};
pub use self::dpdk::{KniRx, KniTxQueue, Mbuf, PortQueue, SizeOf};
pub use self::runtime::{Runtime, UnixSignal};
#[cfg(any(test, feature = "testils"))]
pub use capsule_macros::{bench, test};

/// A type alias of `std:result::Result` for convenience.
pub type Result<T> = std::result::Result<T, failure::Error>;
