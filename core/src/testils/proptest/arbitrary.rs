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

//! Implementations of `proptest.arbitrary.Arbitrary` trait for
//! various types.

use crate::net::MacAddr;
use crate::packets::Mbuf;
use proptest::arbitrary::{any, Arbitrary, StrategyFor};
use proptest::strategy::{MapInto, Strategy};

impl Arbitrary for MacAddr {
    type Parameters = ();
    type Strategy = MapInto<StrategyFor<[u8; 6]>, Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<[u8; 6]>().prop_map_into()
    }
}

impl Arbitrary for Mbuf {
    type Parameters = ();
    type Strategy = fn() -> Self;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        || Mbuf::new().unwrap()
    }
}
