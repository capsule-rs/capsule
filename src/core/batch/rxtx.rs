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

//! Implementations of `PacketRx` and `PacketTx`.
//!
//! Implemented for VecDeque so it can be used as a packet RX or TX
//! in tests.

use super::{PacketRx, PacketTx};
use crate::Mbuf;
use std::collections::VecDeque;

impl PacketRx for VecDeque<Mbuf> {
    fn receive(&mut self) -> Vec<Mbuf> {
        self.drain(..).collect()
    }
}

impl PacketTx for VecDeque<Mbuf> {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        self.extend(packets)
    }
}
