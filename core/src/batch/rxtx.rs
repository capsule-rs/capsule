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
//! Implemented for `PortQueue`.
//!
//! `PacketRx` implemented for `KniRx`.
//!
//! `PacketTx` implemented for `KniTxQueue`.
//!
//! Implemented for the MPSC channel so it can be used as a batch source
//! mostly in tests.

use super::{PacketRx, PacketTx};
use crate::{KniRx, KniTxQueue, Mbuf, PortQueue};
use std::iter;
use std::sync::mpsc::{Receiver, Sender};

impl PacketRx for PortQueue {
    fn receive(&mut self) -> Vec<Mbuf> {
        PortQueue::receive(self)
    }
}

impl PacketTx for PortQueue {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        PortQueue::transmit(self, packets)
    }
}

impl PacketRx for KniRx {
    fn receive(&mut self) -> Vec<Mbuf> {
        KniRx::receive(self)
    }
}

impl PacketTx for KniTxQueue {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        KniTxQueue::transmit(self, packets)
    }
}

impl PacketRx for Receiver<Mbuf> {
    fn receive(&mut self) -> Vec<Mbuf> {
        iter::from_fn(|| self.try_recv().ok()).collect::<Vec<_>>()
    }
}

impl PacketTx for Sender<Mbuf> {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        packets.into_iter().for_each(|packet| {
            let _ = self.send(packet);
        });
    }
}

/// A batch that polls a closure for packets.
#[allow(missing_debug_implementations)]
pub struct PollRx<F>
where
    F: Fn() -> Vec<Mbuf>,
{
    pub(crate) f: F,
}

impl<F> PacketRx for PollRx<F>
where
    F: Fn() -> Vec<Mbuf>,
{
    fn receive(&mut self) -> Vec<Mbuf> {
        (self.f)()
    }
}
