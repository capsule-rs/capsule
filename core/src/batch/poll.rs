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

use super::{Batch, Disposition, PacketRx, PollRx};
use crate::Mbuf;
use std::collections::VecDeque;

/// A batch that polls a receiving source for new packets.
///
/// This marks the beginning of the pipeline.
#[allow(missing_debug_implementations)]
pub struct Poll<Rx: PacketRx> {
    rx: Rx,
    packets: Option<VecDeque<Mbuf>>,
}

impl<Rx: PacketRx> Poll<Rx> {
    /// Creates a new `Poll` batch.
    #[inline]
    pub fn new(rx: Rx) -> Self {
        Poll { rx, packets: None }
    }
}

impl<Rx: PacketRx> Batch for Poll<Rx> {
    type Item = Mbuf;

    /// Replenishes the batch with new packets from the RX source.
    ///
    /// If there are still packets left in the current queue, they are lost.
    #[inline]
    fn replenish(&mut self) {
        // `VecDeque` is not the ideal structure here. We are relying on the
        // conversion from `Vec` to `VecDeque` to be allocation-free. but
        // unfortunately that's not always the case. We need an efficient and
        // allocation-free data structure with pop semantic.
        self.packets = Some(self.rx.receive().into());
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        if let Some(q) = self.packets.as_mut() {
            q.pop_front().map(Disposition::Act)
        } else {
            None
        }
    }
}

/// Creates a new poll batch from a closure.
pub fn poll_fn<F>(f: F) -> Poll<PollRx<F>>
where
    F: Fn() -> Vec<Mbuf>,
{
    Poll::new(PollRx { f })
}
