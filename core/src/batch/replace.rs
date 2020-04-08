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

use super::{Batch, Disposition};
use crate::packets::Packet;
use failure::Fallible;

/// A batch that replaces each packet of the batch with another packet.
///
/// The original packet is dropped from the batch with the new packet in its
/// place. On error, the packet is `aborted` and will short-circuit the
/// remainder of the pipeline.
#[allow(missing_debug_implementations)]
pub struct Replace<B: Batch, T: Packet, F>
where
    F: FnMut(&B::Item) -> Fallible<T>,
{
    batch: B,
    f: F,
    slot: Option<B::Item>,
}

impl<B: Batch, T: Packet, F> Replace<B, T, F>
where
    F: FnMut(&B::Item) -> Fallible<T>,
{
    /// Creates a new `Replace` batch.
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        Replace {
            batch,
            f,
            slot: None,
        }
    }
}

impl<B: Batch, T: Packet, F> Batch for Replace<B, T, F>
where
    F: FnMut(&B::Item) -> Fallible<T>,
{
    type Item = T;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        // internally the replace combinator will add a new packet to the
        // batch and mark the original as dropped. the iteration grows to
        // 2x in length because each item becomes 2 items.
        if let Some(pkt) = self.slot.take() {
            // has a packet in the temp slot. marks it as dropped.
            Some(Disposition::Drop(pkt.reset()))
        } else {
            // nothing in the slot, fetches a new packet from source.
            self.batch.next().map(|disp| {
                disp.map(|orig| {
                    match (self.f)(&orig) {
                        Ok(new) => {
                            // keeps the original in the temp slot, we will mark it dropped
                            // in the iteration that immediately follows.
                            self.slot.replace(orig);
                            Disposition::Act(new)
                        }
                        Err(e) => Disposition::Abort(e),
                    }
                })
            })
        }
    }
}
