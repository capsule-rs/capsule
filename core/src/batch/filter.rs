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

/// A batch that filters the packets of the underlying batch.
///
/// If the predicate evaluates to `false`, the packet is marked as dropped
/// and will short-circuit the remainder of the pipeline.
#[allow(missing_debug_implementations)]
pub struct Filter<B: Batch, P>
where
    P: FnMut(&B::Item) -> bool,
{
    batch: B,
    predicate: P,
}

impl<B: Batch, P> Filter<B, P>
where
    P: FnMut(&B::Item) -> bool,
{
    /// Creates a new `Filter` batch.
    #[inline]
    pub fn new(batch: B, predicate: P) -> Self {
        Filter { batch, predicate }
    }
}

impl<B: Batch, P> Batch for Filter<B, P>
where
    P: FnMut(&B::Item) -> bool,
{
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|pkt| {
                if (self.predicate)(&pkt) {
                    Disposition::Act(pkt)
                } else {
                    Disposition::Drop(pkt.reset())
                }
            })
        })
    }
}
