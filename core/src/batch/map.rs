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
use crate::Result;

/// A batch that maps the packets of the underlying batch.
///
/// On error, the packet is marked as `aborted` and will short-circuit the
/// remainder of the pipeline.
pub struct Map<B: Batch, T: Packet, M>
where
    M: FnMut(B::Item) -> Result<T>,
{
    batch: B,
    map: M,
}

impl<B: Batch, T: Packet, M> Map<B, T, M>
where
    M: FnMut(B::Item) -> Result<T>,
{
    #[inline]
    pub fn new(batch: B, map: M) -> Self {
        Map { batch, map }
    }
}

impl<B: Batch, T: Packet, M> Batch for Map<B, T, M>
where
    M: FnMut(B::Item) -> Result<T>,
{
    type Item = T;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|orig| {
                // because the ownership is moved into the map fn, we have
                // to keep a copy of the underlying mbuf pointer in case we
                // error out.
                let mbuf = orig.mbuf().clone();

                match (self.map)(orig) {
                    Ok(new) => {
                        // TODO: should ref count, not this hacky way.
                        std::mem::forget(mbuf);
                        Disposition::Act(new)
                    }
                    Err(e) => Disposition::Abort(mbuf, e),
                }
            })
        })
    }
}
