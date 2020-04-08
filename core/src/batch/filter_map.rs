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
use crate::Mbuf;
use failure::Fallible;

/// The result of a [`filter_map`].
///
/// [`filter_map`]: crate::batch::Batch::filter_map
#[allow(missing_debug_implementations)]
pub enum Either<T> {
    /// Keeps the packet as mapped result.
    Keep(T),

    /// Drops the packet.
    Drop(Mbuf),
}

/// A batch that both filters and maps the packets of the underlying batch.
///
/// If the closure returns `Drop`, the packet is marked as dropped. On
/// error, the packet is marked as aborted. In both scenarios, it will
/// short-circuit the remainder of the pipeline.
#[allow(missing_debug_implementations)]
pub struct FilterMap<B: Batch, T: Packet, F>
where
    F: FnMut(B::Item) -> Fallible<Either<T>>,
{
    batch: B,
    f: F,
}

impl<B: Batch, T: Packet, F> FilterMap<B, T, F>
where
    F: FnMut(B::Item) -> Fallible<Either<T>>,
{
    /// Creates a new `FilterMap` batch.
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        FilterMap { batch, f }
    }
}

impl<B: Batch, T: Packet, F> Batch for FilterMap<B, T, F>
where
    F: FnMut(B::Item) -> Fallible<Either<T>>,
{
    type Item = T;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|orig| match (self.f)(orig) {
                Ok(Either::Keep(new)) => Disposition::Act(new),
                Ok(Either::Drop(mbuf)) => Disposition::Drop(mbuf),
                Err(e) => Disposition::Abort(e),
            })
        })
    }
}
