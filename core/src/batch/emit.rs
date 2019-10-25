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

/// A batch that short-circuits the remainder of the pipeline and marks
/// all packets for transmit.
pub struct Emit<B: Batch> {
    batch: B,
}

impl<B: Batch> Emit<B> {
    #[inline]
    pub fn new(batch: B) -> Self {
        Emit { batch }
    }
}

impl<B: Batch> Batch for Emit<B> {
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch
            .next()
            .map(|disp| disp.map(|pkt| Disposition::Emit(pkt.reset())))
    }
}
