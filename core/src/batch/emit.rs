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

use super::{Batch, Disposition, PacketTx};
use crate::packets::Packet;

/// A batch that transmits the packets through the specified [`PacketTx`].
///
/// [`PacketTx`]: crate::batch::PacketTx
#[allow(missing_debug_implementations)]
pub struct Emit<B: Batch, Tx: PacketTx> {
    batch: B,
    tx: Tx,
}

impl<B: Batch, Tx: PacketTx> Emit<B, Tx> {
    /// Creates a new `Emit` batch.
    #[inline]
    pub fn new(batch: B, tx: Tx) -> Self {
        Emit { batch, tx }
    }
}

impl<B: Batch, Tx: PacketTx> Batch for Emit<B, Tx> {
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.batch.next().map(|disp| {
            disp.map(|pkt| {
                self.tx.transmit(vec![pkt.reset()]);
                Disposition::Emit
            })
        })
    }
}
