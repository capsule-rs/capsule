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

use super::{Batch, PacketError};
use packets::Packet;

/// Lazily-evaluated emit operator
///
/// Interrupts processing with a short-circuit error that simply emits the packet
pub struct EmitBatch<B: Batch> {
    source: B,
}

impl<B: Batch> EmitBatch<B> {
    #[inline]
    pub fn new(source: B) -> Self {
        EmitBatch { source }
    }
}

impl<B: Batch> Batch for EmitBatch<B> {
    type Item = B::Item;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| match item {
            Ok(packet) => Err(PacketError::Emit(packet.mbuf())),
            e @ Err(_) => e,
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}
