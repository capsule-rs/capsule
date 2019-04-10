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

#![cfg(test)]

use super::{Batch, PacketError};
use packets::RawPacket;

pub struct PacketBatch {
    packets: Vec<RawPacket>,
}

impl PacketBatch {
    pub fn new(data: &[u8]) -> PacketBatch {
        PacketBatch {
            packets: vec![
                RawPacket::from_bytes(data).unwrap(),
                RawPacket::from_bytes(data).unwrap(),
                RawPacket::from_bytes(data).unwrap(),
            ],
        }
    }
}

impl Batch for PacketBatch {
    type Item = RawPacket;

    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.packets.pop().map(|p| Ok(p))
    }

    fn receive(&mut self) {
        // nop
    }
}
