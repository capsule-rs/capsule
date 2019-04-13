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

use super::{Batch, Enqueue, PacketError, QueueBatch, SingleThreadedQueue};
use packets::Packet;
use std::collections::HashMap;

/// Lazily-evaluate groupby operator
///
/// When unmatched, the packet is marked as dropped and will short-circuit
/// the remainder of the pipeline.
///
/// On error, the packet is marked as aborted and will short-circuit the
/// remainder of the pipeline.
pub struct GroupByBatch<B: Batch, S>
where
    S: FnMut(&B::Item) -> usize,
{
    source: B,
    selector: S,
    producer: SingleThreadedQueue<B::Item>,
    groups: Vec<Box<Batch<Item = B::Item>>>,
}

impl<B: Batch, S> GroupByBatch<B, S>
where
    S: FnMut(&B::Item) -> usize,
{
    #[inline]
    pub fn new<C>(source: B, size: usize, selector: S, composer: C) -> Self
    where
        C: FnOnce(
            HashMap<usize, QueueBatch<SingleThreadedQueue<B::Item>>>,
        ) -> Vec<Box<Batch<Item = B::Item>>>,
    {
        let queue = SingleThreadedQueue::<B::Item>::new(1);
        let groups = (0..size)
            .map(|idx| (idx, QueueBatch::new(queue.clone())))
            .collect::<HashMap<_, _>>();
        let groups = composer(groups);

        GroupByBatch {
            source,
            selector,
            producer: queue,
            groups,
        }
    }
}

impl<B: Batch, S> Batch for GroupByBatch<B, S>
where
    S: FnMut(&B::Item) -> usize,
{
    type Item = B::Item;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| {
            match item {
                Ok(packet) => {
                    let group = (self.selector)(&packet);
                    if group < self.groups.len() {
                        self.producer.enqueue(packet);
                        self.groups[group].next().unwrap()
                    } else {
                        // can't find the group, drop the packet
                        Err(PacketError::Drop(packet.mbuf()))
                    }
                }
                Err(e) => Err(e),
            }
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}

/// Merges a list of `Batch` into a `Vec<Box<Batch>>`
#[macro_export]
macro_rules! merge {
    ($($x:expr,)*) => (vec![$(Box::new($x)),*])
}
