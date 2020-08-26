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
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::rc::Rc;

/// A bridge between the main batch pipeline and the branch pipelines
/// created by the [`GroupBy`] combinator. Packets can be fed one at a time
/// through the bridge. Because the pipeline execution is depth first,
/// this is the most efficient way storage wise.
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct Bridge<T: Packet>(Rc<Cell<Option<T>>>);

impl<T: Packet> Bridge<T> {
    /// Creates a new, empty bridge.
    pub fn new() -> Self {
        Bridge(Rc::new(Cell::new(None)))
    }

    /// Feeds a packet into the bridge container.
    pub fn set(&self, pkt: T) {
        self.0.set(Some(pkt));
    }
}

impl<T: Packet> Clone for Bridge<T> {
    fn clone(&self) -> Self {
        Bridge(Rc::clone(&self.0))
    }
}

impl<T: Packet> Batch for Bridge<T> {
    type Item = T;

    fn replenish(&mut self) {
        // nothing to do
    }

    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        self.0.take().map(Disposition::Act)
    }
}

/// Builder closure for a sub batch from a bridge.
pub type GroupByBatchBuilder<T> = dyn FnOnce(Bridge<T>) -> Box<dyn Batch<Item = T>>;

/// A batch that splits the underlying batch into multiple sub batches.
///
/// A closure is used to extract the discriminator used to determine how to
/// split the packets in the batch. If a packet is unmatched, it will be
/// marked as dropped. On error, the packet is marked as aborted.
///
/// All the sub batches must have the same packet type as the underlying
/// batch.
#[allow(missing_debug_implementations)]
pub struct GroupBy<B: Batch, D, S>
where
    D: Eq + Clone + Hash,
    S: Fn(&B::Item) -> D,
{
    batch: B,
    selector: S,
    bridge: Bridge<B::Item>,
    groups: HashMap<D, Box<dyn Batch<Item = B::Item>>>,
    catchall: Box<dyn Batch<Item = B::Item>>,
    fanouts: VecDeque<Disposition<B::Item>>,
}

impl<B: Batch, D, S> GroupBy<B, D, S>
where
    D: Eq + Clone + Hash,
    S: Fn(&B::Item) -> D,
{
    /// Creates a new `GroupBy` batch.
    #[inline]
    pub fn new<C>(batch: B, selector: S, composer: C) -> Self
    where
        C: FnOnce(&mut HashMap<Option<D>, Box<GroupByBatchBuilder<B::Item>>>),
    {
        // get the builders for the sub batches
        let mut builders = HashMap::new();
        composer(&mut builders);

        let bridge = Bridge::new();

        // build the catchall batch pipeline
        let catchall = builders.remove(&None).unwrap()(bridge.clone());

        // build the rest of the batch pipelines
        let groups = builders
            .into_iter()
            .map(|(key, build)| {
                let key = key.unwrap();
                let group = build(bridge.clone());
                (key, group)
            })
            .collect::<HashMap<_, _>>();

        GroupBy {
            batch,
            selector,
            bridge,
            groups,
            catchall,
            fanouts: VecDeque::new(),
        }
    }
}

impl<B: Batch, D, S> Batch for GroupBy<B, D, S>
where
    D: Eq + Clone + Hash,
    S: Fn(&B::Item) -> D,
{
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<Self::Item>> {
        if let Some(disp) = self.fanouts.pop_front() {
            Some(disp)
        } else {
            self.batch.next().map(|disp| {
                disp.map(|pkt| {
                    // gets the discriminator key
                    let key = (self.selector)(&pkt);

                    // feeds this packet through the bridge
                    self.bridge.set(pkt);

                    // runs the packet through. the sub-batch could be a fanout
                    // that produces multiple packets from one input. they are
                    // temporarily stored in a queue and returned in the subsequent
                    // iterations.
                    let batch = match self.groups.get_mut(&key) {
                        Some(group) => group,
                        None => &mut self.catchall,
                    };

                    while let Some(next) = batch.next() {
                        self.fanouts.push_back(next)
                    }

                    self.fanouts.pop_front().unwrap()
                })
            })
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __compose {
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*) => {{
        $(
            $map.insert(Some($key), Box::new(|$arg| Box::new($body)));
        )*
    }};
}

/// Composes the batch builders for the [`group_by`] combinator.
///
/// [`group_by`]: crate::batch::Batch::group_by
#[macro_export]
macro_rules! compose {
    ($map:ident { $($key:expr => |$arg:tt| $body:block)+ }) => {{
        $crate::__compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|group| Box::new(group)));
    }};
    ($map:ident { $($key:expr => |$arg:tt| $body:block)+ _ => |$_arg:tt| $_body:block }) => {{
        $crate::__compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
    ($map:ident { $($key:expr),+ => |$arg:tt| $body:block }) => {{
        $crate::compose!($map { $($key => |$arg| $body)+ });
    }};
    ($map:ident { $($key:expr),+ => |$arg:tt| $body:block _ => |$_arg:tt| $_body:block }) => {{
        $crate::compose!($map { $($key => |$arg| $body)+ _ => |$_arg| $_body });
    }};
    ($map:ident { _ => |$_arg:tt| $_body:block }) => {{
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
}
