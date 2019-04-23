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
use std::collections::HashMap;

pub type PipelineBuilder<T> = FnMut(QueueBatch<SingleThreadedQueue<T>>) -> Box<Batch<Item = T>>;

/// Lazily-evaluate group_by operator
///
/// When unmatched, the packet is marked as dropped and will short-circuit
/// the remainder of the pipeline.
///
/// On error, the packet is marked as aborted and will short-circuit the
/// remainder of the pipeline.
pub struct GroupByBatch<B: Batch, K, S>
where
    K: Eq + Clone + std::hash::Hash,
    S: FnMut(&B::Item) -> K,
{
    source: B,
    selector: S,
    producer: SingleThreadedQueue<B::Item>,
    groups: HashMap<K, Box<Batch<Item = B::Item>>>,
    default: Box<Batch<Item = B::Item>>,
}

impl<B: Batch, K, S> GroupByBatch<B, K, S>
where
    K: Eq + Clone + std::hash::Hash,
    S: FnMut(&B::Item) -> K,
{
    #[inline]
    pub fn new<C>(source: B, selector: S, composer: C) -> Self
    where
        C: FnOnce(&mut HashMap<Option<K>, Box<PipelineBuilder<B::Item>>>) -> (),
    {
        let queue = SingleThreadedQueue::<B::Item>::new(1);
        let mut groups = HashMap::<Option<K>, Box<PipelineBuilder<B::Item>>>::new();
        composer(&mut groups);

        let default = groups.remove(&None).unwrap()(QueueBatch::new(queue.clone()));

        let groups = groups
            .into_iter()
            .map(|(key, mut build)| {
                let key = key.unwrap();
                let group = build(QueueBatch::new(queue.clone()));
                (key, group)
            })
            .collect::<HashMap<_, _>>();

        GroupByBatch {
            source,
            selector,
            producer: queue,
            groups,
            default,
        }
    }
}

impl<B: Batch, K, S> Batch for GroupByBatch<B, K, S>
where
    K: Eq + Clone + std::hash::Hash,
    S: FnMut(&B::Item) -> K,
{
    type Item = B::Item;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| match item {
            Ok(packet) => {
                let key = (self.selector)(&packet);
                match self.groups.get_mut(&key) {
                    Some(group) => {
                        self.producer.enqueue(packet);
                        group.next().unwrap()
                    }
                    None => {
                        self.producer.enqueue(packet);
                        self.default.next().unwrap()
                    }
                }
            }
            Err(e) => Err(e),
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
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

/// Composes the pipelines for the group_by operator
#[macro_export]
macro_rules! compose {
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*) => {{
        $crate::__compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|group| Box::new(group)));
    }};
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*,_ => |$_arg:tt| $_body:block) => {{
        $crate::__compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
}
