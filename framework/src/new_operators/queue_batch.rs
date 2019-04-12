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
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// A reference counted VecQueue
///
/// Only safe for single-threaded access
pub type SingleThreadedQueue<T> = Rc<RefCell<VecDeque<T>>>;

/// A type that can enqueue items
pub trait Enqueue {
    type Item;

    fn enqueue(&self, item: Self::Item);
}

/// A type that can dequeue items
pub trait Dequeue {
    type Item;

    fn dequeue(&self) -> Option<Self::Item>;
}

impl<T> Enqueue for SingleThreadedQueue<T> {
    type Item = T;

    fn enqueue(&self, item: Self::Item) {
        self.borrow_mut().push_back(item);
    }
}

impl<T> Dequeue for SingleThreadedQueue<T> {
    type Item = T;

    fn dequeue(&self) -> Option<Self::Item> {
        self.borrow_mut().pop_front()
    }
}

/// Queue based receive operator
///
/// New items can be enqueued through the producer reference. To
/// create a new instance, use `single_threaded_batch` function.
pub struct QueueBatch<Q: Dequeue> {
    queue: Q,
}

impl<Q: Dequeue> QueueBatch<Q> {
    fn new(queue: Q) -> Self {
        QueueBatch { queue }
    }
}

impl<Q: Dequeue> Batch for QueueBatch<Q>
where
    Q::Item: Packet,
{
    type Item = Q::Item;

    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.queue.dequeue().map(|p| Ok(p))
    }

    fn receive(&mut self) {
        // nop
    }
}

/// Returns a `QueueBatch` and the corresponding producer for
/// single-threaded use.
pub fn single_threaded_batch<T: Packet>(
    capacity: usize,
) -> (SingleThreadedQueue<T>, QueueBatch<SingleThreadedQueue<T>>) {
    let queue = Rc::new(RefCell::new(VecDeque::with_capacity(capacity)));
    (queue.clone(), QueueBatch::new(queue))
}
