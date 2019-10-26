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
use crate::Mbuf;
use futures::{future, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_executor::current_thread;

/// Turns the batch pipeline into an executable task.
pub struct Send<B: Batch, Tx: PacketTx> {
    batch: B,
    tx: Tx,
}

impl<B: Batch, Tx: PacketTx> Send<B, Tx> {
    #[inline]
    pub fn new(batch: B, tx: Tx) -> Self {
        Send { batch, tx }
    }

    fn execute(&mut self) {
        // let's get a new batch
        self.batch.replenish();

        let mut transmit_q = Vec::with_capacity(64);
        let mut drop_q = Vec::with_capacity(64);

        // consume the whole batch to completion
        while let Some(disp) = self.batch.next() {
            match disp {
                Disposition::Act(packet) => transmit_q.push(packet.reset()),
                Disposition::Emit(mbuf) => transmit_q.push(mbuf),
                Disposition::Drop(mbuf) => drop_q.push(mbuf),
                Disposition::Abort(mbuf, _) => drop_q.push(mbuf),
            }
        }

        if !transmit_q.is_empty() {
            self.tx.transmit(transmit_q);
        }

        if !drop_q.is_empty() {
            Mbuf::free_bulk(drop_q);
        }
    }
}

/// By implementing the `Future` trait, `Send` can be spawned onto the tokio
/// executor. Each time the future is polled, it processes one batch of
/// packets before returning the `Poll::Pending` status and yields.
impl<B: Batch + Unpin, Tx: PacketTx + Unpin> Future for Send<B, Tx> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        // executes a batch of packets.
        self.get_mut().execute();

        // now schedules the waker as a future and yields the core so other
        // futures have a chance to run.
        let waker = cx.waker().clone();
        current_thread::spawn(future::lazy(|_| waker.wake()));

        Poll::Pending
    }
}
