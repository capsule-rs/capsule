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

use super::{Batch, PacketError, BATCH_SIZE};
use packets::Packet;

/// Send operator
///
/// Marks the end of a pipeline.
pub struct SendBatch<B: Batch, Tx: PacketTx> {
    source: B,
    port: Tx,
    transmit_q: Vec<*mut MBuf>,
    drop_q: Vec<*mut MBuf>,
}

impl<B: Batch, Tx: PacketTx> SendBatch<B, Tx> {
    pub fn new(source: B, port: Tx) -> Self {
        SendBatch {
            source,
            port,
            transmit_q: Vec::with_capacity(BATCH_SIZE),
            drop_q: Vec::with_capacity(BATCH_SIZE),
        }
    }
}

impl<B: Batch, Tx: PacketTx> Executable for SendBatch<B, Tx> {
    fn execute(&mut self) {
        self.source.receive();

        let transmit_q = &mut self.transmit_q;
        let drop_q = &mut self.drop_q;

        while let Some(item) = self.source.next() {
            match item {
                Ok(packet) => {
                    transmit_q.push(packet.mbuf());
                }
                Err(PacketError::Drop(mbuf)) => {
                    drop_q.push(mbuf);
                }
                Err(PacketError::Abort(mbuf, err)) => {
                    error_chain!(&err);
                    drop_q.push(mbuf);
                }
            }
        }

        if transmit_q.len() > 0 {
            let mut to_send = transmit_q.len();
            while to_send > 0 {
                match self.port.send(transmit_q.as_mut_slice()) {
                    Ok(sent) => {
                        let sent = sent as usize;
                        to_send -= sent;
                        if to_send > 0 {
                            transmit_q.drain(..sent);
                        }
                    }
                    // the underlying DPDK method `rte_eth_tx_burst` will
                    // never return an error. The error arm is unreachable
                    _ => unreachable!(),
                }
            }
            unsafe {
                transmit_q.set_len(0);
            }
        }

        if drop_q.len() > 0 {
            let len = drop_q.len();
            let ptr = drop_q.as_mut_ptr();
            unsafe {
                // never have a non-zero return
                mbuf_free_bulk(ptr, len as i32);
                drop_q.set_len(0);
            }
        }
    }

    #[inline]
    fn dependencies(&mut self) -> Vec<usize> {
        vec![]
    }
}
