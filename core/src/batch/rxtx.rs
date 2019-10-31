//! Implementations of `PacketRx` and `PacketTx`.
//!
//! Implemented for `PortQueue`.
//! 
//! `PacketRx` implemented for `KniRx`.
//!
//! `PacketTx` implemented for `KniTxQueue`.
//!
//! Implemented for the MPSC channel so it can be used as a batch source
//! mostly in tests.

use super::{PacketRx, PacketTx};
use crate::{KniRx, KniTxQueue, Mbuf, PortQueue};
use std::iter;
use std::sync::mpsc::{Receiver, Sender};

impl PacketRx for PortQueue {
    fn receive(&mut self) -> Vec<Mbuf> {
        PortQueue::receive(self)
    }
}

impl PacketTx for PortQueue {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        PortQueue::transmit(self, packets)
    }
}

impl PacketRx for KniRx {
    fn receive(&mut self) -> Vec<Mbuf> {
        KniRx::receive(self)
    }
}

impl PacketTx for KniTxQueue {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        KniTxQueue::transmit(self, packets)
    }
}

impl PacketRx for Receiver<Mbuf> {
    fn receive(&mut self) -> Vec<Mbuf> {
        iter::from_fn(|| self.try_recv().ok()).collect::<Vec<_>>()
    }
}

impl PacketTx for Sender<Mbuf> {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        packets.into_iter().for_each(|packet| {
            let _ = self.send(packet);
        });
    }
}

pub struct PollRx<F>
where
    F: Fn() -> Vec<Mbuf>,
{
    pub(crate) f: F,
}

impl<F> PacketRx for PollRx<F>
where
    F: Fn() -> Vec<Mbuf>,
{
    fn receive(&mut self) -> Vec<Mbuf> {
        (self.f)()
    }
}
