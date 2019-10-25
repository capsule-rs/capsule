//! Implementations of `PacketRx` and `PacketTx`.
//!
//! Implemented for `PortQueue`.
//!
//! Implemented for `VecDeque` so it can be used as the batch source mostly
//! in tests.

use super::{PacketRx, PacketTx};
use crate::{Mbuf, PortQueue};
use std::collections::VecDeque;

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

impl PacketRx for VecDeque<Mbuf> {
    fn receive(&mut self) -> Vec<Mbuf> {
        self.drain(..).collect()
    }
}

impl PacketTx for VecDeque<Mbuf> {
    fn transmit(&mut self, packets: Vec<Mbuf>) {
        self.extend(packets)
    }
}
