//! Implementations of `PacketRx` and `PacketTx`.
//!
//! Implemented for VecDeque so it can be used as a packet RX or TX
//! in tests.

use super::{PacketRx, PacketTx};
use crate::Mbuf;
use std::collections::VecDeque;

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
