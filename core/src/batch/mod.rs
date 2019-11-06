mod emit;
mod filter;
mod filter_map;
mod for_each;
mod group_by;
mod map;
mod poll;
mod rxtx;
mod send;

pub use self::emit::*;
pub use self::filter::*;
pub use self::filter_map::*;
pub use self::for_each::*;
pub use self::group_by::*;
pub use self::map::*;
pub use self::poll::*;
pub use self::rxtx::*;
pub use self::send::*;

use crate::packets::Packet;
use crate::{Mbuf, Result};
use failure::Error;
use std::collections::HashMap;
use std::hash::Hash;

/// Way to categorize the packets of a batch inside a processing pipeline.
/// The disposition instructs the combinators how to process a packet.
pub enum Disposition<T: Packet> {
    /// Indicating the packet should be processed.
    Act(T),

    /// Indicating the packet has already been sent, possibly through a
    /// different `PacketTx`.
    Emit,

    /// Indicating the packet is intentionally dropped from the output.
    Drop(Mbuf),

    /// Indicating an error has occurred during processing. The packet will
    /// be dropped from the output. Aborted packets are not bulk freed.
    /// The packet is returned to mempool when it goes out of scope.
    Abort(Error),
}

impl<T: Packet> Disposition<T> {
    /// Easy way to map a `Disposition<T>` to a `Disposition<U>` by reducing
    /// it down to a map from `T` to `Disposition<U>`.
    fn map<U: Packet, F>(self, f: F) -> Disposition<U>
    where
        F: FnOnce(T) -> Disposition<U>,
    {
        match self {
            Disposition::Act(packet) => f(packet),
            Disposition::Emit => Disposition::Emit,
            Disposition::Drop(mbuf) => Disposition::Drop(mbuf),
            Disposition::Abort(err) => Disposition::Abort(err),
        }
    }

    /// Returns whether the disposition is `Act`.
    pub fn is_act(&self) -> bool {
        match self {
            Disposition::Act(_) => true,
            _ => false,
        }
    }

    /// Returns whether the disposition is `Emit`.
    pub fn is_emit(&self) -> bool {
        match self {
            Disposition::Emit => true,
            _ => false,
        }
    }

    /// Returns whether the disposition is `Drop`.
    pub fn is_drop(&self) -> bool {
        match self {
            Disposition::Drop(_) => true,
            _ => false,
        }
    }

    /// Returns whether the disposition is `Abort`.
    pub fn is_abort(&self) -> bool {
        match self {
            Disposition::Abort(_) => true,
            _ => false,
        }
    }
}

/// Types that can receive packets.
pub trait PacketRx {
    /// Receives a batch of packets.
    fn receive(&mut self) -> Vec<Mbuf>;
}

/// Types that can trasmit packets.
pub trait PacketTx {
    /// Transmits a batch of packets.
    fn transmit(&mut self, packets: Vec<Mbuf>);
}

/// Batch of packets.
pub trait Batch {
    /// The packet type.
    type Item: Packet;

    /// Replenishes the batch with new packets from the source.
    fn replenish(&mut self);

    /// Returns the disposition of the next packet in the batch.
    ///
    /// A value of `None` indicates that the batch is exhausted. To start
    /// the next cycle, call `replenish` first.
    fn next(&mut self) -> Option<Disposition<Self::Item>>;

    /// Creates a batch that transmits all packets through the specified
    /// `PacketTx`.
    ///
    /// Use when packets need to be delivered to a destination different
    /// from the pipeline's main outbound queue. The send is immediate and
    /// is not in batch. Packets sent with `emit` will be out of order
    /// relative to other packets in the batch.
    fn emit<Tx: PacketTx>(self, tx: Tx) -> Emit<Self, Tx>
    where
        Self: Sized,
    {
        Emit::new(self, tx)
    }

    /// Creates a batch that uses a predicate to determine if a packet
    /// should be processed or dropped.
    #[inline]
    fn filter<P>(self, predicate: P) -> Filter<Self, P>
    where
        P: FnMut(&Self::Item) -> bool,
        Self: Sized,
    {
        Filter::new(self, predicate)
    }

    /// Creates a batch that both filters and maps.
    #[inline]
    fn filter_map<T: Packet, F>(self, f: F) -> FilterMap<Self, T, F>
    where
        F: FnMut(Self::Item) -> Result<Outcome<T>>,
        Self: Sized,
    {
        FilterMap::new(self, f)
    }

    /// Creates a batch that maps the packets to a new type.
    #[inline]
    fn map<T: Packet, F>(self, f: F) -> Map<Self, T, F>
    where
        F: FnMut(Self::Item) -> Result<T>,
        Self: Sized,
    {
        Map::new(self, f)
    }

    /// Calls a closure on each packet of the batch.
    ///
    /// Can be use for side-effect actions without the need to mutate the
    /// packet.
    #[inline]
    fn for_each<F>(self, f: F) -> ForEach<Self, F>
    where
        F: FnMut(&Self::Item) -> Result<()>,
        Self: Sized,
    {
        ForEach::new(self, f)
    }

    /// Splits the batch into multiple sub batches.
    ///
    /// `selector` is a closure that receives a reference to the packet and
    /// evaluates to a discriminator value. The underlying batch will be split
    /// into sub batches based on this value.
    ///
    /// `composer` is a closure that constructs a hash map of batch pipeline
    /// builders for each individual sub batch. The `compose` macro is an
    /// ergonomic way to write the composer closure.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.group_by(
    ///     |packet| packet.protocol(),
    ///     |groups| {
    ///         compose!(
    ///             groups,
    ///             ProtocolNumbers::Tcp => |group| {
    ///                 group.map(do_tcp)
    ///             },
    ///             ProtocolNumbers::Udp => |group| {
    ///                 group.map(do_udp)
    ///             }
    ///         )
    ///     }
    /// );
    /// ```
    #[inline]
    fn group_by<D, S, C>(self, selector: S, composer: C) -> GroupBy<Self, D, S>
    where
        D: Eq + Clone + Hash,
        S: Fn(&Self::Item) -> D,
        C: FnOnce(&mut HashMap<Option<D>, Box<PipelineBuilder<Self::Item>>>) -> (),
        Self: Sized,
    {
        GroupBy::new(self, selector, composer)
    }

    /// Turns the batch pipeline into an executable task.
    ///
    /// Send marks the end of the batch pipeline. No more combinators can be
    /// appended after send.
    #[inline]
    fn send<Tx: PacketTx>(self, tx: Tx) -> Send<Self, Tx>
    where
        Self: Sized,
    {
        Send::new(self, tx)
    }
}

/// Trait bound for batch pipelines. Can be used as a convenience for writing
/// pipeline installers.
///
/// # Example
///
/// ```
/// fn install(q: PortQueue) -> impl Pipeline {
///     // install logic
/// }
/// ```
pub trait Pipeline: futures::Future<Output = ()> {
    /// Runs the pipeline once to process one batch of packets.
    fn run_once(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::ip::ProtocolNumbers;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{ICMPV4_PACKET, TCP_PACKET, UDP_PACKET};
    use std::sync::mpsc;

    fn new_batch(data: &[&[u8]]) -> impl Batch<Item = Mbuf> {
        let packets = data
            .iter()
            .map(|bytes| Mbuf::from_bytes(bytes).unwrap())
            .collect::<Vec<_>>();

        let (mut tx, rx) = mpsc::channel();
        tx.transmit(packets);
        let mut batch = Poll::new(rx);
        batch.replenish();
        batch
    }

    #[nb2::test]
    fn emit_batch() {
        let (tx, mut rx) = mpsc::channel();

        let mut batch = new_batch(&[&UDP_PACKET])
            .map(|p| p.parse::<Ethernet>())
            .emit(tx)
            .for_each(|_| panic!("emit broken!"));

        assert!(batch.next().unwrap().is_emit());

        // sent to the tx
        assert_eq!(1, rx.receive().len());
    }

    #[nb2::test]
    fn filter_batch() {
        let mut batch = new_batch(&[&UDP_PACKET]).filter(|_| true);
        assert!(batch.next().unwrap().is_act());

        let mut batch = new_batch(&[&UDP_PACKET]).filter(|_| false);
        assert!(batch.next().unwrap().is_drop());
    }

    #[nb2::test]
    fn filter_map_batch() {
        let mut batch = new_batch(&[&UDP_PACKET, &ICMPV4_PACKET]).filter_map(|p| {
            let v4 = p.parse::<Ethernet>()?.parse::<Ipv4>()?;
            if v4.protocol() == ProtocolNumbers::Udp {
                Ok(Outcome::Keep(v4))
            } else {
                Ok(Outcome::Drop(v4.reset()))
            }
        });

        // udp is let through
        assert!(batch.next().unwrap().is_act());
        // icmp is dropped
        assert!(batch.next().unwrap().is_drop());
        // at the end
        assert!(batch.next().is_none());
    }

    #[nb2::test]
    fn map_batch() {
        let mut batch = new_batch(&[&UDP_PACKET]).map(|p| p.parse::<Ethernet>());
        assert!(batch.next().unwrap().is_act());

        // can't shrink the mbuf that much
        let mut batch = new_batch(&[&UDP_PACKET]).map(|mut p| {
            p.shrink(0, 999_999)?;
            Ok(p)
        });
        assert!(batch.next().unwrap().is_abort());
    }

    #[nb2::test]
    fn for_each_batch() {
        let mut side_effect = false;

        let mut batch = new_batch(&[&UDP_PACKET]).for_each(|_| {
            side_effect = true;
            Ok(())
        });

        assert!(batch.next().unwrap().is_act());
        assert!(side_effect);
    }

    #[nb2::test]
    fn group_by_batch() {
        let mut batch = new_batch(&[&TCP_PACKET, &UDP_PACKET, &ICMPV4_PACKET])
            .map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
            .group_by(
                |p| p.protocol(),
                |groups| {
                    compose!(
                        groups,
                        ProtocolNumbers::Tcp => |group| {
                            group.map(|mut p| {
                                p.set_ttl(1);
                                Ok(p)
                            })
                        },
                        ProtocolNumbers::Udp => |group| {
                            group.map(|mut p| {
                                p.set_ttl(2);
                                Ok(p)
                            })
                        },
                        _ => |group| {
                            group.filter(|_| {
                                false
                            })
                        }
                    );
                },
            );

        // first one is the tcp arm
        let disp = batch.next().unwrap();
        assert!(disp.is_act());
        if let Disposition::Act(pkt) = disp {
            assert_eq!(1, pkt.ttl());
        }

        // next one is the udp arm
        let disp = batch.next().unwrap();
        assert!(disp.is_act());
        if let Disposition::Act(pkt) = disp {
            assert_eq!(2, pkt.ttl());
        }

        // last one is the catch all arm
        assert!(batch.next().unwrap().is_drop());
    }
}
