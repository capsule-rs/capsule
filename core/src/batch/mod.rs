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

//! Combinators that can be applied to batches of packets within a pipeline.

mod emit;
mod filter;
mod filter_map;
mod for_each;
mod group_by;
mod inspect;
mod map;
mod poll;
mod replace;
mod rxtx;
mod send;

pub use self::emit::*;
pub use self::filter::*;
pub use self::filter_map::*;
pub use self::for_each::*;
pub use self::group_by::*;
pub use self::inspect::*;
pub use self::map::*;
pub use self::poll::*;
pub use self::replace::*;
pub use self::rxtx::*;
pub use self::send::*;

use crate::packets::Packet;
use crate::Mbuf;
use failure::{Error, Fallible};
use std::collections::HashMap;
use std::hash::Hash;

/// Way to categorize the packets of a batch inside a processing pipeline.
/// The disposition instructs the combinators how to process a packet.
#[allow(missing_debug_implementations)]
pub enum Disposition<T: Packet> {
    /// Indicating the packet should be processed.
    Act(T),

    /// Indicating the packet has already been sent, possibly through a
    /// different [`PacketTx`].
    ///
    /// [`PacketTx`]: crate::batch::PacketTx
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

/// Common behaviors to apply on batches of packets.
pub trait Batch {
    /// The packet type.
    type Item: Packet;

    /// Replenishes the batch with new packets from the source.
    fn replenish(&mut self);

    /// Returns the disposition of the next packet in the batch.
    ///
    /// A value of `None` indicates that the batch is exhausted. To start
    /// the next cycle, call [`replenish`] first.
    ///
    /// [`replenish`]: Batch::replenish
    fn next(&mut self) -> Option<Disposition<Self::Item>>;

    /// Creates a batch that transmits all packets through the specified
    /// [`PacketTx`].
    ///
    /// Use when packets need to be delivered to a destination different
    /// from the pipeline's main outbound queue. The send is immediate and
    /// is not in batch. Packets sent with `emit` will be out of order
    /// relative to other packets in the batch.
    ///
    /// # Example
    ///
    /// ```
    /// let (tx, _) = mpsc::channel();
    /// let mut batch = batch.emit(tx);
    /// ```
    ///
    /// [`PacketTx`]: crate::batch::PacketTx
    fn emit<Tx: PacketTx>(self, tx: Tx) -> Emit<Self, Tx>
    where
        Self: Sized,
    {
        Emit::new(self, tx)
    }

    /// Creates a batch that uses a predicate to determine if a packet
    /// should be processed or dropped. If the predicate evaluates to `false`,
    /// the packet is marked as dropped.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.filter(|packet| {
    ///     let v4 = packet.parse::<Ethernet>()?.parse::<Ipv4>()?;
    ///     v4.ttl() > 0
    /// });
    /// ```
    #[inline]
    fn filter<P>(self, predicate: P) -> Filter<Self, P>
    where
        P: FnMut(&Self::Item) -> bool,
        Self: Sized,
    {
        Filter::new(self, predicate)
    }

    /// Creates a batch that both [`filters`] and [`maps`].
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.filter_map(|packet| {
    ///     let v4 = packet.parse::<Ethernet>()?.parse::<Ipv4>()?;
    ///     if v4.protocol() == ProtocolNumbers::Udp {
    ///         Ok(Either::Keep(v4))
    ///     } else {
    ///         Ok(Either::Drop(v4.reset()))
    ///     }
    /// });
    /// ```
    ///
    /// [`filters`]: Batch::filter
    /// [`maps`]: Batch::map
    #[inline]
    fn filter_map<T: Packet, F>(self, f: F) -> FilterMap<Self, T, F>
    where
        F: FnMut(Self::Item) -> Fallible<Either<T>>,
        Self: Sized,
    {
        FilterMap::new(self, f)
    }

    /// Creates a batch that maps the packets to another packet type.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.map(|packet| {
    ///     packet.parse::<Ethernet>()?.parse::<Ipv4>()
    /// });
    /// ```
    #[inline]
    fn map<T: Packet, F>(self, f: F) -> Map<Self, T, F>
    where
        F: FnMut(Self::Item) -> Fallible<T>,
        Self: Sized,
    {
        Map::new(self, f)
    }

    /// Calls a closure on each packet of the batch.
    ///
    /// Can be use for side-effect actions without the need to mutate the
    /// packet. However, an error will abort the packet.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.for_each(|packet| {
    ///     println!("{:?}", packet);
    ///     Ok(())
    /// });
    /// ````
    #[inline]
    fn for_each<F>(self, f: F) -> ForEach<Self, F>
    where
        F: FnMut(&Self::Item) -> Fallible<()>,
        Self: Sized,
    {
        ForEach::new(self, f)
    }

    /// Calls a closure on each packet of the batch, including ones that are
    /// already dropped, emitted or aborted.
    ///
    /// Unlike [`for_each`], `inspect` does not affect the packet disposition.
    /// Useful as a debugging tool.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.inspect(|disp| {
    ///     if let Disposition::Act(v6) = disp {
    ///         if v6.hop_limit() > A_HOP_LIMIT {
    ///             debug!(...);
    ///         }
    ///     }
    /// });
    /// ```
    ///
    /// [`for_each`]: Batch::for_each
    #[inline]
    fn inspect<F>(self, f: F) -> Inspect<Self, F>
    where
        F: FnMut(&Disposition<Self::Item>),
        Self: Sized,
    {
        Inspect::new(self, f)
    }

    /// Splits the packets into multiple sub batches. Each sub batch runs
    /// through a separate pipeline, and are then merged back together.
    ///
    /// `selector` is a closure that receives a reference to the packet and
    /// evaluates to a discriminator value. The underlying batch will be split
    /// into sub batches based on this value.
    ///
    /// `composer` is a closure that constructs a hash map of batch pipeline
    /// builders for each individual sub pipeline. The [`compose!`] macro is an
    /// ergonomic way to write the composer closure. The syntax of the macro
    /// loosely resembles the std `match` expression. Each match arm consists of
    /// a single discriminator value mapped to a builder closure.
    ///
    /// If a packet does not match with an arm, it will be passed through to
    /// the next combinator. Use the catch all arm `_` to make the matching
    /// exhaustive.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.group_by(
    ///     |packet| packet.protocol(),
    ///     |groups| {
    ///         compose!( groups {
    ///             ProtocolNumbers::Tcp => |group| {
    ///                 group.map(do_tcp)
    ///             }
    ///             ProtocolNumbers::Udp => |group| {
    ///                 group.map(do_udp)
    ///             }
    ///             _ => |group| {
    ///                 group.map(unmatched)
    ///             }
    ///         })
    ///     },
    /// );
    /// ```
    ///
    /// [`compose!`]: macro@compose
    #[inline]
    fn group_by<D, S, C>(self, selector: S, composer: C) -> GroupBy<Self, D, S>
    where
        D: Eq + Clone + Hash,
        S: Fn(&Self::Item) -> D,
        C: FnOnce(&mut HashMap<Option<D>, Box<GroupByBatchBuilder<Self::Item>>>),
        Self: Sized,
    {
        GroupBy::new(self, selector, composer)
    }

    /// A batch that replaces each packet with another packet.
    ///
    /// Use for pipelines that generate new outbound packets based on inbound
    /// packets and drop the inbound.
    ///
    /// # Example
    ///
    /// ```
    /// let mut batch = batch.replace(|request| {
    ///     let reply = Mbuf::new()?;
    ///     let ethernet = request.peek::<Ethernet>()?;
    ///     let mut reply = reply.push::<Ethernet>()?;
    ///     reply.set_src(ethernet.dst());
    ///     reply.set_dst(ethernet.src());
    ///
    ///     ...
    ///
    ///     Ok(reply)
    /// });
    fn replace<T: Packet, F>(self, f: F) -> Replace<Self, T, F>
    where
        F: FnMut(&Self::Item) -> Fallible<T>,
        Self: Sized,
    {
        Replace::new(self, f)
    }

    /// Turns the batch pipeline into an executable task with default name.
    ///
    /// Send marks the end of the batch pipeline. No more combinators can be
    /// appended after send.
    ///
    /// To give the pipeline a unique name, use
    /// [`send_named`] instead.
    ///
    /// # Example
    /// ```
    /// Poll::new(q.clone()).map(map_fn).send(q);
    /// ```
    ///
    /// [`send_named`]: Batch::send_named
    #[inline]
    fn send<Tx: PacketTx>(self, tx: Tx) -> Send<Self, Tx>
    where
        Self: Sized,
    {
        Batch::send_named(self, "default", tx)
    }

    /// Turns the batch pipeline into an executable task.
    ///
    /// `name` is used for logging and metrics. It does not need to be unique.
    /// Multiple pipeline instances with the same name are aggregated together
    /// into one set of metrics. Give each pipeline a different name to keep
    /// metrics separated.
    #[inline]
    fn send_named<Tx: PacketTx>(self, name: &str, tx: Tx) -> Send<Self, Tx>
    where
        Self: Sized,
    {
        Send::new(name.to_owned(), self, tx)
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
    /// Returns the name of the pipeline.
    fn name(&self) -> &str;

    /// Runs the pipeline once to process one batch of packets.
    fn run_once(&mut self);
}

/// Splices a [`PacketRx`] directly to a [`PacketTx`] without any intermediary
/// combinators.
///
/// Useful for pipelines that perform simple forwarding without any packet
/// processing.
///
/// # Example
///
/// ```
/// Runtime::build(config)?
///     .add_pipeline_to_port("kni0", |q| {
///         batch::splice(q.clone(), q.kni().unwrap().clone())
///     });
/// ```
///
/// [`PacketRx`]: crate::batch::PacketRx
/// [`PacketTx`]: crate::batch::PacketTx
pub fn splice<Rx: PacketRx + Unpin, Tx: PacketTx + Unpin>(rx: Rx, tx: Tx) -> impl Pipeline {
    Poll::new(rx).send(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::ip::ProtocolNumbers;
    use crate::packets::Ethernet;
    use crate::testils::byte_arrays::{ICMPV4_PACKET, IPV4_TCP_PACKET, IPV4_UDP_PACKET};
    use std::sync::mpsc::{self, TryRecvError};

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

    #[capsule::test]
    fn emit_batch() {
        let (tx, mut rx) = mpsc::channel();

        let mut batch = new_batch(&[&IPV4_UDP_PACKET])
            .map(|p| p.parse::<Ethernet>())
            .emit(tx)
            .for_each(|_| panic!("emit broken!"));

        assert!(batch.next().unwrap().is_emit());

        // sent to the tx
        assert_eq!(1, rx.receive().len());
    }

    #[capsule::test]
    fn filter_batch() {
        let mut batch = new_batch(&[&IPV4_UDP_PACKET]).filter(|_| true);
        assert!(batch.next().unwrap().is_act());

        let mut batch = new_batch(&[&IPV4_UDP_PACKET]).filter(|_| false);
        assert!(batch.next().unwrap().is_drop());
    }

    #[capsule::test]
    fn filter_map_batch() {
        let mut batch = new_batch(&[&IPV4_UDP_PACKET, &ICMPV4_PACKET]).filter_map(|p| {
            let v4 = p.parse::<Ethernet>()?.parse::<Ipv4>()?;
            if v4.protocol() == ProtocolNumbers::Udp {
                Ok(Either::Keep(v4))
            } else {
                Ok(Either::Drop(v4.reset()))
            }
        });

        // udp is let through
        assert!(batch.next().unwrap().is_act());
        // icmp is dropped
        assert!(batch.next().unwrap().is_drop());
        // at the end
        assert!(batch.next().is_none());
    }

    #[capsule::test]
    fn map_batch() {
        let mut batch = new_batch(&[&IPV4_UDP_PACKET]).map(|p| p.parse::<Ethernet>());
        assert!(batch.next().unwrap().is_act());

        // can't shrink the mbuf that much
        let mut batch = new_batch(&[&IPV4_UDP_PACKET]).map(|mut p| {
            p.shrink(0, 999_999)?;
            Ok(p)
        });
        assert!(batch.next().unwrap().is_abort());
    }

    #[capsule::test]
    fn for_each_batch() {
        let mut side_effect = false;

        let mut batch = new_batch(&[&IPV4_UDP_PACKET]).for_each(|_| {
            side_effect = true;
            Ok(())
        });

        assert!(batch.next().unwrap().is_act());
        assert!(side_effect);
    }

    #[capsule::test]
    fn inspect_batch() {
        let mut side_effect = false;

        let mut batch = new_batch(&[&IPV4_UDP_PACKET]).inspect(|_| {
            side_effect = true;
        });

        assert!(batch.next().unwrap().is_act());
        assert!(side_effect);
    }

    #[capsule::test]
    fn group_by_batch() {
        let mut batch = new_batch(&[&IPV4_TCP_PACKET, &IPV4_UDP_PACKET, &ICMPV4_PACKET])
            .map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
            .group_by(
                |p| p.protocol(),
                |groups| {
                    compose!( groups {
                        ProtocolNumbers::Tcp => |group| {
                            group.map(|mut p| {
                                p.set_ttl(1);
                                Ok(p)
                            })
                        }
                        ProtocolNumbers::Udp => |group| {
                            group.map(|mut p| {
                                p.set_ttl(2);
                                Ok(p)
                            })
                        }
                        _ => |group| {
                            group.filter(|_| {
                                false
                            })
                        }
                    })
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

    #[capsule::test]
    fn group_by_no_catchall() {
        let mut batch = new_batch(&[&ICMPV4_PACKET])
            .map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
            .group_by(
                |p| p.protocol(),
                |groups| {
                    compose!( groups {
                        ProtocolNumbers::Tcp => |group| {
                            group.filter(|_| false)
                        }
                    })
                },
            );

        // did not match, passes through
        assert!(batch.next().unwrap().is_act());
    }

    #[capsule::test]
    fn group_by_or() {
        let mut batch = new_batch(&[&IPV4_TCP_PACKET, &IPV4_UDP_PACKET, &ICMPV4_PACKET])
            .map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
            .group_by(
                |p| p.protocol(),
                |groups| {
                    compose!( groups {
                        ProtocolNumbers::Tcp, ProtocolNumbers::Udp => |group| {
                            group.map(|mut p| {
                                p.set_ttl(1);
                                Ok(p)
                            })
                        }
                        _ => |group| {
                            group.filter(|_| {
                                false
                            })
                        }
                    })
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
            assert_eq!(1, pkt.ttl());
        }

        // last one is the catch all arm
        assert!(batch.next().unwrap().is_drop());
    }

    #[capsule::test]
    fn group_by_or_no_catchall() {
        let mut batch = new_batch(&[&IPV4_TCP_PACKET, &IPV4_UDP_PACKET])
            .map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
            .group_by(
                |p| p.protocol(),
                |groups| {
                    compose!( groups {
                        ProtocolNumbers::Tcp, ProtocolNumbers::Udp => |group| {
                            group.map(|mut p| {
                                p.set_ttl(1);
                                Ok(p)
                            })
                        }
                    })
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
            assert_eq!(1, pkt.ttl());
        }
    }

    #[capsule::test]
    fn group_by_fanout() {
        let mut batch = new_batch(&[&IPV4_TCP_PACKET])
            .map(|p| p.parse::<Ethernet>()?.parse::<Ipv4>())
            .group_by(
                |p| p.protocol(),
                |groups| {
                    compose!( groups {
                        ProtocolNumbers::Tcp => |group| {
                            group.replace(|_| {
                                Mbuf::from_bytes(&IPV4_UDP_PACKET)?
                                    .parse::<Ethernet>()?
                                    .parse::<Ipv4>()
                            })
                        }
                    })
                },
            );

        // replace inside group_by will produce a new UDP packet
        // and marks the original TCP packet as dropped.
        assert!(batch.next().unwrap().is_act());
        assert!(batch.next().unwrap().is_drop());
        assert!(batch.next().is_none());
    }

    #[capsule::test]
    fn replace_batch() {
        let mut batch =
            new_batch(&[&IPV4_UDP_PACKET]).replace(|_| Mbuf::from_bytes(&IPV4_TCP_PACKET));

        // first one is the replacement
        assert!(batch.next().unwrap().is_act());
        // next one is the original
        assert!(batch.next().unwrap().is_drop());
        // at the end
        assert!(batch.next().is_none());
    }

    #[capsule::test]
    fn poll_fn_batch() {
        let mut batch = poll_fn(|| vec![Mbuf::new().unwrap()]);
        batch.replenish();

        assert!(batch.next().unwrap().is_act());
        assert!(batch.next().is_none());
    }

    #[capsule::test]
    fn splice_pipeline() {
        let (mut tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();

        // no packet yet
        let mut pipeline = splice(rx1, tx2);
        pipeline.run_once();
        assert_eq!(TryRecvError::Empty, rx2.try_recv().unwrap_err());

        // send one packet
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        tx1.transmit(vec![packet]);
        pipeline.run_once();
        assert!(rx2.try_recv().is_ok());
    }
}
