use super::{Batch, Disposition};
use crate::packets::Packet;
use std::cell::Cell;
use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;

/// A bridge between the main batch pipeline and the branch pipelines
/// created by the `GroupBy` combinator. Packets can be fed one at a time
/// through the bridge. Because the pipeline execution is depth first,
/// this is the most efficient way storage wise.
#[derive(Clone, Default)]
pub struct Bridge<T: Packet>(Rc<Cell<Option<T>>>);

impl<T: Packet> Bridge<T> {
    pub fn new() -> Self {
        Bridge(Rc::new(Cell::new(None)))
    }

    pub fn set(&self, pkt: T) {
        self.0.set(Some(pkt));
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
pub type GroupByBatchBuilder<T> = dyn Fn(Bridge<T>) -> Box<dyn Batch<Item = T>>;

/// A batch that splits the underlying batch into multiple sub batches.
///
/// A closure is used to extract the discriminator used to determine how to
/// split the packets in the batch. If a packet is unmatched, it will be
/// marked as dropped. On error, the packet is marked as aborted.
///
/// All the sub batches must have the same packet type as the underlying
/// batch.
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
}

impl<B: Batch, D, S> GroupBy<B, D, S>
where
    D: Eq + Clone + Hash,
    S: Fn(&B::Item) -> D,
{
    #[inline]
    pub fn new<C>(batch: B, selector: S, composer: C) -> Self
    where
        C: FnOnce(&mut HashMap<Option<D>, Box<GroupByBatchBuilder<B::Item>>>) -> (),
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
        self.batch.next().map(|disp| {
            disp.map(|pkt| {
                // get the discriminator key
                let key = (self.selector)(&pkt);

                // feed this packet through the bridge
                self.bridge.set(pkt);

                // run the packet through
                match self.groups.get_mut(&key) {
                    Some(group) => group.next().unwrap(),
                    None => self.catchall.next().unwrap(),
                }
            })
        })
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

/// Composes the batch builders for the `group_by` combinator
#[macro_export]
macro_rules! compose {
    ($map:ident { $($key:expr => |$arg:tt| $body:block)* }) => {{
        $crate::__compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|group| Box::new(group)));
    }};
    ($map:ident { $($key:expr => |$arg:tt| $body:block)* _ => |$_arg:tt| $_body:block }) => {{
        $crate::__compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
    ($map:ident { _ => |$_arg:tt| $_body:block }) => {{
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
}
