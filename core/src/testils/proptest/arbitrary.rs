//! Implementations of `proptest.arbitrary.Arbitrary` trait for
//! various types.

use crate::dpdk::Mbuf;
use crate::net::MacAddr;
use proptest::arbitrary::{any, Arbitrary, StrategyFor};
use proptest::prop_compose;
use proptest::strategy::{BoxedStrategy, LazyJust, MapInto, Strategy};

prop_compose! {
    fn new_mbuf_strategy()
        (mbuf in LazyJust::new(|| Mbuf::new().unwrap()))-> Mbuf {
            mbuf
    }
}

impl Arbitrary for MacAddr {
    type Parameters = ();
    type Strategy = MapInto<StrategyFor<[u8; 6]>, Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<[u8; 6]>().prop_map_into()
    }
}

impl Arbitrary for Mbuf {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        new_mbuf_strategy().boxed()
    }
}
