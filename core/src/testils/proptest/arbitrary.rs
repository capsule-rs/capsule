//! Implementations of `proptest.arbitrary.Arbitrary` trait for
//! various types.

use crate::dpdk::Mbuf;
use crate::net::MacAddr;
use proptest::arbitrary::{any, Arbitrary, StrategyFor};
use proptest::collection::vec;
use proptest::strategy::{BoxedStrategy, MapInto, Strategy};
use proptest::{num, prop_compose};

const MIN_MBUF: u32 = 20;
const MAX_MBUF: u32 = 100;

prop_compose! {
    fn new_mbuf_strategy(min: u32, max: u32)
        (num_bytes in min.. max)
        (bytes in (vec(num::u8::ANY, num_bytes as usize)))-> Mbuf {
            Mbuf::from_bytes(&bytes).unwrap()
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
        new_mbuf_strategy(MIN_MBUF, MAX_MBUF).boxed()
    }
}
