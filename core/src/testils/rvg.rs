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

use proptest::collection::vec;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, TestRunner};

/// A random value generator (RVG), which, given proptest strategies, will
/// generate random values based on those strategies.
#[derive(Debug, Default)]
pub struct Rvg {
    runner: TestRunner,
}

impl Rvg {
    /// Creates a new RVG with the default random number generator.
    pub fn new() -> Self {
        Rvg {
            runner: TestRunner::new(Config::default()),
        }
    }

    /// Creates a new RVG with a deterministic random number generator,
    /// using the same seed across test runs.
    pub fn deterministic() -> Self {
        Rvg {
            runner: TestRunner::deterministic(),
        }
    }

    /// Generates a value for the strategy.
    ///
    /// # Example
    ///
    /// ```
    /// let mut gen = Rvg::new();
    /// let udp = gen.generate(v4_udp());
    /// ```
    pub fn generate<S: Strategy>(&mut self, strategy: &S) -> S::Value {
        strategy
            .new_tree(&mut self.runner)
            .expect("No value can be generated")
            .current()
    }

    /// Generates a vec of some length with a value for the strategy.
    ///
    /// # Example
    ///
    /// ```
    /// let mut gen = Rvg::new();
    /// let udps = gen.generate_vec(v4_udp(), 10);
    /// ```
    pub fn generate_vec<S: Strategy>(&mut self, strategy: &S, len: usize) -> Vec<S::Value> {
        vec(strategy, len..=len)
            .new_tree(&mut self.runner)
            .expect("No value can be generated")
            .current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fieldmap;
    use crate::packets::ip::ProtocolNumbers;
    use crate::testils::packet::PacketExt;
    use crate::testils::proptest::*;
    use std::net::Ipv6Addr;

    #[capsule::test]
    fn gen_v4_packet() {
        let mut gen = Rvg::new();
        let packet = gen.generate(&v4_udp());
        let v4 = packet.into_v4();
        assert_eq!(ProtocolNumbers::Udp, v4.protocol());
    }

    #[capsule::test]
    fn gen_sr_packets() {
        let mut gen = Rvg::new();
        let srhs = gen.generate_vec(&sr_tcp().prop_map(|v| v.into_sr_tcp()), 10);
        assert_eq!(10, srhs.len());
    }

    #[capsule::test]
    fn gen_sr_packets_with_fieldmap() {
        let mut gen = Rvg::new();

        let segments = vec![
            "::2".parse::<Ipv6Addr>().unwrap(),
            "::3".parse::<Ipv6Addr>().unwrap(),
            "::4".parse::<Ipv6Addr>().unwrap(),
        ];
        let srhs = gen.generate_vec(
            &sr_tcp_with(fieldmap! {field::sr_segments => segments}).prop_map(|v| v.into_sr()),
            10,
        );
        assert_eq!(10, srhs.len());
        let _ = srhs.iter().map(|srh| assert_eq!(3, srh.segments().len()));
    }
}
