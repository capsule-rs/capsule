use proptest::collection::vec;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, TestRunner};

/// Struct for generating `proptest` strategies, e.g. a single packet or vector
/// of packets, as a single value
pub struct StrategyValGen {
    runner: TestRunner,
}

impl StrategyValGen {
    /// Create a new instance of the StrategyValGen with the default RNG.
    pub fn new() -> Self {
        StrategyValGen {
            runner: TestRunner::new(Config::default()),
        }
    }

    /// Create a new instance of the StrategyValGen with a deterministic RNG,
    /// using the same seed across test runs.
    pub fn deterministic() -> Self {
        Self {
            runner: TestRunner::deterministic(),
        }
    }

    /// Generate a value for the strategy.
    ///
    /// # Example
    ///
    /// ```
    /// let mut gen = StrategyValGen::new();
    /// let udp = gen.generate(v4_udp());
    /// ```
    pub fn generate<S: Strategy>(&mut self, strategy: S) -> S::Value {
        strategy
            .new_tree(&mut self.runner)
            .expect("No value can be generated")
            .current()
    }

    /// Generate a vec of some length with a value for the strategy.
    ///
    /// # Example
    ///
    /// ```
    /// let mut gen = StrategyValGen::new();
    /// let udps = gen.generate_vec(v4_udp(), 10);
    /// ```
    pub fn generate_vec<S: Strategy>(&mut self, strategy: &S, len: usize) -> Vec<S::Value> {
        vec(strategy, len..len + 1)
            .new_tree(&mut self.runner)
            .expect("No value can be generated")
            .current()
    }
}
