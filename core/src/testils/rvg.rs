use proptest::collection::vec;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, TestRunner};

/// Random value generator (RNG), which, given proptest strategies, will to
/// generate random values based on those strategies.
#[derive(Default)]
pub struct Rvg {
    runner: TestRunner,
}

impl Rvg {
    /// Create a new instance of the RVG with the default RNG.
    pub fn new() -> Self {
        Rvg {
            runner: TestRunner::new(Config::default()),
        }
    }

    /// Create a new instance of the RVG with a deterministic RNG,
    /// using the same seed across test runs.
    pub fn deterministic() -> Self {
        Rvg {
            runner: TestRunner::deterministic(),
        }
    }

    /// Generate a value for the strategy.
    ///
    /// # Example
    ///
    /// ```
    /// let mut gen = Rvg::new();
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
