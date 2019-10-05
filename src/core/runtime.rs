use crate::dpdk::eal_init;
use crate::Result;

pub struct Runtime {}

impl Runtime {
    pub fn init(args: Vec<String>) -> Result<Self> {
        eal_init(args)?;
        Ok(Runtime {})
    }
}
