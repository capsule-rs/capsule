use crate::dpdk::{eal_init, Mempool, SocketId};
use crate::Result;
use log::{debug, info};
use std::collections::HashMap;

pub struct Runtime {
    mempools: HashMap<SocketId, Mempool>,
}

impl Runtime {
    pub fn init(args: Vec<String>) -> Result<Self> {
        eal_init(args)?;

        info!("creating mempools...");
        let socket_id = SocketId::current();
        let mempool = Mempool::create(1023, 16, socket_id)?;
        info!("created '{}'.", mempool.name());
        debug!("{}", mempool);

        let mut mempools = HashMap::new();
        mempools.insert(socket_id, mempool);

        Ok(Runtime { mempools })
    }
}
