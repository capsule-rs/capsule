use crate::dpdk::{eal_init, CoreId, Mempool, Port, SocketId};
use crate::Result;
use std::collections::HashMap;

pub struct Runtime {
    mempools: HashMap<SocketId, Mempool>,
}

impl Runtime {
    pub fn init(args: Vec<String>) -> Result<Self> {
        eal_init(args)?;

        info!("creating mempools...");
        let socket_id = SocketId::current();
        let mempool = Mempool::create(65535, 16, socket_id)?;
        info!("created '{}'.", mempool.name());
        debug!("{}", mempool);

        let mut mempools = HashMap::new();
        mempools.insert(socket_id, mempool);

        let cores = [CoreId(0)];

        let _ = Port::init(
            "0000:00:08.0".to_owned(),
            256,
            256,
            &cores[..],
            &mut mempools,
        )?;
        let _ = Port::init("net_pcap0".to_owned(), 256, 256, &cores[..], &mut mempools)?;

        Ok(Runtime { mempools })
    }
}
