use crate::dpdk::{eal_cleanup, eal_init, CoreId, Mempool, Port, SocketId, MEMPOOL};
use crate::ffi;
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
        let mut mempool = Mempool::create(65535, 16, socket_id)?;
        info!("created {}.", mempool.name());
        debug!("{:?}", mempool);

        let ptr: *mut ffi::rte_mempool = mempool.raw_mut();
        MEMPOOL.with(|tl| tl.set(ptr));

        let mut mempools = HashMap::new();
        mempools.insert(socket_id, mempool);

        let cores = [CoreId(0)];

        info!("initializing ports...");
        let pci = Port::init("0000:00:08.0".to_owned(), 256, 256, &cores, &mut mempools)?;
        info!("init port {}.", pci.name());
        debug!("{:?}", pci);
        let pcap = Port::init("net_pcap0".to_owned(), 256, 256, &cores, &mut mempools)?;
        info!("init port {}.", pcap.name());
        debug!("{:?}", pcap);

        Ok(Runtime { mempools })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        debug!("freeing EAL.");
        eal_cleanup().unwrap();
    }
}
