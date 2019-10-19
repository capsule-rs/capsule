use crate::core_map::CoreMapBuilder;
use crate::dpdk::{eal_cleanup, eal_init, CoreId, Port, SocketId};
use crate::mempool_map::MempoolMap;
use crate::Result;

pub struct Runtime {
    mempools: MempoolMap,
}

impl Runtime {
    pub fn init(args: Vec<String>) -> Result<Self> {
        eal_init(args)?;

        info!("creating mempools...");
        let socket_id = SocketId::current();
        let mut mempools = MempoolMap::new(65535, 16, &[socket_id])?;

        let cores = [CoreId::new(0), CoreId::new(1), CoreId::new(2)];

        let map = CoreMapBuilder::new()
            .cores(&cores)
            .master_core(&cores[0])
            .mempools(mempools.borrow_mut())
            .finish()?;

        info!("initializing ports...");
        let pci = Port::init(
            "0000:00:08.0".to_owned(),
            256,
            256,
            &cores[1..2],
            mempools.borrow_mut(),
        )?;
        info!("init port {}.", pci.name());
        debug!("{:?}", pci);
        let pcap = Port::init(
            "net_pcap0".to_owned(),
            256,
            256,
            &cores[2..3],
            mempools.borrow_mut(),
        )?;
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
