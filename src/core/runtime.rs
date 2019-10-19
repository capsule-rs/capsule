use crate::core_map::CoreMapBuilder;
use crate::dpdk::{eal_cleanup, eal_init, CoreId, Port, PortBuilder, SocketId};
use crate::mempool_map::MempoolMap;
use crate::Result;

pub struct Runtime {
    ports: Vec<Port>,
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

        let pci = PortBuilder::new("0000:00:08.0".to_owned())?
            .cores(&cores[1..2])?
            .mempools(mempools.borrow_mut())
            .rx_tx_queue_capacity(256, 256)?
            .finish()?;
        debug!("{:?}", pci);

        let pcap = PortBuilder::new("net_pcap0".to_owned())?
            .cores(&cores[2..3])?
            .mempools(mempools.borrow_mut())
            .rx_tx_queue_capacity(256, 256)?
            .finish()?;
        debug!("{:?}", pcap);

        Ok(Runtime {
            ports: vec![pci, pcap],
            mempools,
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        debug!("freeing EAL.");
        eal_cleanup().unwrap();
    }
}
