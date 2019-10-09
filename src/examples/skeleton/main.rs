extern crate failure;
extern crate log;
extern crate nb2;
extern crate simplelog;

use log::{debug, info};
use nb2::{Mbuf, Result, Runtime};
use simplelog::*;

fn main() -> Result<()> {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
    )
    .unwrap()])
    .unwrap();

    let args = [
        "shizzle",
        "--master-lcore",
        "0",
        "-l",
        "0",
        "-w",
        "0000:00:08.0",
        "--vdev",
        "net_pcap0,rx_iface=lo,tx_pcap=tx.pcap",
        "-v",
    ];

    let args = args.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
    let runtime = Runtime::init(args)?;

    info!("HOORAY!!!");

    let mbuf = Mbuf::new()?;
    debug!("{}", mbuf);

    drop(mbuf);
    drop(runtime);

    Ok(())
}
