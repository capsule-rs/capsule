extern crate failure;
extern crate log;
extern crate nb2;
extern crate simplelog;

use log::info;
use nb2::{Result, Runtime};
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
        "net_pcap0,tx_pcap=tx.pcap",
        "-v",
    ];

    let args = args.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
    let _ = Runtime::init(args)?;

    info!("HOORAY!!!");

    // let port = dpdk::PmdPort::init("0000:00:08.0", &mut mempool)?;
    // println!("0000:00:08.0 uses driver '{}'.", port.driver_name());
    // port.start()?;
    // println!("port started.");
    // loop {
    //     let pks = port.receive();
    //     port.send(pks);
    // }
    // port.stop();
    // println!("port stopped.");

    Ok(())
}
