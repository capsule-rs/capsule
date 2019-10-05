extern crate failure;
extern crate nb2;

use nb2::{Result, Runtime};

fn main() -> Result<()> {
    let args = [
        "shizzle",
        "--log-level=9",
        "-l",
        "0",
        "-w",
        "0000:00:08.0",
        "-v",
    ];

    let args = args.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
    let runtime = Runtime::init(args)?;
    println!("HOORAY!!!");

    // let mut mempool = dpdk::Mempool::create("dump", 257, 0)?;
    // println!("mempool '{}' created.", mempool.name());
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
