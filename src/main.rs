extern crate failure;

mod dpdk;

use failure::Error;

fn main() -> Result<(), Error> {
    let args = [
        "shizzle",
        "--log-level=9",
        "-l",
        "0",
        "-w",
        "0000:00:08.0",
        "-v",
    ];
    dpdk::eal_init(&args)?;
    println!("HOORAY!!!");
    let mut mempool = dpdk::Mempool::create("dump", 8191, 0)?;
    println!("mempool '{}' created.", mempool.name());
    let port = dpdk::PmdPort::init("0000:00:08.0", &mut mempool)?;
    println!("0000:00:08.0 uses driver '{}'.", port.driver_name());
    port.start()?;
    println!("port started.");
    port.stop();
    println!("port stopped.");
    Ok(())
}
