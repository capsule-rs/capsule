extern crate failure;

mod dpdk;

use failure::Error;

fn main() -> Result<(), Error> {
    let args = [
        "shizzle",
        "--log-level=9",
        "-l",
        "0-3",
        "--proc-type",
        "primary",
        "-v",
    ];
    dpdk::eal_init(&args)?;
    let nb_ports = dpdk::eth_dev_count_avail();
    println!("HOORAY!!! {} ports available.", nb_ports);
    Ok(())
}
