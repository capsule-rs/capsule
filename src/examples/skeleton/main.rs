extern crate failure;
extern crate log;
extern crate nb2;
extern crate simplelog;

use log::{debug, info};
use nb2::settings::load_config;
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

    let settings = load_config()?;
    debug!("settings: {:?}", settings);

    let runtime = Runtime::init(settings)?;

    info!("HOORAY!!!");

    let mbuf = Mbuf::new()?;
    debug!("{:?}", mbuf);

    drop(mbuf);
    drop(runtime);

    Ok(())
}
