use nb2::settings::load_config;
use nb2::{Mbuf, Result, Runtime};
use tracing::{debug, info, Level};
use tracing_subscriber::fmt;

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let settings = load_config()?;
    debug!(config = ?settings);

    let runtime = Runtime::init(settings)?;

    info!("HOORAY!!!");

    let mbuf = Mbuf::new()?;
    debug!(?mbuf);

    drop(mbuf);
    drop(runtime);

    Ok(())
}
