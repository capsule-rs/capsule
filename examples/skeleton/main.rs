use nb2::config::load_config;
use nb2::{Result, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?.execute()
}
