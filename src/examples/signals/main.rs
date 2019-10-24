use nb2::settings::load_config;
use nb2::UnixSignal::{self, *};
use nb2::{Result, Runtime};
use tracing::{info, Level};
use tracing_subscriber::fmt;

fn on_signal(signal: UnixSignal) -> bool {
    info!(?signal);
    match signal {
        SIGHUP => false,
        SIGINT | SIGTERM => true,
    }
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    let mut runtime = Runtime::build(config)?;
    runtime.set_on_signal(on_signal);

    println!("Ctrl-C to stop...");
    runtime.execute()
}
