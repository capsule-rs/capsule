use nb2::settings::load_config;
use nb2::{Result, Runtime, UnixSignal};
use tracing::{info, Level};
use tracing_subscriber::fmt;

fn on_signal(signal: UnixSignal) -> bool {
    match signal {
        UnixSignal::SIGHUP => {
            info!("SIGHUP");
            false
        }
        UnixSignal::SIGINT | UnixSignal::SIGTERM => {
            info!("SIGINT");
            true
        }
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
