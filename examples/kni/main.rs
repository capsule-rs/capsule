use nb2::settings::load_config;
use nb2::{batch, Result, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_port("kni0", |q| {
            batch::splice(q.clone(), q.kni().unwrap().clone())
        })?
        .add_kni_rx_pipeline_to_port("kni0", batch::splice)?
        .execute()
}
