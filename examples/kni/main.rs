use metrics_core::{Builder, Drain, Observe};
use metrics_runtime::observers::YamlBuilder;
use nb2::metrics;
use nb2::settings::load_config;
use nb2::{batch, Result, Runtime};
use std::time::Duration;
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn print_stats() {
    let mut observer = YamlBuilder::new().build();
    metrics::global().controller().observe(&mut observer);
    println!("{}", observer.drain());
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_port("kni0", |q| {
            batch::splice(q.clone(), q.kni().unwrap().clone())
        })?
        .add_kni_rx_pipeline_to_port("kni0", batch::splice)?
        .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .execute()
}
