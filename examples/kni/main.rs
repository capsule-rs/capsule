/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use capsule::config::load_config;
use capsule::metrics;
use capsule::{batch, Runtime};
use failure::Fallible;
use metrics_core::{Builder, Drain, Observe};
use metrics_runtime::observers::YamlBuilder;
use std::time::Duration;
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn print_stats() {
    let mut observer = YamlBuilder::new().build();
    metrics::global().controller().observe(&mut observer);
    println!("{}", observer.drain());
}

fn main() -> Fallible<()> {
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
