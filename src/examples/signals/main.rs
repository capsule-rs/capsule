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

use capsule::settings::load_config;
use capsule::UnixSignal::{self, *};
use capsule::{Result, Runtime};
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
