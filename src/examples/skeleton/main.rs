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

extern crate capsule;
extern crate failure;
extern crate simplelog;

use capsule::settings::load_config;
use capsule::{Mbuf, Result, Runtime};
use log::{debug, info};
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
