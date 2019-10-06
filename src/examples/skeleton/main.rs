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

use capsule::{Result, Runtime};
use simplelog::*;

fn main() -> Result<()> {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
    )
    .unwrap()])
    .unwrap();

    let args = [
        "shizzle",
        "--master-lcore",
        "0",
        "-l",
        "0",
        "-w",
        "0000:00:08.0",
        "-m",
        "1024",
        "--log-level=9",
        "-v",
    ];

    let args = args.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
    let _ = Runtime::init(args)?;
    println!("HOORAY!!!");

    // let port = dpdk::PmdPort::init("0000:00:08.0", &mut mempool)?;
    // println!("0000:00:08.0 uses driver '{}'.", port.driver_name());
    // port.start()?;
    // println!("port started.");
    // loop {
    //     let pks = port.receive();
    //     port.send(pks);
    // }
    // port.stop();
    // println!("port stopped.");

    Ok(())
}
