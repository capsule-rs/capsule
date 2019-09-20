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

extern crate failure;

mod dpdk;

use failure::Error;

fn main() -> Result<(), Error> {
    let args = [
        "shizzle",
        "--log-level=9",
        "-l",
        "0-3",
        "--proc-type",
        "primary",
        "-v",
    ];
    dpdk::eal_init(&args)?;
    let nb_ports = dpdk::eth_dev_count_avail();
    println!("HOORAY!!! {} ports available.", nb_ports);
    Ok(())
}
