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

#![cfg(test)]

use crate::dpdk::eal_init;
use std::sync::Once;

static TEST_INIT: Once = Once::new();

/// Run once handle to initialize EAL for `cargo test`
pub fn cargo_test_init() {
    TEST_INIT.call_once(|| {
        eal_init(vec!["dpdk_test".to_owned()]).unwrap();
    });
}
