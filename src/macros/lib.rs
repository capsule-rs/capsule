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

#![recursion_limit = "128"]

extern crate proc_macro;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Procedural macro for running DPDK based tests.
///
/// Each test will create a new one-use `Mempool` with a maximum capacity
/// of 15. The `Mempool` is not shared with other tests, allowing tests to
/// run in isolation and in parallel.
///
/// # Example
///
/// ```
/// #[cfg(test)]
/// pub mod tests {
///     use super::*;
///
///     #[capsule::test]
///     fn test_drop() {
///         ...
///         assert!(drop);
///     }
/// ```
#[proc_macro_attribute]
pub fn test(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let ret = &input.sig.output;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let body = &input.block;

    let result = quote! {
        #[test]
        fn #name(#inputs) #ret {
            ::capsule::testil::cargo_test_init();
            let mut mempool = ::capsule::dpdk::mempool::Mempool::new(15, 0, ::capsule::dpdk::SocketId::ANY).unwrap();
            ::capsule::dpdk::mempool::MEMPOOL.with(|tls| tls.set(mempool.raw_mut()));

            #body

            ::capsule::dpdk::mempool::MEMPOOL.with(|tls| tls.replace(::std::ptr::null_mut()));
            drop(mempool);
        }
    };

    result.into()
}
