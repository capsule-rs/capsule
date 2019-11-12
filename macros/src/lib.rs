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

use darling::FromMeta;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, ItemFn};

// Handle arguments to our macros or default otherwise
#[derive(Debug, FromMeta)]
#[darling(default)]
struct AttrArgs {
    mempool_capacity: usize,
    mempool_cache_size: usize,
}

impl Default for AttrArgs {
    fn default() -> Self {
        AttrArgs {
            mempool_capacity: 15,
            mempool_cache_size: 0,
        }
    }
}

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
pub fn test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let ret = &input.sig.output;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let body = &input.block;

    let attr_args = parse_macro_input!(args as AttributeArgs);

    let AttrArgs {
        mempool_capacity,
        mempool_cache_size,
    } = match AttrArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => {
            return e.write_errors().into();
        }
    };

    let result = quote! {
        #[test]
        fn #name(#inputs) #ret {
            ::capsule::testils::cargo_test_init();
            let _guard = ::capsule::testils::new_mempool(#mempool_capacity, #mempool_cache_size);

            #body
        }
    };

    result.into()
}

/// Procedural macro for running DPDK based benches.
///
/// Each bench loop will create a new one-use `Mempool` with a maximum capacity
/// of 15. The `Mempool` is not shared with other bench runs, allowing benches to
/// run in isolation and in parallel.
///
/// # Example
///
/// ```
/// #[capsule::bench(mempool_capcity = 30)]
/// fn run_benchmark(c: &mut Criterion) {
///     c.bench_function("bench:run_benchmark", |b| {
///         b.iter(|| bench_thing());
///     });
/// }
/// ```
#[proc_macro_attribute]
pub fn bench(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let ret = &input.sig.output;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let body = &input.block;

    let attr_args = parse_macro_input!(args as AttributeArgs);

    let AttrArgs {
        mempool_capacity,
        mempool_cache_size,
    } = match AttrArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => {
            return e.write_errors().into();
        }
    };

    let result = quote! {
        fn #name(#inputs) #ret {
            ::capsule::testils::cargo_test_init();
            let _guard = ::capsule::testils::new_mempool(#mempool_capacity, #mempool_cache_size);

            #body
        }
    };

    result.into()
}
