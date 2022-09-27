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

//! Procedural macros for [`Capsule`].
//!
//! [`Capsule`]: https://crates.io/crates/capsule

#![recursion_limit = "128"]
#![allow(broken_intra_doc_links)]

mod derive_packet;

use darling::FromMeta;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self, parse_macro_input};

/// Derive macro for [`SizeOf`].
///
/// [`SizeOf`]: crate::SizeOf
#[proc_macro_derive(SizeOf)]
pub fn derive_size_of(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics ::capsule::packets::SizeOf for #name #ty_generics #where_clause {
            fn size_of() -> usize {
                std::mem::size_of::<Self>()
            }
        }
    };

    expanded.into()
}

/// Derive macro for [`Icmpv4Packet`].
///
/// Also derives the associated [`Packet`] implementation.
///
/// [`Packet`]: crate::packets::Packet
/// [`Icmpv4Packet`]: crate::packets::icmp::v4::Icmpv4Packet
#[proc_macro_derive(Icmpv4Packet)]
pub fn derive_icmpv4_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_packet::gen_icmpv4(input)
}

/// Derive macro for [`Icmpv6Packet`].
///
/// Also derives the associated [`Packet`] implementation.
///
/// [`Packet`]: crate::packets::Packet
/// [`Icmpv6Packet`]: crate::packets::icmp::v6::Icmpv6Packet
#[proc_macro_derive(Icmpv6Packet)]
pub fn derive_icmpv6_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_packet::gen_icmpv6(input)
}

// Arguments and defaults to our test/bench macros
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
/// }
/// ```
#[proc_macro_attribute]
pub fn test(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);

    let ret = &input.sig.output;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let body = &input.block;

    let attr_args = parse_macro_input!(args as syn::AttributeArgs);

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
    let input = parse_macro_input!(input as syn::ItemFn);

    let ret = &input.sig.output;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let body = &input.block;

    let attr_args = parse_macro_input!(args as syn::AttributeArgs);

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
