#![recursion_limit = "128"]

mod derive_packet;

use darling::FromMeta;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self, parse_macro_input};

// Custom derive macro for SizeOf trait.
#[proc_macro_derive(SizeOf)]
pub fn derive_size_of(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics SizeOf for #name #ty_generics #where_clause {
            fn size_of() -> usize {
                std::mem::size_of::<Self>()
            }
        }
    };

    expanded.into()
}

// Custom-derive macro implementation for `Icmpv4Packet`
#[proc_macro_derive(Icmpv4Packet)]
pub fn derive_icmpv6_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_packet::gen_icmpv4(input)
}

// Custom-derive macro implementation for `Icmpv6Packet`
#[proc_macro_derive(Icmpv6Packet)]
pub fn derive_icmpv4_packet(input: TokenStream) -> TokenStream {
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
///     #[nb2::test]
///     fn test_drop() {
///         ...
///         assert!(drop);
///     }
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
            ::nb2::testils::cargo_test_init();
            let _guard = ::nb2::testils::new_mempool(#mempool_capacity, #mempool_cache_size);

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
/// #[nb2::bench(mempool_capcity = 30)]
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
            ::nb2::testils::cargo_test_init();
            let _guard = ::nb2::testils::new_mempool(#mempool_capacity, #mempool_cache_size);

            #body
        }
    };

    result.into()
}
