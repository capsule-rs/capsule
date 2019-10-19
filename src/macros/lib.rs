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
///     #[nb2::test]
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
            ::nb2::testil::cargo_test_init();
            let mut mempool = ::nb2::dpdk::mempool::Mempool::new(15, 0, ::nb2::dpdk::SocketId::ANY).unwrap();
            ::nb2::dpdk::mempool::MEMPOOL.with(|tls| tls.set(mempool.raw_mut()));

            #body

            ::nb2::dpdk::mempool::MEMPOOL.with(|tls| tls.replace(::std::ptr::null_mut()));
            drop(mempool);
        }
    };

    result.into()
}
