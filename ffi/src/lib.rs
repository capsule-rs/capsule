#![allow(clippy::all)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![cfg(target_os = "linux")]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
