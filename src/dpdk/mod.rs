mod mbuf;
mod mempool;
mod port;
mod rte;

pub use mbuf::*;
pub use mempool::*;
pub use port::*;

use failure::{format_err, Error};
use std::ffi::CString;
use std::os::raw;

pub fn eal_init(args: &[&str]) -> Result<(), Error> {
    unsafe {
        let len = args.len() as raw::c_int;
        let mut args = args
            .iter()
            .map(|&s| CString::from_vec_unchecked(s.into()).into_raw())
            .collect::<Vec<*mut raw::c_char>>();

        if rte::rte_eal_init(len, args.as_mut_ptr()) >= 0 {
            Ok(())
        } else {
            Err(format_err!("Cannot init EAL."))
        }
    }
}
