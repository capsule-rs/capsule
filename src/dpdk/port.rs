use crate::dpdk::rte;
use crate::dpdk::Mempool;
use failure::{format_err, Error};
use std::ffi::{CStr, CString};
use std::os::raw;
use std::ptr;

pub struct PmdPort {
    name: String,
    port_id: u16,
    dev_info: rte::rte_eth_dev_info,
}

impl PmdPort {
    pub fn init(name: &str, pool: &mut Mempool) -> Result<Self, Error> {
        unsafe {
            let mut port_id = 0u16;
            let ret = rte::rte_eth_dev_get_port_by_name(
                CString::from_vec_unchecked(name.into()).as_ptr(),
                &mut port_id,
            );
            if ret < 0 {
                return Err(format_err!("{} device '{}' not found.", ret, name));
            }

            let mut dev_info = rte::rte_eth_dev_info::default();
            rte::rte_eth_dev_info_get(port_id, &mut dev_info);

            let conf = rte::rte_eth_conf::default();
            let ret = rte::rte_eth_dev_configure(port_id, 1, 1, &conf);
            if ret != 0 {
                return Err(format_err!("{} device '{}' not configured.", ret, name));
            }

            let mut rxd_size = 1024;
            let mut txd_size = 1024;
            let ret = rte::rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &mut rxd_size, &mut txd_size);
            if ret != 0 {
                return Err(format_err!("{} device descriptors not adjusted.", ret));
            }

            let socket_id = rte::rte_eth_dev_socket_id(port_id) as raw::c_uint;
            println!("socket id {}", socket_id);

            let ret = rte::rte_eth_rx_queue_setup(
                port_id,
                0,
                rxd_size,
                socket_id,
                ptr::null(),
                pool.as_mut(),
            );
            if ret < 0 {
                return Err(format_err!("{} rx queue not setup.", ret));
            }

            let ret = rte::rte_eth_tx_queue_setup(port_id, 0, txd_size, socket_id, ptr::null());
            if ret < 0 {
                return Err(format_err!("{} tx queue not setup.", ret));
            }

            Ok(PmdPort {
                name: name.to_owned(),
                port_id,
                dev_info,
            })
        }
    }

    pub fn driver_name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.dev_info.driver_name)
                .to_str()
                .unwrap_or("unknown")
        }
    }

    pub fn start(&self) -> Result<(), Error> {
        unsafe {
            let ret = rte::rte_eth_dev_start(self.port_id);
            if ret == 0 {
                Ok(())
            } else {
                Err(format_err!("{} device {} not started.", ret, self.name))
            }
        }
    }

    pub fn stop(&self) {
        unsafe {
            rte::rte_eth_dev_stop(self.port_id);
        }
    }
}
