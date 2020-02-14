#!/usr/bin/env bash

## KNI: https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html

KNI_MOD_PATH=${1:-"/usr/src/extra/dpdk/rte_kni.ko"}

sudo insmod $KNI_MOD_PATH
