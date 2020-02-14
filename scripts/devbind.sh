#!/usr/bin/env bash

## If not using `uio_pci_generic`, `modprobe` kernel module for driver of your
## choice before devbind'ing.
## More info: .
DPDK_DRIVER=${1:-"uio_pci_generic"}

## More info: https://doc.dpdk.org/guides/tools/devbind.html
if [ -z ${DPDK_DEVICES+x} ]; then
    echo "DPDK_DEVICES is unset and is necessary for running dpdk-devbind."
    exit 1
fi

sudo dpdk-devbind.py --force -b $DPDK_DRIVER $DPDK_DEVICES
dpdk-devbind.py --status
