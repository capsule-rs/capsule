#!/usr/bin/env bash

HUGEPAGES=${1:-2048}


if [[ $EUID -ne 0 ]]; then
    echo "This script should be run as root!" 1>&2
    exit 1
fi

## minimal installs
apt-get update \
    && apt-get upgrade -y \
    && apt-get -q install -y \
               build-essential \
               ca-certificates \
               clang \
               kmod \
               libclang-dev \
               libnuma-dev \
               libpcap-dev \
               libz-dev \
               linux-headers-$(uname -r) \
               llvm-dev \
               xz-utils \
    && rm -rf /var//lib/apt/lists /var/cache/apt/archives

# Allocate (by default) 2048 hugepages
# Change can be validated by executing 'cat /proc/meminfo | grep Huge'
echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages


## Note: example of how to set dpdk_devices for nb2/build.rs.
export DPDK_DEVICES="0000:00:08.0 0000:00:09.0 0000:00:0a.0 0000:00:10.0"
