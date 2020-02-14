#!/usr/bin/env bash

## Version we recommend.
DPDK_VERSION=${1:-18.11}

## Download DPDK version from Github Archive (https://github.com/DPDK/dpdk).
wget https://github.com/DPDK/dpdk/archive/v${DPDK_VERSION}.tar.gz -O - | tar xz -C $HOME

## Build DPDK and install into system paths.
## More info: https://doc.dpdk.org/guides/prog_guide/build-sdk-meson.html.
cd $HOME/dpdk-${DPDK_VERSION}
meson build
cd build && ninja && ninja install

## Create the necessary links and caches.
sudo ldconfig
