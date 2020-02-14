#!/usr/bin/env bash

HUGEPAGES=${1:-2048}

## Minimal installs.
sudo apt-get update \
  && sudo apt-get install -y \
    build-essential \
    ca-certificates \
    clang \
    kmod \
    libclang-dev \
    libnuma-dev \
    libpcap-dev \
    linux-headers-$(uname -r) \
    llvm-dev \
    meson \
  && sudo rm -rf /var//lib/apt/lists /var/cache/apt/archives

# Allocate (by default) 2048 hugepages.
# Change can be validated by executing 'cat /proc/meminfo | grep Huge'.
echo $HUGEPAGES | sudo tee -a /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
