#!/usr/bin/env bash

## Version we recommend.
RUSTUP_TOOLCHAIN=${1:-nightly-2019-10-28}

## Note: make sure cargo is your PATH,
## e.g. `source $HOME/.cargo/env`.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUSTUP_TOOLCHAIN \
  && source $HOME/.cargo/env \
  && cargo install cargo-watch \
  && rustup default $RUSTUP_TOOLCHAIN

## Needed if cargo not installed for root user, when running DPDK examples/apps
## with root privilege, as need by DPDK:
##
## sudo ln -s $HOME/.rustup /root/.rustup
