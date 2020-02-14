#!/usr/bin/env bash

RUSTUP_TOOLCHAIN=${1:-nightly-2019-10-28}

## Note: make sure cargo is in PATH.

curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUSTUP_TOOLCHAIN \
    && source $HOME/.cargo/env \
    && rustup default $RUSTUP_TOOLCHAIN
