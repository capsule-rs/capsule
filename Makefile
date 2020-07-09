SHELL := /bin/bash

CLIPPY_ARGS = -- -D clippy::wildcard_dependencies -D rust-2018-idioms -D warnings
CRITERION_PLOTS_DIR = bench/target/criterion
NIGHTLY := $(shell rustup show|grep nightly 2> /dev/null)

TO_DEVNULL = &>/dev/null

.PHONY: bench check clean clean-plots docs fmt lint find-plots test watch watch-lint

bench:
	@cargo bench

check:
	@pushd core $(TO_DEVNULL) && cargo check --all-targets --features full && popd $(TO_DEVNULL)
	@cargo check --all-targets --workspace --exclude capsule

clean:
	@cargo clean

clean-plots:
	@rm -rf $(CRITERION_PLOTS_DIR)

docs:
ifdef NIGHTLY
	@RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --lib -p capsule \
	-p capsule-ffi -p capsule-macros --no-deps --all-features
else
	@cargo doc --lib -p capsule -p capsule-ffi -p capsule-macros --no-deps \
	--all-features
endif

find-plots:
	@ls $(CRITERION_PLOTS_DIR)/report/index.html

fmt:
	@cargo fmt --all

lint:
	@pushd core $(TO_DEVNULL) && cargo clippy --all-targets --features full $(CLIPPY_ARGS) && popd $(TO_DEVNULL)
	@cargo clippy --all-targets --workspace --exclude capsule $(CLIPPY_ARGS)

test:
	@pushd core $(TO_DEVNULL) && cargo test --all-targets --features full && popd $(TO_DEVNULL)
	@cargo test --all-targets --workspace --exclude capsule

compile-failure:
	@pushd core $(TO_DEVNULL) && cargo test --features compile_failure && popd $(TO_DEVNULL)

watch:
ifdef WATCH
	@cargo watch --poll -x build -w $(WATCH)
else
	@cargo watch --poll -x build --all
endif

watch-lint:
ifdef WATCH
	@cargo watch --poll -s "make lint" -w $(WATCH)
else
	@cargo watch --poll -s "make lint" --all
endif
