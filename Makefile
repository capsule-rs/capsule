SHELL := /bin/bash

CLIPPY_ARGS = --all-targets --all-features -- -D clippy::wildcard_dependencies -D rust-2018-idioms -D warnings
CRITERION_PLOTS_DIR = bench/target/criterion
NIGHTLY := $(shell rustup show|grep nightly 2> /dev/null)

.PHONY: bench check clean clean-plots docs fmt lint find-plots test watch watch-lint

bench:
	@cargo bench

check:
	@cargo check --workspace --all-targets --all-features

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
	@cargo clippy $(CLIPPY_ARGS)

test:
	@pushd core && cargo test --features full && popd
	@cargo test --all-targets --workspace --exclude capsule

compile-failure:
	@pushd core && cargo test --features compile_failure && popd

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
