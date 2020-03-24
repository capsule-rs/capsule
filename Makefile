CLIPPY_ARGS = --all-targets --all-features -- -D clippy::wildcard_dependencies -D rust-2018-idioms -D warnings
CRITERION_PLOTS_DIR = bench/target/criterion
NIGHTLY := $(shell rustup show|grep nightly 2> /dev/null)

.PHONY: bench build build-rel clean clean-plots docs fmt lint find-plots test watch watch-bench watch-test

bench:
	@cargo bench

build:
	@cargo build --all-features

build-rel:
	@cargo build --release

clean:
	@cargo clean

clean-plots:
	@rm -rf $(CRITERION_PLOTS_DIR)

docs:
ifdef NIGHTLY
	@RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc -p capsule --no-deps --all-features
else
	@cargo doc -p capsule --no-deps --all-features
endif

find-plots:
	@ls $(CRITERION_PLOTS_DIR)/report/index.html

fmt:
	@cargo fmt

lint:
	@cargo clippy $(CLIPPY_ARGS)

test:
	@cargo test --all-features

watch:
ifdef WATCH
	@cargo watch --poll -x build -w $(WATCH)
else
	@cargo watch --poll -x build --all
endif

watch-bench:
ifdef WATCH
	@cargo watch --poll -x bench -w $(WATCH)
else
	@cargo watch --poll -x bench --all
endif

watch-lint:
ifdef WATCH
	@cargo watch --poll -s "make lint" -w $(WATCH)
else
	@cargo watch --poll -s "make lint" --all
endif

watch-test:
ifdef WATCH
	@cargo watch --poll -s "cargo test --all-features" -w $(WATCH)
else
	@cargo watch --poll -s "cargo test --all-features" --all
endif
