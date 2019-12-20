CLIPPY_ARGS = --all-targets --all-features -- -D clippy::wildcard_dependencies -D rust-2018-idioms -D warnings
COVERAGE_PACKAGES = nb2
COVERAGE_EXCLUDES = macros/* ffi/*
CRITERION_PLOTS_DIR = bench/target/criterion

.PHONY: bench build build-rel clean clean-plots coverage fmt lint find-plots test watch watch-bench watch-test

bench:
	@cargo bench

build:
	@cargo build

build-rel:
	@cargo build --release

clean:
	@cargo clean

clean-plots:
	rm -rf $(CRITERION_PLOTS_DIR)

coverage:
	@cargo tarpaulin -l -p $(COVERAGE_PACKAGES) --exclude-files $(COVERAGE_EXCLUDES) --out Xml

fmt:
	@cargo fmt

lint:
	@cargo clippy $(CLIPPY_ARGS)

find-plots:
	@ls $(CRITERION_PLOTS_DIR)/report/index.html

test:
	@cargo test

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
	@cargo watch --poll -x test -w $(WATCH)
else
	@cargo watch --poll -x test --all
endif
