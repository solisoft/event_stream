.PHONY: build run-broker demo test lint fmt check audit clean

build:
	cargo build --release

run-broker: build
	./target/release/es-broker --data-dir ./data --bind 127.0.0.1:9000

demo: build
	./scripts/demo.sh

test:
	cargo test --workspace

fmt:
	cargo fmt --all

check:
	cargo clippy --workspace --all-targets -- -D warnings

lint: fmt check

audit:
	cargo deny check bans licenses sources

clean:
	rm -rf ./data
	cargo clean
