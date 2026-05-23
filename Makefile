.PHONY: build run-broker demo test lint clean

build:
	cargo build --release

run-broker: build
	./target/release/es-broker --data-dir ./data --bind 127.0.0.1:9000

demo: build
	./scripts/demo.sh

test:
	cargo test --workspace

clean:
	rm -rf ./data
	cargo clean
