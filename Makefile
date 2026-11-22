.PHONY: test test-rust test-go test-python build demo

test: test-rust test-go test-python

test-rust:
	cargo test --manifest-path Cargo.toml

test-go:
	cd go && go test ./...

test-python:
	cd python && python3 -m unittest discover -s tests -v

build:
	cargo build --release --manifest-path Cargo.toml
	cd go && go build ./...
	cd python && python3 -m compileall -q tgkeyhunt

demo:
	bash examples/demo.sh
