FROM rust:1-bookworm AS rust
WORKDIR /src
COPY Cargo.toml ./
COPY rust ./rust
RUN cargo build --release --manifest-path Cargo.toml

FROM golang:1.22-bookworm AS go
WORKDIR /src/go
COPY go ./
RUN go build -o /out/tgkeyscan ./cmd/tgkeyscan

FROM python:3.12-slim
WORKDIR /app
COPY python ./python
COPY examples ./examples
COPY --from=rust /src/target/release/tgkeyhunt /usr/local/bin/tgkeyhunt
COPY --from=go /out/tgkeyscan /usr/local/bin/tgkeyscan
ENV PYTHONPATH=/app/python
ENTRYPOINT ["bash", "/app/examples/demo.sh"]
