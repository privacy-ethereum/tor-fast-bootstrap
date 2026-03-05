FROM rust:1.89-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY web/ web/

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tor-fast-bootstrap /usr/local/bin/

EXPOSE 42298
VOLUME /data

ENTRYPOINT ["tor-fast-bootstrap", "--output-dir", "/data"]