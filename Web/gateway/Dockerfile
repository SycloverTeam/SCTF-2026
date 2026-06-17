FROM rust:1-bookworm AS builder

WORKDIR /src
COPY gateway ./gateway
COPY vault ./vault

RUN cargo build --manifest-path gateway/Cargo.toml --release
RUN cargo build --manifest-path vault/Cargo.toml --release

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin ctf

COPY --from=builder /src/gateway/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /src/vault/target/release/vault /usr/local/bin/vault
COPY gateway.toml /etc/gateway.toml
COPY docker/start.sh /usr/local/bin/start-challenge

RUN chmod +x /usr/local/bin/start-challenge

ENV TREASURY_RECONCILIATION_TOKEN=SCTF{[redacted]}
USER ctf
EXPOSE 8080

CMD ["/usr/local/bin/start-challenge"]
