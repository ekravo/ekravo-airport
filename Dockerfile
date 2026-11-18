# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /build
# Copy the lockfile so the image builds the exact dependency set that CI tests.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# The workspace [patch.crates-io] points at the vendored SQLite binding fix.
COPY vendor ./vendor
# The device client is not shipped in the server image, but the workspace still
# resolves its manifest. Build only the server binary.
RUN cargo build --release --locked -p airport-server --bin airport

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/airport --shell /usr/sbin/nologin airport \
    && mkdir -p /var/lib/airport \
    && chown airport:airport /var/lib/airport

COPY --from=builder /build/target/release/airport /usr/local/bin/airport
COPY docker-healthcheck.sh /usr/local/bin/airport-healthcheck
RUN chmod 0755 /usr/local/bin/airport-healthcheck

USER airport
WORKDIR /var/lib/airport
ENV AIRPORT_BIND_ADDR=0.0.0.0:8787 \
    AIRPORT_DATABASE_URL=sqlite:///var/lib/airport/airport.db \
    AIRPORT_LOG_FORMAT=json

EXPOSE 8787
VOLUME ["/var/lib/airport"]

# Supports plaintext and in-process TLS. TLS deployments set
# AIRPORT_HEALTHCHECK_URL=https://… and AIRPORT_HEALTHCHECK_CA=/path/ca.pem.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/airport-healthcheck"]

ENTRYPOINT ["airport"]
