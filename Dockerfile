# syntax=docker/dockerfile:1

# ---- dependency cache -------------------------------------------------------
# cargo-chef builds only the dependency graph first, so editing src/ does not
# recompile 300 crates.
# The builder and runtime must share a Debian release: the binary links against the
# builder's glibc, and an older glibc in the runtime fails at startup with
# "GLIBC_2.xx not found". Bump both tags together (trixie = Debian 13).
# The minor is pinned to Cargo.toml's rust-version so builds are reproducible; Dependabot
# proposes the bump.
FROM rust:1.99-slim-trixie AS chef
WORKDIR /build
RUN cargo install cargo-chef --locked

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates
RUN cargo build --release --locked
# distroless has no shell to `mkdir` with, so the data directory is made here and copied.
RUN mkdir -p /out/data

# ---- runtime ----------------------------------------------------------------
# distroless/cc is enough: SQLite is compiled in via rusqlite's `bundled` feature
# and TLS is rustls, so there is no system OpenSSL or libsqlite3 to install.
FROM gcr.io/distroless/cc-debian13:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="vedette" \
      org.opencontainers.image.description="Watches NVD and the CISA KEV catalog and notifies on CVEs affecting declared software" \
      org.opencontainers.image.source="https://github.com/SennLabs/Vedette" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# Paths in config/vedette.toml are relative to /app, so the same file works here and
# under `cargo run` from the repository root.
WORKDIR /app
COPY --from=builder /build/target/release/vedette /usr/local/bin/vedette
# The example config is baked in so `docker run` works on its own; deployments mount
# their own over /app/config.
COPY config /app/config

# The database lives on a volume. It must exist in the image owned by nonroot (65532):
# a new named volume copies the ownership of the directory it mounts over, and without
# it the volume is root-owned and SQLite fails with "unable to open database file".
COPY --from=builder --chown=65532:65532 /out/data /app/data

ENV VEDETTE_CONFIG=/app/config/vedette.toml \
    VEDETTE_LOG=info

USER nonroot:nonroot
# The check passes only once both sources have synced. The first NVD sync can take hours,
# so the start period is long: a success during it flips to healthy immediately, and a
# container that is genuinely broken merely shows "starting" instead of "unhealthy".
# Without this, anything that restarts unhealthy containers would loop the first sync.
HEALTHCHECK --interval=5m --timeout=20s --start-period=4h --retries=3 \
    CMD ["/usr/local/bin/vedette", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/vedette"]
CMD ["run"]
