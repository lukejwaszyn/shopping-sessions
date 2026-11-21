# Shopping Sessions: single static Rust binary in an empty image.
# No FROM line pins a platform: the scorer builds this natively on linux/amd64,
# and `make build PLATFORM=linux/arm64` builds a native image on Apple silicon.
FROM rust:1.99.0-alpine AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The scorers are Cascade Lake or newer, so x86-64-v3 (AVX2, BMI2) is safe.
# The alpine toolchain targets musl and links statically.
RUN set -eux; \
    if [ "$(uname -m)" = "x86_64" ]; then export RUSTFLAGS="-C target-cpu=x86-64-v3"; fi; \
    cargo build --release --locked; \
    cp target/release/pipeline /pipeline

FROM scratch
COPY --from=build /pipeline /pipeline
# The scorer runs as uid 1000 with a read-only root; the binary needs neither
# a home directory nor /tmp. It reads DATA_DIR, OUTPUT_DIR and NCPU.
USER 1000:1000
ENV DATA_DIR=/data OUTPUT_DIR=/output SCRATCH_DIR=/scratch
CMD ["/pipeline"]
