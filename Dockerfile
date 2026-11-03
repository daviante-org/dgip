# ==============================================================================
# DGIP Network Intelligence Service — Multi-Platform Scratch Container Image
# ==============================================================================
# Pure-Rust static musl binary packaged into `FROM scratch` (~10 MB, zero shell,
# zero OS package attack surface). Compatible out of the box with:
#   - Docker Engine & Docker Compose
#   - Podman (rootless & rootful) & Podman Compose / Systemd Quadlets
#   - Kubernetes (Pod Security Standards: "restricted" / runAsNonRoot: true)
#   - Red Hat OpenShift Container Platform ("restricted-v2" SCC arbitrary UIDs)
#
# Published exclusively to GitHub Container Registry:
#   ghcr.io/daviante-org/dgip
# ==============================================================================

FROM docker.io/library/rust:1.99-alpine AS builder

RUN apk upgrade --no-cache \
    && apk add --no-cache musl-dev ca-certificates

WORKDIR /build

# 1. Pre-compile and cache all locked third-party crates once per Cargo.lock
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'pub fn _dep_stub() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked --bin dgip \
    && rm -rf src target/release/deps/dgip* target/release/deps/libdgip* target/release/dgip* target/release/.fingerprint/dgip-*

# 2. Compile DGIP application source against cached dependencies
COPY src ./src
COPY openapi.yaml ./openapi.yaml
COPY assets ./assets

RUN find src -type f -exec touch {} + \
    && cargo build --release --locked --bin dgip \
    && mkdir -p /rootfs/usr/local/bin /rootfs/etc/ssl/certs /rootfs/app /rootfs/tmp/dgip-cache \
    && cp /build/target/release/dgip /rootfs/usr/local/bin/dgip \
    && chmod 0755 /rootfs/usr/local/bin/dgip \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && cp /build/openapi.yaml /rootfs/app/openapi.yaml \
    && cp -R /build/assets /rootfs/app/assets \
    && printf 'dgip:x:10001:0:DGIP:/tmp:/sbin/nologin\n' > /rootfs/etc/passwd \
    && printf 'root:x:0:dgip\n' > /rootfs/etc/group \
    && chown -R 10001:0 /rootfs/app /rootfs/tmp \
    && chmod -R g=u /rootfs/app /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

FROM scratch

# Standard OpenContainers (OCI) metadata labels linking GHCR packages to GitHub
LABEL org.opencontainers.image.title="DGIP Network Intelligence Service" \
      org.opencontainers.image.description="Self-hosted 4-layer IPv4 & IPv6 network, geolocation, RPKI & security intelligence engine compiled in Rust." \
      org.opencontainers.image.vendor="Daviante" \
      org.opencontainers.image.authors="Daviante <code@daviante.org>" \
      org.opencontainers.image.url="https://daviante.org" \
      org.opencontainers.image.source="https://github.com/daviante-org/dgip" \
      org.opencontainers.image.documentation="https://github.com/daviante-org/dgip/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    DGIP_HOST=0.0.0.0 \
    DGIP_PORT=8090 \
    DGIP_SWAGGER_ENABLED=true \
    DGIP_ASSETS_DIR=/app/assets \
    DGIP_CACHE_DIR=/tmp/dgip-cache

COPY --from=builder /rootfs/ /

WORKDIR /app

# Numeric UID >10000 in GID 0 satisfies Kubernetes `runAsNonRoot: true`,
# OpenShift `restricted-v2` SCC arbitrary UIDs, and CIS/Trivy KSV-0020
USER 10001:0

EXPOSE 8090

# Native static-binary container liveness probe (zero shell or external curl needed)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/dgip", "healthcheck"]

CMD ["/usr/local/bin/dgip", "serve"]
