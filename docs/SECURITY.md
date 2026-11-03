# Security Policy & Architecture

**Maintainer:** Daviante (`https://daviante.org`)  
**Security Contact:** `code@daviante.org`

---

## 1. Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Send vulnerability reports privately to:

- **Email**: `code@daviante.org`
- **Subject**: `[SECURITY] dgip: <short summary>`

Include affected versions or endpoints, reproduction steps, and potential impact. Daviante acknowledges reports within **72 hours**, investigates promptly, and coordinates remediation before public disclosure.

---

## 2. Defense-in-Depth Controls

### 2.1 Zero-Mutation Read-Only HTTP Surface
- The public HTTP server (`src/http.rs`) exposes **10 read-only routes** (`/healthz/*`, `/v1/ip/*`, `/v1/snapshots/*`) plus the zero-CDN interactive portal (`/`) and flag-gated documentation (`/docs`, `/openapi.json`).
- **Zero administrative or database-mutating HTTP endpoints exist.** All operational actions (`dgip status`, `dgip sync`, `dgip release`, `dgip config`, `dgip feed`, `dgip host`) execute exclusively via the local `/usr/local/bin/dgip` static binary inside the container, protected by host/Kubernetes/OpenShift runtime RBAC rather than internet-reachable bearer tokens.

### 2.2 Strict Input Parsing, Streaming Body Cap & Anti-Spoofing
- **No DNS Resolution on User Input**: `/v1/ip/{ip}` and `POST /v1/ip/batch` parse strict IPv4/IPv6 literals via Rust's `std::net::IpAddr` parser. Hostnames, CIDR suffixes (`8.8.8.0/24`), and IPv6 zone IDs (`fe80::1%eth0`) are rejected immediately with `application/problem+json`.
- **Streaming Body Guard**: Enforces `max_request_body_bytes` (`256 KiB` default) both upfront on `Content-Length` and chunk-by-chunk across `Transfer-Encoding: chunked` streams (`413 Payload Too Large`), preventing unauthenticated memory exhaustion.
- **Right-to-Left `X-Forwarded-For` Anti-Spoofing**: `extract_client_ip` ignores `X-Forwarded-For` unless the direct TCP peer matches an explicit CIDR in `dgip_config.trusted_proxies`, walking hops right-to-left and stopping at the first non-trusted address so clients cannot forge leftmost headers to bypass rate limits.
- **Bounded-Memory Per-IP Rate Limiting**: `SlidingWindowRateLimiter` enforces separate sliding windows for lookups (`120/min`) and binary downloads (`30/min`) with strict `max_keys` (`50,000` default) LRU eviction so spoofed or distributed source IPs cannot grow memory unboundedly.
- **Hardened HTTP Security Headers**: Every response emits `Content-Security-Policy` (`default-src 'none'; frame-ancestors 'none'` on API routes; scoped `cdn.jsdelivr.net` policy on `/docs`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Permissions-Policy: geolocation=(), microphone=(), camera=()`.

### 2.3 Outbound SSRF, Tarbomb & Decompression Guards
Every outbound HTTPS fetch (`download_https_bounded`) and every `301`/`302`/`303`/`307`/`308` redirect hop enforces:
1. **`https://` Scheme Only**: Plaintext `http://` is never permitted (`file://` is rejected unless `DGIP_ALLOW_LOCAL_FILES=true` in offline test runs).
2. **Database Hostname Allowlist**: Exact FQDN membership in `dgip_allowed_hosts`.
3. **Pre-Connect Unicast DNS Verification & Socket Pinning**: Resolves all `A`/`AAAA` records prior to connecting, aborts if **any** resolved IP is non-global (blocking `127.0.0.0/8`, `::1`, RFC 1918 private networks, `169.254.169.254` cloud metadata endpoints, link-local, multicast, and CGNAT space), and pins those verified socket addresses in `reqwest` to eliminate DNS rebinding TOCTOU.
4. **Multi-Layer Byte & Tarbomb Caps**: Enforces streaming compressed limits (`max_compressed_bytes`), streaming gzip decompression limits (`max_uncompressed_bytes`), PAX path-traversal/symlink rejection, cumulative archive extraction caps (`max_archive_bytes = 512 MiB`), SHA-256 manifest verification, and per-feed `min_records` sanity thresholds before touching database tables.

### 2.4 BGP Routing Hygiene & SQL Safety
- Rejects default routes (`0.0.0.0/0`, `::/0`), overly broad supernets (`< /8` IPv4, `< /12` IPv6), low-visibility route leaks (`< bgp_min_peers`), BGP `AS_SET`s, private/reserved ASNs, and all IANA RFC 6890 special-purpose bogon blocks.
- All SQL queries use parameterized `tokio-postgres` bindings; Blue/Green table identifiers are strictly gated (`slot in ("a", "b")`), and bulk `COPY` streams escape `\`, `\t`, `\n`, and `\r` control characters deterministically.

### 2.5 `FROM scratch` Container, Kubernetes & Supply-Chain Hardening
- Packaged into `FROM scratch` containing only the static `musl` Rust binary, TLS root certificates, `openapi.yaml`, and SVG brand assets — zero shell (`/bin/sh`), zero package managers, and zero OS libraries.
- Runs as non-root `UID 10001` / `GID 0` (`g=u` permissions) with `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, and `noexec,nosuid` `/tmp` storage — passing both Kubernetes **Restricted Pod Security Standards** and Red Hat OpenShift **`restricted-v2` SCC** out of the box.
- Official GHCR container images and OCI Helm charts are built in GitHub Actions with **keyless OIDC SLSA build provenance attestations**, verifiable via:
  ```bash
  gh attestation verify oci://ghcr.io/daviante-org/dgip:1.0.0 --owner daviante-org
  ```
