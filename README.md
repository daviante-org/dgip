<div align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/logo.svg">
    <img alt="dgip" src="./assets/logo.svg" width="200" height="56">
  </picture>
</div>

<br>

**Self-Hosted 4-Layer IPv4 & IPv6 Network, Geolocation, RPKI & Security Intelligence Engine**

`dgip` is the self-hosted IP intelligence service maintained by [Daviante](https://daviante.org) (`https://dgip.daviante.org`). It compiles **4 layers of open Internet intelligence** directly from 25 authoritative registries, route collectors, RPKI validators, cloud/operator geofeeds, and open threat feeds; serves sub-10ms **read-only** REST lookups from PostgreSQL Blue/Green GiST range indexes; provides the `dgip` operational CLI; and produces the weekly multi-format dataset releases published in [`daviante-org/dgip-data`](https://github.com/daviante-org/dgip-data).

---

## Key Capabilities

- **4-Layer Open IP Intelligence (Zero Commercial Aggregators & Zero Telemetry)**:
  1. **Layer 1 — Authoritative RIRs & RIPE RIS BGP**: **ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC** extended delegations + **RIPE NCC RIS** global BGP routing tables (`rrc00`–`rrc26`) and AS organization names (with automatic RIPE NCC NRO mirror fallback).
  2. **Layer 2 — Sub-National & Cloud Regional Geolocation (`RFC 8805`)**: Overlays **AWS, Google Cloud, Oracle Cloud, DigitalOcean, Akamai/Linode, Vultr**, and **Apple iCloud Private Relay** physical regional feeds over RIR headquarters registrations to resolve real datacenter/POP country, ISO 3166-2 `region_code`, and `city`.
  3. **Layer 3 — Cryptographic RPKI Route Origin Validation & AS Classification**: Validates BGP announcements against **OpenBSD `rpki-client`** Validated ROA Payloads (`RFC 6811` / `RFC 7607`, rejecting RPKI-`invalid` BGP hijacks by default) and classifies ASNs via **`bgp.tools`** (`isp`, `hosting`, `cdn`, `transit`, `content`, `education`, `government`, `business`).
  4. **Layer 4 — Cloud, CDN, Tor Exit, Privacy Relay & Threat Intelligence**: Multi-label coordinate sweep-line combining **Cloudflare, Fastly, GitHub, AWS, GCP, OCI, DigitalOcean, Linode, Vultr**, **Apple iCloud Private Relay**, **Tor Project Exit Nodes**, **Spamhaus DROP (`IPv4`/`IPv6`)**, and **Abuse.ch Feodo Tracker Botnet C2** into unified `SecurityInfo` flags.
- **100% Read-Only HTTP Surface + Built-In `dgip` CLI**: Exposes zero administrative or mutating HTTP endpoints to the network. Operational tasks (`dgip status`, `dgip sync`, `dgip release`, `dgip config`, `dgip feed`, `dgip host`) run locally inside the container via `/usr/local/bin/dgip` with `--json` support and `<= 2s` live hot-reload.
- **Zero-Downtime Blue/Green Updates**: Compiles all 6 IPv4/IPv6 ASN, Country, and Security interval tables natively in Rust, bulk-loads the inactive PostgreSQL slot (`*_a` / `*_b`) via streaming `COPY`, builds fresh `int8range`/`numrange` GiST indexes, and flips `active_slot` atomically without interrupting live queries.
- **Multi-Standard Weekly Snapshots (`vYYYY.Www`)**: Generates **6 RFC 4180 Range CSVs** (`asn`, `country`, `security`), **IETF RFC 8805 Geofeed** (with ISO 3166-2 region & city), and **3 dual-stack MaxMind DB Binary v2.0 (`.mmdb`)** databases (`dgip-asn.mmdb`, `dgip-country.mmdb`, `dgip-security.mmdb`) alongside `manifest.json` and `SHA256SUMS.txt`.
- **Ultra-Light `FROM scratch` Rust Runtime**: Single static `musl` Rust binary (`~10 MB` image, `< 15 MB` idle RAM, zero shell or OS packages, `0` Trivy image CVEs) running unprivileged (`UID 10001:0`, `chmod -R g=u`, `--read-only` rootfs, `cap_drop: [ALL]`) across **Docker**, **Podman** (rootless & rootful), **Kubernetes** (`restricted` PSS), and **Red Hat OpenShift** (`restricted-v2` SCC + native Edge-TLS `Route`).

---

## Quick Start

### Docker or Podman Compose
```bash
cp .env.example .env
docker compose up -d          # or: podman compose up -d
docker compose exec dgip dgip status
```

### Kubernetes (Official GitHub OCI Helm v3 Chart)
```bash
helm install dgip oci://ghcr.io/daviante-org/charts/dgip -n dgip --create-namespace
kubectl -n dgip exec deploy/dgip -- dgip status
```

### Red Hat OpenShift (`restricted-v2` SCC + Native Route)
```bash
oc new-project dgip
helm install dgip oci://ghcr.io/daviante-org/charts/dgip -n dgip \
  --set openshift.enabled=true \
  --set openshift.route.enabled=true
```

---

## HTTP API & `dgip` CLI Overview

A zero-CDN interactive 4-layer IP lookup portal is served at `GET /` (`https://dgip.daviante.org`), and branded Swagger UI is served at `GET /docs` (OpenAPI 3.1 contract: [`openapi.yaml`](./openapi.yaml); disable Swagger anytime via `DGIP_SWAGGER_ENABLED=false` or `dgip config set swagger_enabled=false`). Compatible with **PostgreSQL 12+** (`13`–`18`; default Compose/Helm image uses `postgres:18.6-alpine`).

### Read-Only HTTP Endpoints
| Method & Path | Description |
| :--- | :--- |
| `GET /healthz/live` · `GET /healthz/ready` | Container liveness and PostgreSQL + active GiST slot readiness probes. |
| `GET /v1/ip/me` | Caller IPv4/IPv6 ASN, RPKI status, sub-national geolocation, security flags, and RFC 6890 bogon lookup. |
| `GET /v1/ip/{ip}` | Single IPv4 or IPv6 literal 4-layer lookup (`::ffff:` IPv4-mapped supported). |
| `POST /v1/ip/batch` | Bulk 4-layer lookup for up to `1,000` IPv4/IPv6 addresses in a single request. |
| `GET /v1/snapshots` · `GET /v1/snapshots/latest` | Snapshot release history, SHA-256 manifest, and `?current_version=` update check. |
| `GET /v1/snapshots/{version}/bundle.tar.gz` | Complete weekly `tar.gz` bundle (`ETag` / `304` & `X-Checksum-Sha256`). |
| `GET /v1/snapshots/{version}/files/{filename}` | Individual `.csv.gz`, RFC 8805 Geofeed, `.mmdb`, `manifest.json`, or `SHA256SUMS.txt`. |

### `dgip` Operational CLI (`/usr/local/bin/dgip`)
```bash
dgip status [--json]                                         # Inspect active slot, row counts & sync health
dgip sync [--force] [--json]                                 # Refresh inactive GiST slot from RIR/RIPE feeds
dgip release [--force] [--note TEXT] [--json]                # Cut a multi-format vYYYY.Www snapshot release
dgip catalog [--json]                                        # Summary of runtime PostgreSQL catalog tables
dgip config {list | get <key> | set KEY=VALUE ...} [--json]  # Live hot-reload runtime parameters (<= 2s)
dgip feed {list | enable <k> | disable <k> | set-url ...}    # Manage upstream RIR & RIPE RIS feeds
dgip host {list | allow <fqdn> | deny <fqdn>}                # Manage outbound HTTPS SSRF host allowlist
dgip build-release --output-dir <dir> [--version <ver>]      # Standalone offline compiler (no DB needed)
```

---

## Documentation Index

| Document | Contents |
| :--- | :--- |
| **[`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)** | System topology, Blue/Green GiST design, 3-phase data lifecycle, advisory locks, and PostgreSQL schema. |
| **[`docs/SOURCES_AND_DATA_POLICY.md`](./docs/SOURCES_AND_DATA_POLICY.md)** | All 25 Layer 1–4 open feeds, RPKI ROV & geofeed overlay rules, security sweep-line, artifact schemas, and operator correction policy. |
| **[`docs/USAGE.md`](./docs/USAGE.md)** | REST API examples (4-layer JSON responses, RFC 9457 errors & `429` retry headers), Rust/Go/NGINX `.mmdb` integration, and full `dgip` CLI reference. |
| **[`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md)** | Sizing, firewall egress, Docker, Podman, Reverse Proxy TLS (`trusted_proxies`), Kubernetes OCI Helm, OpenShift `restricted-v2`, and air-gapped setup. |
| **[`docs/CONFIGURATION.md`](./docs/CONFIGURATION.md)** | Complete reference for `DGIP_*` environment variables, Helm `values.yaml`, and all 30 hot-reloadable `dgip_config` keys. |
| **[`docs/TROUBLESHOOTING.md`](./docs/TROUBLESHOOTING.md)** | Symptom-by-symptom operational runbook (DB pool, RIR throttling, `X-Forwarded-For` `429`s, `410 Gone`, OpenShift SCC, OOM sizing). |
| **[`docs/SECURITY.md`](./docs/SECURITY.md)** | Vulnerability reporting (`code@daviante.org`), read-only HTTP threat model, SSRF/tarbomb guards, container hardening, and SLSA provenance verification. |
| **[`docs/TERMS.md`](./docs/TERMS.md)** | Terms of Use, acceptable public API usage, and geolocation/BGP routing accuracy disclaimers. |
| **[`docs/PRIVACY.md`](./docs/PRIVACY.md)** | Zero-telemetry self-hosted guarantee, `https://dgip.daviante.org` volatile rate-limit policy, and RIR metadata scope. |
| **[`CREDITS.md`](./CREDITS.md)** · **[`NOTICE`](./NOTICE)** | Complete third-party data ownership, copyright, attribution, and trademark notices across all 25 upstream feeds and open format specs. |
| **[`openapi.yaml`](./openapi.yaml)** | Canonical OpenAPI 3.1 HTTP specification (verified 1:1 against Axum HTTP routes in CI). |
| **[`charts/dgip/`](./charts/dgip/Chart.yaml)** · **[`deploy/`](./deploy/kubernetes/dgip.yaml)** | Official Helm v3 chart and standalone Kubernetes / Red Hat OpenShift manifests. |

---

## License & Upstream Data Attribution

Software, schemas, and documentation in this repository are licensed under the [Apache License, Version 2.0](./LICENSE) (see [`NOTICE`](./NOTICE)). Daviante claims no ownership over third-party registry, BGP routing, RPKI, geofeed, or threat-intelligence data; all upstream rights belong to their respective owners as credited in [`CREDITS.md`](./CREDITS.md). Weekly compiled datasets in [`daviante-org/dgip-data`](https://github.com/daviante-org/dgip-data) are published under PDDL v1.0 subject to upstream source terms.

Maintained by **Daviante** (`https://daviante.org`) — Contact: `code@daviante.org`.
