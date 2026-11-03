# Usage, API Integration & `dgip` CLI Guide

**Production API:** `https://dgip.daviante.org`  
**OpenAPI 3.1 Contract:** [`openapi.yaml`](../openapi.yaml)  
**Public Datasets:** `https://github.com/daviante-org/dgip-data`

This guide covers querying the read-only HTTP API, handling rate limits and RFC 9457 error responses, integrating weekly `.mmdb` and `.csv.gz` snapshots locally, and operating a self-hosted instance with the `dgip` CLI.

---

## 1. HTTP API Reference & Examples

All HTTP endpoints are **read-only** and require **no API key**. Responses include standard rate-limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`), and all `4xx`/`5xx` errors conform to **RFC 9457 Problem Details** (`Content-Type: application/problem+json`).

### 1.1 Look Up a Single IPv4 or IPv6 Address (`GET /v1/ip/{ip}`)

Accepts strict IPv4 or IPv6 address literals (no DNS hostnames, CIDR `/prefix` suffixes, or IPv6 `%zone` IDs). RFC 4291 IPv4-mapped IPv6 literals (`::ffff:8.8.8.8`) are automatically normalized to canonical IPv4 (`8.8.8.8`) with `is_ipv4_mapped: true`.

```bash
curl -sS https://dgip.daviante.org/v1/ip/3.6.0.1 | jq
```

**`200 OK` — 4-Layer Routed Public IP Response (AWS Mumbai):**
```json
{
  "ip": "3.6.0.1",
  "ip_version": 4,
  "is_ipv4_mapped": false,
  "is_bogon": false,
  "bogon_type": null,
  "found": true,
  "asn": {
    "number": 16509,
    "code": "AS16509",
    "organization": "AMAZON-02",
    "network_type": "hosting",
    "rpki_status": "valid",
    "range_start": "3.6.0.0",
    "range_end": "3.7.255.255"
  },
  "geo": {
    "country_code": "IN",
    "country_name": "India",
    "continent_code": "AS",
    "continent_name": "Asia",
    "region_code": "IN-MH",
    "city": "Mumbai",
    "source": "geofeed",
    "range_start": "3.6.0.0",
    "range_end": "3.7.255.255"
  },
  "security": {
    "is_cloud": true,
    "is_datacenter": true,
    "is_cdn": false,
    "is_tor_exit": false,
    "is_privacy_relay": false,
    "is_threat": false,
    "provider": "aws",
    "threat_feeds": [],
    "range_start": "3.6.0.0",
    "range_end": "3.7.255.255"
  },
  "snapshot_version": "v2026.W45",
  "live_updated_at": "2026-11-02T18:53:00Z"
}
```

**`200 OK` — Special-Purpose / Bogon IP Response (`192.168.1.10`):**
```json
{
  "ip": "192.168.1.10",
  "ip_version": 4,
  "is_ipv4_mapped": false,
  "is_bogon": true,
  "bogon_type": "private",
  "found": false,
  "asn": null,
  "geo": null,
  "security": null,
  "snapshot_version": "v2026.W45",
  "live_updated_at": "2026-11-02T18:53:00Z"
}
```

**`400 Bad Request` — Invalid Input (`application/problem+json`):**
```json
{
  "type": "about:blank",
  "title": "Invalid IP Address",
  "status": 400,
  "detail": "CIDR notation is not allowed; provide a single IP address: '8.8.8.0/24'",
  "instance": "/v1/ip/8.8.8.0/24"
}
```

---

### 1.2 Look Up Caller IP (`GET /v1/ip/me`)

Returns ASN and country metadata for the connecting client's IP address (or the rightmost untrusted client IP in `X-Forwarded-For` when behind a configured `trusted_proxies` reverse proxy):

```bash
curl -sS https://dgip.daviante.org/v1/ip/me | jq
```

---

### 1.3 Bulk Batch Lookup (`POST /v1/ip/batch`)

Resolves up to `max_batch_size` IPs (`1,000` by default; max payload `256 KiB`) in a single request using set-based PostgreSQL GiST range joins (`~12ms` for 100 mixed IPv4/IPv6 addresses). Invalid entries inside the array do **not** fail the whole batch — each item reports `ok: true|false` individually in input order.

```bash
curl -sS -X POST https://dgip.daviante.org/v1/ip/batch \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["8.8.8.8", "2606:4700:4700::1111", "10.0.0.1", "not-an-ip"]
  }' | jq
```

**`200 OK` Response (abbreviated):**
```json
{
  "count": 4,
  "snapshot_version": "v2026.W45",
  "live_updated_at": "2026-11-02T15:46:53Z",
  "results": [
    { "input": "8.8.8.8", "ok": true, "data": { "ip": "8.8.8.8", "found": true, "..." : "..." }, "error": null },
    { "input": "2606:4700:4700::1111", "ok": true, "data": { "ip": "2606:4700:4700::1111", "found": true, "..." : "..." }, "error": null },
    { "input": "10.0.0.1", "ok": true, "data": { "ip": "10.0.0.1", "is_bogon": true, "bogon_type": "private", "found": false }, "error": null },
    { "input": "not-an-ip", "ok": false, "data": null, "error": "Invalid IPv4 or IPv6 address literal: 'not-an-ip'" }
  ]
}
```

---

### 1.4 Snapshot Discovery, Update Checks & Conditional Downloads

```bash
# Check whether a newer snapshot exists than your locally installed version
curl -sS "https://dgip.daviante.org/v1/snapshots/latest?current_version=v2026.W44" | jq '{version, update_available, bundle_sha256}'

# Download an artifact with ETag caching (returns 304 Not Modified when unchanged)
curl -fsSLOJ -H 'If-None-Match: "<sha256-from-previous-run>"' \
  https://dgip.daviante.org/v1/snapshots/v2026.W45/files/dgip-country.mmdb
```

| Endpoint | Purpose |
| :--- | :--- |
| `GET /v1/snapshots?limit=20` | Lists snapshot release history newest-first (`has_blobs: false` indicates pruned binary blobs). |
| `GET /v1/snapshots/latest` | Returns latest snapshot metadata, per-file SHA-256 digests, diff summary, and Markdown release notes. |
| `GET /v1/snapshots/{version}` | Returns metadata for an explicit version (e.g. `v2026.W45`). |
| `GET /v1/snapshots/{version}/bundle.tar.gz` | Downloads the complete archive (`ETag`, `X-Checksum-Sha256`, `Cache-Control: immutable`). |
| `GET /v1/snapshots/{version}/files/{filename}` | Downloads a single CSV, Geofeed, `.mmdb`, `manifest.json`, or `SHA256SUMS.txt` (`410 Gone` if pruned). |

---

### 1.5 Rate Limits & Retry Handling (`429 Too Many Requests`)

Default sliding-window limits per client IP:
- **Lookups & metadata**: `120` requests / `60s`
- **Binary artifact downloads**: `30` requests / `60s`

When exceeded, `dgip` returns `429 Too Many Requests` (`application/problem+json`) with `Retry-After` (seconds):

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/problem+json
Retry-After: 18
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1762104120
```

---

## 2. Language Client Examples

### Rust (`reqwest` + `serde_json`)
```rust
let client = reqwest::Client::new();
let resp: serde_json::Value = client
    .post("https://dgip.daviante.org/v1/ip/batch")
    .json(&serde_json::json!({ "ips": ["1.1.1.1", "2606:4700:4700::1111"] }))
    .send()
    .await?
    .error_for_status()?
    .json()
    .await?;
```

### Go (`net/http`)
```go
resp, err := http.Get("https://dgip.daviante.org/v1/ip/8.8.8.8")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
```

### JavaScript / TypeScript (`fetch`)
```ts
const res = await fetch("https://dgip.daviante.org/v1/ip/8.8.8.8");
if (!res.ok) throw new Error(`HTTP ${res.status}`);
const info = await res.json();
console.log(info.asn?.code, info.geo?.country_code);
```

---

## 3. Local Offline Integration (`.mmdb` & `.csv.gz`)

For high-throughput mail servers (such as DGMail), API gateways, or firewalls performing thousands of lookups per second, download the weekly files from [`daviante-org/dgip-data`](https://github.com/daviante-org/dgip-data/releases/latest) or your own `dgip` instance and evaluate lookups in-process with zero network latency.

### Rust (`maxminddb`)
```rust
let asn_db = maxminddb::Reader::open_readfile("dgip-asn.mmdb")?;
let cc_db = maxminddb::Reader::open_readfile("dgip-country.mmdb")?;
let sec_db = maxminddb::Reader::open_readfile("dgip-security.mmdb")?;

let asn: serde_json::Value = asn_db.lookup("1.1.1.1".parse()?)?;
let geo: serde_json::Value = cc_db.lookup("3.6.0.1".parse()?)?;
let sec: serde_json::Value = sec_db.lookup("104.16.0.1".parse()?)?;
```

### NGINX (`ngx_http_geoip2_module`)
```nginx
geoip2 /etc/nginx/geoip/dgip-country.mmdb {
    auto_reload 60m;
    $geoip2_country_code default=-- country iso_code;
}
geoip2 /etc/nginx/geoip/dgip-asn.mmdb {
    auto_reload 60m;
    $geoip2_asn autonomous_system_number;
}
```

---

## 4. Complete `dgip` Operational CLI Reference

Inside the container image, `/usr/local/bin/dgip` handles all operational and administrative workflows. Prefix commands with your container runtime:
- **Docker**: `docker exec dgip dgip <subcommand>` (or `docker compose exec dgip dgip ...`)
- **Podman**: `podman exec dgip dgip <subcommand>`
- **Kubernetes**: `kubectl -n dgip exec deploy/dgip -- dgip <subcommand>`
- **OpenShift**: `oc -n dgip exec deploy/dgip -- dgip <subcommand>`

Every subcommand (except offline `build-release`) accepts `--json` for clean JSON output on `stdout` (progress logs always write to `stderr`).

| Command | Description |
| :--- | :--- |
| `dgip --version` | Print installed `dgip` version (`dgip 1.0.0`). |
| `dgip status [--json]` | Show bootstrap state, active Blue/Green slot (`a`/`b`), active snapshot version, row counts, sync/release timestamps & errors, and cached snapshot blobs. |
| `dgip sync [--force] [--json]` | Download all enabled RIR/RIPE feeds, compile in child process, `COPY` into inactive slot, build GiST indexes, and flip `active_slot` atomically (`--force` bypasses SHA-256 unchanged check). |
| `dgip release [--force] [--note TEXT] [--json]` | Compile a weekly snapshot (`vYYYY.Www`) including CSVs, Geofeed, `.mmdb` files, `bundle.tar.gz`, and diff release notes into PostgreSQL. |
| `dgip catalog [--json]` | Display active `catalog_version` and counts of config keys, feeds, allowed hosts, countries, and special ranges. |
| `dgip config list [--json]` | List all 30 runtime keys and values in `dgip_config`. |
| `dgip config get <key> [--json]` | Print the current value of a single `dgip_config` key. |
| `dgip config set KEY=VALUE [...] [--json]` | Validate and persist one or more settings (e.g. `dgip config set rate_limit_per_minute=240 trusted_proxies=10.0.0.0/8,172.16.0.0/12`). Running HTTP workers hot-reload within `2s`. |
| `dgip feed list [--json]` | List all 25 upstream Layer 1–4 feed definitions, record minimums, and URLs. |
| `dgip feed enable <feed_key> [--json]` | Enable a feed in `dgip_feed_sources`. |
| `dgip feed disable <feed_key> [--json]` | Temporarily disable a feed in `dgip_feed_sources`. |
| `dgip feed set-url <feed_key> <https_url> [--min-records N]` | Point a feed to an alternative HTTPS URL (ensure its FQDN is permitted in `dgip host list`). |
| `dgip host list [--json]` | List all hostnames in `dgip_allowed_hosts` (outbound SSRF allowlist). |
| `dgip host allow <fqdn> [--notes TEXT]` | Add or re-enable an outbound HTTPS hostname in `dgip_allowed_hosts`. |
| `dgip host deny <fqdn> [--notes TEXT]` | Disable an outbound HTTPS hostname in `dgip_allowed_hosts`. |
| `dgip build-release --output-dir <dir> [--version <ver>]` | Compile a standalone release directory directly from RIR/RIPE feeds onto local disk without requiring PostgreSQL. |

### Exit Codes
- `0` — Command succeeded.
- `1` — Runtime, database connectivity, or upstream synchronization error.
- `2` — CLI argument or configuration validation error (`InvalidConfigUpdateError`).
- `130` — Interrupted (`SIGINT` / `Ctrl+C`).
