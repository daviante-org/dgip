# Privacy Policy

**Effective Date:** November 2, 2026  
**Maintainer:** Daviante (`https://daviante.org`)  
**Contact:** `code@daviante.org`

This Privacy Policy explains how `dgip` handles network data in three contexts: (1) self-hosted `dgip` deployments, (2) queries to the Daviante-hosted API (`https://dgip.daviante.org`), and (3) compiled network datasets.

---

## 1. Zero Telemetry in Self-Hosted Deployments

When you deploy `dgip` on your own infrastructure (Docker, Podman, Kubernetes, or OpenShift):

- **Zero Phone-Home or Analytics**: `dgip` contains **no** telemetry, crash-reporting beacons, license checks, or usage analytics back to Daviante or any third party.
- **Controlled Outbound Network Activity**:
  1. On first startup against an empty database (`dgip_state.initial_bootstrapped = FALSE`), if `bootstrap_enabled` is `true`, `dgip` performs a single HTTPS `GET` to GitHub (`github.com/daviante-org/dgip-data`) to download `bundle.tar.gz`. Operators can disable even this single request via `DGIP_INITIAL_BOOTSTRAP_URL=""` or `dgip config set bootstrap_enabled=false`.
  2. Subsequent scheduled syncs connect exclusively to the 8 official RIR and RIPE NCC registry feeds configured in `dgip_feed_sources`.
- **Full Data Locality**: All IP lookup requests sent to your self-hosted `dgip` instance remain entirely within your infrastructure.

---

## 2. Hosted Public API (`https://dgip.daviante.org`)

When a client or application queries `https://dgip.daviante.org` (`/v1/ip/*`, `/v1/snapshots/*`, or `/docs`):

1. **In-Memory Lookup Evaluation**: Submitted IPv4/IPv6 literals and the caller's IP address are evaluated in memory against PostgreSQL GiST range tables solely to return the requested ASN/country response or snapshot file.
2. **Volatile Sliding-Window Rate Limiting**: Connecting client IP addresses are held transiently in volatile process RAM (`SlidingWindowRateLimiter`, default `60s` window with bounded LRU eviction) strictly to enforce fair-use rate limits (`X-RateLimit-*`). These counters expire automatically in memory and are **never** persisted to PostgreSQL or disk.
3. **No Persistent Query Logging, Cookies, or Profiling**:
   - Daviante does **not** store historical `/v1/ip/*` lookup targets or `POST /v1/ip/batch` payloads in any database.
   - The API sets **zero** cookies, performs **zero** browser fingerprinting, and shares **zero** query traffic with third parties or advertisers.
   - Note: When viewing interactive documentation at `https://dgip.daviante.org/docs`, your browser loads open-source Swagger UI v5 static CSS/JS assets from `cdn.jsdelivr.net`; API callers querying `/v1/*` never contact any CDN.
4. **Minimal Operational Diagnostics**: Standard transient infrastructure error logs (such as upstream registry synchronization warnings or application faults) are retained solely for service reliability.

---

## 3. Scope of Compiled Registry Datasets

Datasets compiled by `dgip` and published in `daviante-org/dgip-data` contain exclusively **network-level public Internet infrastructure metadata** sourced from ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC, and RIPE RIS:

- IPv4 and IPv6 network block boundaries (`start_ip`, `end_ip`, CIDR prefixes).
- Autonomous System Numbers (ASNs) and registered AS organization names.
- Country/territory ISO 3166-1 alpha-2 codes assigned to RIR allocations.

Compiled datasets **never** contain individual subscriber names, personal email addresses, street addresses, postal codes, GPS coordinates, or end-user traffic logs.

---

## 4. Network Metadata Corrections & Contact

Because `dgip` processes public RIR and BGP routing records rather than personal subscriber records, network operators wishing to update country or ASN registration attributes for IP blocks they administer should update the authoritative registration at their Regional Internet Registry (ARIN, RIPE NCC, APNIC, LACNIC, or AFRINIC) as detailed in [`SOURCES_AND_DATA_POLICY.md`](./SOURCES_AND_DATA_POLICY.md).

Privacy questions may be directed to `code@daviante.org`.
