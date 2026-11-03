# Upstream Data Sources, 4-Layer Compilation Rules & Data Policy

**Maintainer:** Daviante (`https://daviante.org`)  
**Contact:** `code@daviante.org`

This document specifies all **25 open upstream data sources** across the **4 IP Intelligence Layers** ingested by `dgip`, how conflicting or overlapping records are resolved into canonical lookup tables, and how network operators can update upstream records.

---

## 1. Zero-Commercial-Aggregator Provenance Guarantee

`dgip` compiles all Autonomous System (ASN), cryptographic RPKI route validation, sub-national/cloud geolocation, and security/threat datasets directly from primary public Internet number registries, route collectors, RPKI validators, first-party network operator geofeeds, and open threat feeds:

- **Zero commercial geolocation brokers or paid APIs.**
- **Zero opaque third-party GitHub scraper repositories.**
- **One-time optional fast bootstrap**: On an empty database (`dgip_state.initial_bootstrapped = FALSE`), `dgip` downloads the latest signed `bundle.tar.gz` from Daviante's own public release repository (`https://github.com/daviante-org/dgip-data`) so the API becomes ready in ~35 seconds, then switches permanently to direct synchronization against the 25 upstream feeds. Operators wishing to build the very first release straight from upstream origins can set `dgip config set bootstrap_enabled=false` (or `DGIP_INITIAL_BOOTSTRAP_URL=""`).

---

## 2. The 4 Open IP Intelligence Layers (25 Default Feeds)

### Layer 1 — Authoritative RIR Country Delegations & RIPE RIS BGP (8 Feeds)

| Feed Key | Kind | Source | Authoritative HTTPS URL |
| :--- | :--- | :--- | :--- |
| `rir-arin` | `rir_delegated` | **ARIN** (North America) | `https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest` *(25s stall fallback to `ftp.ripe.net`)* |
| `rir-ripencc` | `rir_delegated` | **RIPE NCC** (Europe, Middle East, Central Asia) | `https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest` |
| `rir-apnic` | `rir_delegated` | **APNIC** (Asia-Pacific) | `https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest` *(25s stall fallback to `ftp.ripe.net`)* |
| `rir-lacnic` | `rir_delegated` | **LACNIC** (Latin America & Caribbean) | `https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest` *(25s stall fallback to `ftp.ripe.net`)* |
| `rir-afrinic` | `rir_delegated` | **AFRINIC** (Africa) | `https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest` *(25s stall fallback to `ftp.ripe.net`)* |
| `ris-bgp-ipv4` | `ris_bgp` | **RIPE NCC RIS** (`rrc00`–`rrc26` IPv4 BGP) | `https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz` |
| `ris-bgp-ipv6` | `ris_bgp` | **RIPE NCC RIS** (`rrc00`–`rrc26` IPv6 BGP) | `https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz` |
| `ripe-asnames` | `asn_names` | **RIPE NCC** Registered AS Organization Names | `https://ftp.ripe.net/ripe/asnames/asn.txt` |

### Layer 2 — Cloud Regional & Operator RFC 8805 Geofeeds (7 Feeds)
Hyperscale clouds register entire `/8`–`/12` supernets to corporate headquarters (for example `US` in ARIN) while deploying physical servers in Mumbai, Tokyo, Frankfurt, or Sydney. Layer 2 overlays first-party operator feeds onto Layer 1 RIR delegations (`geo.source = "geofeed"`), resolving physical `country_code`, ISO 3166-2 `region_code`, and `city`:

| Feed Key | Kind | Operator | Authoritative HTTPS URL |
| :--- | :--- | :--- | :--- |
| `geo-aws` | `geofeed_rfc8805` | **Amazon Web Services (AWS)** | `https://ip-ranges.amazonaws.com/geo-ip-feed.csv` |
| `geo-gcp` | `cloud_gcp_json` | **Google Cloud Platform (GCP)** | `https://www.gstatic.com/ipranges/cloud.json` |
| `geo-oracle` | `cloud_oracle_json` | **Oracle Cloud Infrastructure (OCI)** | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` |
| `geo-digitalocean` | `geofeed_rfc8805` | **DigitalOcean** | `https://digitalocean.com/geo/google.csv` |
| `geo-linode` | `geofeed_rfc8805` | **Akamai Connected Cloud / Linode** | `https://geoip.linode.com/` |
| `geo-vultr` | `geofeed_rfc8805` | **Vultr / Constant** | `https://geofeed.constant.com/` |
| `geo-apple-relay` | `geofeed_rfc8805` | **Apple iCloud Private Relay** | `https://mask-api.icloud.com/egress-ip-ranges.csv` |

### Layer 3 — RPKI Route Origin Validation & ASN Classification (2 Feeds)

| Feed Key | Kind | Source | Authoritative HTTPS URL |
| :--- | :--- | :--- | :--- |
| `rpki-vrps` | `rpki_vrps_csv` | **OpenBSD `rpki-client` Public Console** (5 RIR Trust Anchors) | `https://console.rpki-client.org/vrps.csv` |
| `asn-classes` | `asn_classes_csv` | **bgp.tools** Global AS Classification & Fallback Names | `https://bgp.tools/asns.csv` |

### Layer 4 — CDN, Cloud, Tor Exit, Privacy Relay & Threat Intelligence (8 Dedicated Feeds + Cloud/Relay Feeds)

| Feed Key | Kind | Signal | Authoritative HTTPS URL |
| :--- | :--- | :--- | :--- |
| `cdn-cloudflare-v4` | `cdn_cidr_list` | `is_cdn`, `is_cloud` (`provider="cloudflare"`) | `https://www.cloudflare.com/ips-v4` |
| `cdn-cloudflare-v6` | `cdn_cidr_list` | `is_cdn`, `is_cloud` (`provider="cloudflare"`) | `https://www.cloudflare.com/ips-v6` |
| `cdn-fastly` | `cdn_fastly_json` | `is_cdn`, `is_cloud` (`provider="fastly"`) | `https://api.fastly.com/public-ip-list` |
| `cloud-github` | `cloud_github_json` | `is_cloud`, `is_datacenter` (`provider="github"`) | `https://api.github.com/meta` |
| `threat-tor-exit` | `tor_exit_list` | `is_tor_exit` | `https://check.torproject.org/torbulkexitlist` |
| `threat-spamhaus-drop-v4` | `spamhaus_drop_json` | `is_threat` (`spamhaus_drop`) | `https://www.spamhaus.org/drop/drop_v4.json` |
| `threat-spamhaus-drop-v6` | `spamhaus_drop_json` | `is_threat` (`spamhaus_drop`) | `https://www.spamhaus.org/drop/drop_v6.json` |
| `threat-feodo-c2` | `threat_ip_list` | `is_threat` (`feodo_c2` botnet C2s) | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` |

*(Plus `aws`, `gcp`, `oracle`, `digitalocean`, `linode`, `vultr`, and `apple_icloud_relay` ranges extracted automatically from the Layer 2 feeds above.)*

---

## 3. Filtering, Hygiene & Resolution Pipeline

1. **Completeness, Decompression Bounds & Graceful Enrichment Resilience**:
   - Every feed enforces `max_compressed_bytes`, `max_uncompressed_bytes`, and `min_records`.
   - Core Layer 1 feeds (`rir_delegated`, `ris_bgp`, `asn_names`) are strictly required; if any core feed fails or is truncated, the sync aborts without touching the active Blue/Green slot.
   - Optional Layer 2–4 enrichment feeds default to graceful resilience (`enrichment_strict = false`): a transient outage on a single threat list logs a warning without blocking daily RIR/BGP updates (set `dgip config set enrichment_strict=true` for fail-closed behavior).
2. **Cryptographic RPKI Route Origin Validation (`RFC 6811` & `RFC 7607`)**:
   - Every RIPE RIS BGP `(prefix, origin_asn)` announcement is validated against covering Validated ROA Payloads (`vrps.csv`):
     - `valid`: Covered by a matching `(ASN, maxLength)` ROA.
     - `invalid`: Covered by one or more ROAs (including `AS0` SLURM/unallocated ROAs per RFC 7607), and none authorize `(origin_asn, prefixlen)`. When `rpki_reject_invalid = true` (default), RPKI-invalid BGP hijacks and route leaks are **dropped during compilation**!
     - `unknown`: Not covered by any published ROA.
   - When multiple valid/unknown origins announce the exact same prefix, `valid` outranks `unknown`, followed by highest RIS peer count, then lowest ASN.
3. **Longest-Prefix-Wins Flattening & `O(N + M)` Geofeed Priority Overlay**:
   - Within Layer 1 RIRs and within Layer 2 Geofeeds, overlapping prefixes are flattened via stack-based Longest-Prefix-Match (`flatten_binary_cidrs`).
   - Layer 2 physical regional intervals are then overlaid onto Layer 1 RIR intervals (`overlay_disjoint_intervals`) so physical datacenter/POP country, ISO 3166-2 region, and city win unconditionally over corporate headquarters registrations while preserving uncovered sibling ranges.
4. **Multi-Label Security Coordinate Sweep-Line (`merge_security_intervals`)**:
   - Unlike country or origin ASN (where each IP has one winner), an IP can simultaneously be a cloud VM, a GitHub Actions runner, a Tor exit node, and listed on Spamhaus DROP.
   - `merge_security_intervals` sweeps all interval start/end coordinates in `O(N log N)` time, bitwise-ORing all active flags (`is_cloud`, `is_datacenter`, `is_cdn`, `is_tor_exit`, `is_privacy_relay`, `is_threat`), selecting the highest-specificity `provider` (edge/app overlays like `apple_icloud_relay`, `cloudflare`, `fastly`, `github` outrank underlying IaaS supernets like `aws`), and collecting sorted `threat_feeds`.
5. **Special-Purpose / Bogon Exclusion (`dgip_special_ranges`)**:
   - All IANA RFC 6890 / RFC 4291 special-purpose ranges are stripped from all 4 layers during compilation and classified in memory at query time (`is_bogon: true`, `bogon_type: "<category>"`).

---

## 4. Published Artifact Specifications

Every weekly release (`vYYYY.Www`) produces **10 dataset artifacts** plus `bundle.tar.gz`, `manifest.json`, and `SHA256SUMS.txt`:

| File | Standard | Schema / Contents |
| :--- | :--- | :--- |
| `dgip-asn-ipv4.csv.gz` | RFC 4180 CSV (`gzip`) | Headerless UTF-8 (6 cols): `start_ip,end_ip,asn,asn_org,network_type,rpki_status` |
| `dgip-asn-ipv6.csv.gz` | RFC 4180 CSV + RFC 5952 (`gzip`) | Headerless UTF-8 (6 cols): `start_ip,end_ip,asn,asn_org,network_type,rpki_status` |
| `dgip-country-ipv4.csv.gz` | RFC 4180 CSV (`gzip`) | Headerless UTF-8 (6 cols): `start_ip,end_ip,country_code,region_code,city,geo_source` |
| `dgip-country-ipv6.csv.gz` | RFC 4180 CSV + RFC 5952 (`gzip`) | Headerless UTF-8 (6 cols): `start_ip,end_ip,country_code,region_code,city,geo_source` |
| `dgip-security-ipv4.csv.gz` | RFC 4180 CSV (`gzip`) | Headerless UTF-8 (10 cols): `start_ip,end_ip,is_cloud,is_datacenter,is_cdn,is_tor_exit,is_privacy_relay,is_threat,provider,threat_feeds` |
| `dgip-security-ipv6.csv.gz` | RFC 4180 CSV + RFC 5952 (`gzip`) | Headerless UTF-8 (10 cols): `start_ip,end_ip,is_cloud,is_datacenter,is_cdn,is_tor_exit,is_privacy_relay,is_threat,provider,threat_feeds` |
| `dgip-geofeed.csv.gz` | IETF RFC 8805 (`gzip`) | `ip_prefix,country_code,region_code,city,` covering all IPv4 & IPv6 geolocation CIDRs |
| `dgip-asn.mmdb` | MaxMind DB Binary v2.0 | Dual-stack `GeoLite2-ASN` compatible tree (+ `network_type` & `rpki_status`) |
| `dgip-country.mmdb` | MaxMind DB Binary v2.0 | Dual-stack `GeoLite2-Country` / `City` compatible tree (+ `subdivisions`, `city`, `source`) |
| `dgip-security.mmdb` | MaxMind DB Binary v2.0 | Dual-stack `DGIP-Security` radix tree (`is_cloud`, `is_cdn`, `is_tor_exit`, `is_threat`, `provider`, `threat_feeds`) |
| `bundle.tar.gz` | POSIX.1-2001 PAX `tar.gz` | Deterministic archive containing `manifest.json` + all 10 dataset files |
| `manifest.json` | RFC 8259 JSON | Build timestamp, version, source attribution, record counts, and SHA-256 digests |
| `SHA256SUMS.txt` | GNU `sha256sum` | Checksum manifest for `sha256sum -c SHA256SUMS.txt` |

---

## 5. Upstream Attribution & Operator Correction Policy

### Source Attribution
Every `manifest.json` and snapshot metadata response carries explicit attribution:
> *Compiled by Daviante (https://daviante.org) from public Regional Internet Registry delegations (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC), RIPE NCC RIS BGP routing tables, OpenBSD rpki-client RPKI VRPs, bgp.tools AS classifications, RFC 8805 operator/cloud geofeeds, and open network security feeds (Tor Project, Spamhaus DROP, Abuse.ch Feodo Tracker).*

### How Network Operators & LIRs Request Corrections
Daviante does **not** maintain ad-hoc manual IP geolocation overrides. Network operators seeking to update country, sub-national location, or ASN metadata for prefixes they administer should:
1. Update the `country:` and `geofeed:` (`RFC 9092` / `RFC 8805`) attributes on the authoritative `inetnum` / `inet6num` / `NetRange` registration object at **ARIN, RIPE NCC, APNIC, LACNIC, or AFRINIC**.
2. Publish matching cryptographic **RPKI ROAs** for intended origin ASNs so BGP announcements validate as `rpki_status: "valid"`.

Once published upstream, updates propagate automatically into `dgip`'s next 24-hour live sync and Monday `02:00 UTC` snapshot release. Compiler bugs may be reported to `code@daviante.org`.
