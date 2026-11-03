# Data Sources, Ownership, Credits & Legal Attribution

**Project:** `daviante-org/dgip` (`https://dgip.daviante.org`)  
**Maintainer:** Daviante (`https://daviante.org`)  
**Legal & Provenance Contact:** `code@daviante.org`

---

## 1. Ownership Statement & Scope of License

1. **Software Ownership (`Apache-2.0`)**: Daviante owns and licenses solely the **DGIP** Rust source code, schema definitions, normalization/sweep-line algorithms, container packaging, Helm charts, and documentation in this repository under the [Apache License, Version 2.0](./LICENSE).
2. **No Claim of Ownership Over Third-Party Data**: **Daviante does not claim copyright, sui generis database ownership, or proprietary title over any upstream registry allocations, BGP routing tables, RPKI cryptographic objects, cloud/operator geofeeds, or threat intelligence lists** fetched by `dgip` or compiled into [`daviante-org/dgip-data`](https://github.com/daviante-org/dgip-data). All underlying rights remain the property of their respective maintainers, Regional Internet Registries (RIRs), CSIRTs, and network operators listed below.
3. **No Sublicensing of Upstream Rights**: Nothing in this repository transfers, assigns, or sublicenses the intellectual property or database rights of any upstream data provider. Organizations redistributing compiled outputs or integrating `dgip` into commercial products are responsible for complying with the applicable public data policies of the underlying upstream sources.
4. **Nominative Attribution & Non-Endorsement**: Third-party names, marks, and domains are cited strictly to identify authoritative upstream data origins. Daviante is an independent project and is **not** affiliated with, sponsored by, or endorsed by any of the organizations listed below.

---

## 2. Complete Upstream Data Inventory & Credits (25 Feeds Across 4 Layers)

### 2.1 Layer 1 — Regional Internet Registries (NRO) & Global BGP Routing

| Feed Key | Upstream Owner / Legal Entity | Canonical Endpoint / Reference | License / Public Data Governance |
| :--- | :--- | :--- | :--- |
| `rir-arin` | **American Registry for Internet Numbers, Ltd. (ARIN)** | `https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest` | Public NRO Extended Delegation Statistics ([ARIN Statistics](https://www.arin.net/resources/registry/statistics/)) |
| `rir-ripencc` | **Réseaux IP Européens Network Coordination Centre (RIPE NCC)** | `https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest` | Public NRO Extended Delegation Statistics ([RIPE NCC Legal / Public Data](https://www.ripe.net/about-us/legal/)) |
| `rir-apnic` | **Asia-Pacific Network Information Centre Pty Ltd (APNIC)** | `https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest` | Public NRO Extended Delegation Statistics ([APNIC FTP Site Terms of Use](https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/apnic-ftp-site-terms-of-use/)) |
| `rir-lacnic` | **Latin America and Caribbean Network Information Centre (LACNIC)** | `https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest` | Public NRO Extended Delegation Statistics ([LACNIC Statistics](https://www.lacnic.net/)) |
| `rir-afrinic` | **African Network Information Centre (AFRINIC) Ltd** | `https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest` | Public NRO Extended Delegation Statistics ([AFRINIC Statistics](https://afrinic.net/)) |
| `ris-bgp-ipv4` · `ris-bgp-ipv6` | **RIPE NCC — Routing Information Service (RIS)** | `https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz` · `riswhoisdump.IPv6.gz` | Public BGP Route Collector Data (`rrc00`–`rrc26`, [RIPE RIS](https://ris.ripe.net/)) |
| `ripe-asnames` | **RIPE NCC** | `https://ftp.ripe.net/ripe/asnames/asn.txt` | Public RIR Autonomous System Registry Metadata |

### 2.2 Layer 2 — First-Party Cloud & Operator Geofeeds (`IETF RFC 8805`)

These machine-readable IP range and `RFC 8805` self-published geofeed files are published directly by each network operator so routing systems, firewalls, and geolocation consumers resolve physical datacenter/POP locations accurately rather than corporate headquarters addresses:

| Feed Key | Network Operator / Owner | Canonical Endpoint | Publication Purpose / Standard |
| :--- | :--- | :--- | :--- |
| `geo-aws` | **Amazon Web Services, Inc. (AWS)** | `https://ip-ranges.amazonaws.com/geo-ip-feed.csv` | Self-published `RFC 8805` regional geofeed |
| `geo-gcp` | **Google LLC (Google Cloud Platform)** | `https://www.gstatic.com/ipranges/cloud.json` | Published GCP regional IP ranges JSON |
| `geo-oracle` | **Oracle America, Inc. (Oracle Cloud Infrastructure)** | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` | Published OCI regional public IP ranges JSON |
| `geo-digitalocean` | **DigitalOcean, LLC** | `https://digitalocean.com/geo/google.csv` | Self-published `RFC 8805` regional geofeed |
| `geo-linode` | **Akamai Technologies, Inc. / Linode LLC** | `https://geoip.linode.com/` | Self-published `RFC 8805` regional geofeed |
| `geo-vultr` | **The Constant Company, LLC (Vultr)** | `https://geofeed.constant.com/` | Self-published `RFC 8805` regional geofeed |
| `geo-apple-relay` | **Apple Inc. (iCloud Private Relay)** | `https://mask-api.icloud.com/egress-ip-ranges.csv` | Self-published `RFC 8805` egress geofeed ([Apple Support Documentation](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/)) |

### 2.3 Layer 3 — Cryptographic RPKI Route Origin Validation & AS Taxonomy

| Feed Key | Upstream Project / Owner | Canonical Endpoint | License / Terms |
| :--- | :--- | :--- | :--- |
| `rpki-vrps` | **The OpenBSD Project — `rpki-client`** | `https://console.rpki-client.org/vrps.csv` | Public RPKI Validated ROA Payloads (`RFC 6811` / `RFC 7607`) aggregated across the 5 RIR Trust Anchors (`rpki-client` software is ISC-licensed) |
| `asn-classes` | **bgp.tools (Port 179 Ltd / Ben Cox)** | `https://bgp.tools/asns.csv` | Public AS classification export (`User-Agent` contact header & caching limits honored per [`bgp.tools/kb/api`](https://bgp.tools/kb/api)) |

### 2.4 Layer 4 — Edge CDN Ranges, Tor Consensus & Open Threat Intelligence

| Feed Key | Upstream Maintainer / Owner | Canonical Endpoint | License / Attribution Requirements |
| :--- | :--- | :--- | :--- |
| `cdn-cloudflare-v4` · `cdn-cloudflare-v6` | **Cloudflare, Inc.** | `https://www.cloudflare.com/ips-v4` · `ips-v6` | Published edge proxy IPv4/IPv6 CIDR lists |
| `cdn-fastly` | **Fastly, Inc.** | `https://api.fastly.com/public-ip-list` | Published edge POP IPv4/IPv6 CIDR list |
| `cloud-github` | **GitHub, Inc.** | `https://api.github.com/meta` | Published GitHub infrastructure CIDR metadata |
| `threat-tor-exit` | **The Tor Project, Inc.** | `https://check.torproject.org/torbulkexitlist` | Public Tor network consensus exit relay addresses |
| `threat-spamhaus-drop-v4` · `threat-spamhaus-drop-v6` | **The Spamhaus Project** (`© The Spamhaus Project`) | `https://www.spamhaus.org/drop/drop_v4.json` · `drop_v6.json` | **Free with Attribution**: Provided free of charge by **The Spamhaus Project** ([Spamhaus DROP](https://www.spamhaus.org/drop/)). Copyright and database rights remain with The Spamhaus Project; fair-use polling intervals are strictly enforced. |
| `threat-feodo-c2` | **abuse.ch** (Institute for Cybersecurity and Engineering ICE, Bern University of Applied Sciences) | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | **CC0 1.0 Universal (Public Domain)** ([Feodo Tracker](https://feodotracker.abuse.ch/)) |

---

## 3. Open Format & Protocol Specifications

- **MaxMind DB File Format Specification v2.0 (`.mmdb`)**:
  - Specification authored by **MaxMind, Inc.** (`https://maxmind.github.io/MaxMind-DB/`) and licensed under the **Creative Commons Attribution-ShareAlike 3.0 Unported License (`CC BY-SA 3.0`)** (`https://creativecommons.org/licenses/by-sa/3.0/`).
  - `dgip` (`src/mmdb.rs`) is an independent, clean-room Rust implementation of the open `.mmdb` binary container specification so standard `libmaxminddb` readers work out of the box. **Zero MaxMind GeoLite2 or GeoIP2 database content is used or distributed.** `MaxMind` and `GeoIP` are registered trademarks of MaxMind, Inc.
- **IETF & IANA Standards**:
  - **IANA Special-Purpose IP Address Registries** (`RFC 6890`, `RFC 4291`), **Self-Published IP Geolocation Feeds** (`RFC 8805`, `RFC 9092`), **RPKI BGP Prefix Origin Validation** (`RFC 6811`, `RFC 7607`), **IPv6 Canonical Text Representation** (`RFC 5952`), and **Problem Details for HTTP APIs** (`RFC 9457`).

---

## 4. Rights-Holder & Attribution Inquiries

We respect the work, infrastructure, and licensing terms of every registry, CSIRT, researcher, and network operator whose open publications make `dgip` possible. If you represent an upstream data provider and wish to request an updated attribution notice, polling adjustment, or removal of a feed URL from default configuration, please contact **`code@daviante.org`**.
