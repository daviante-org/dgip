# Terms of Use

**Effective Date:** November 2, 2026  
**Maintainer:** Daviante (`https://daviante.org`)  
**Contact:** `code@daviante.org`

By using the `dgip` software (`daviante-org/dgip`), querying the Daviante-hosted public API (`https://dgip.daviante.org`), or downloading datasets published in `daviante-org/dgip-data`, you agree to these Terms of Use.

---

## 1. Software, Dataset Licensing & Upstream Ownership

1. **Application Software (`daviante-org/dgip`)**: Source code, container definitions, Helm charts, deployment manifests, and documentation in this repository are licensed under the **Apache License, Version 2.0** ([`LICENSE`](../LICENSE), [`NOTICE`](../NOTICE)). You may self-host, modify, and distribute `dgip` in accordance with the Apache-2.0 license, including preserving the attribution notices in [`NOTICE`](../NOTICE).
2. **Published Datasets (`daviante-org/dgip-data`)**: Daviante's compilation work in weekly dataset snapshots (`bundle.tar.gz`, `.csv.gz`, `.mmdb`) distributed via `daviante-org/dgip-data` is dedicated under the Open Data Commons Public Domain Dedication and License (**PDDL v1.0**), strictly subject to upstream Regional Internet Registry, BGP collector, cloud provider, and threat-intelligence terms documented in [`CREDITS.md`](../CREDITS.md), [`NOTICE`](../NOTICE), and [`SOURCES_AND_DATA_POLICY.md`](./SOURCES_AND_DATA_POLICY.md).
3. **No Claim of Upstream Ownership**: Daviante does **not** claim ownership over third-party upstream registry records, routing tables, geofeed files, or security blocklists, and does **not** transfer or sublicense rights belonging to upstream providers.

---

## 2. Acceptable Use of the Hosted Public API (`https://dgip.daviante.org`)

Daviante operates `https://dgip.daviante.org` as an open, unauthenticated public utility for developers, operators, and automated weekly dataset synchronization:

1. **Respect Rate Limits**: Automated callers must honor HTTP `429 Too Many Requests` responses, `Retry-After` intervals, and `X-RateLimit-*` headers.
2. **Use Local Snapshots for High-Volume Workloads**: Mail transfer agents (such as DGMail), reverse proxies, security gateways, analytics pipelines, and high-QPS services performing continuous or bulk lookups must download the weekly `.mmdb` or `.csv.gz` dataset releases (or self-host `dgip`) rather than sending sustained high-volume live traffic to `https://dgip.daviante.org`.
3. **Prohibited Conduct**: You may not attempt to degrade or disrupt service availability, evade per-IP rate limiters (e.g., through distributed proxy rotation), probe non-public infrastructure, or misrepresent modified datasets as unaltered official Daviante releases.

---

## 3. Geolocation and BGP Routing Accuracy Disclaimer

IP-to-country and IP-to-ASN mappings are administrative and topological approximations derived from public Regional Internet Registry delegation files and global Border Gateway Protocol (BGP) announcements:

- Allocated IP ranges may be announced over global anycast networks, cloud CDNs, VPNs, satellite constellations, mobile carrier gateways, or cross-border Local Internet Registry (LIR) sub-assignments that do not match the physical location or legal jurisdiction of an end user.
- BGP origin ASNs and organization names may change at any time due to IP transfers, leasing, traffic engineering, or transient routing anomalies prior to upstream registry convergence.

**High-Risk Use Restriction**: Neither `dgip`, `https://dgip.daviante.org`, nor `dgip-data` is designed, certified, or intended for emergency services routing (such as E911/E112), life-safety or medical systems, critical physical infrastructure control, or as sole dispositive proof of an individual's physical location or identity in legal, law-enforcement, or regulatory proceedings.

---

## 4. Disclaimer of Warranties and Limitation of Liability

THE SOFTWARE, DATASETS, AND HOSTED API ARE PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, AVAILABILITY, OR NON-INFRINGEMENT.

IN NO EVENT SHALL DAVIANTE, ITS MAINTAINERS, OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, LOSS OF USE, DATA, OR PROFITS, OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT, ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, DATASETS, OR HOSTED API, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

## 5. Updates and Contact

Daviante may revise these Terms of Use by publishing an updated version in this repository. Questions may be directed to `code@daviante.org`.
