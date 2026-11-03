# Configuration Reference (Environment, Helm & PostgreSQL Catalog)

`dgip` separates **process bootstrap settings** (environment variables read once at container startup) from **operational runtime configuration** (stored in PostgreSQL and hot-reloaded within `2s` across all replicas without restarting pods).

---

## 1. Container Bootstrap Environment Variables (`DGIP_*`)

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `DGIP_DATABASE_URL` | `str` | `postgresql://dgip:dgip@localhost:5432/dgip` | PostgreSQL 17+ connection URI (`?sslmode=require` supported for managed/external DBs). |
| `DGIP_DB_POOL_MIN_SIZE` | `int` (`1..64`) | `2` | Minimum pool configuration bound for `deadpool-postgres`. |
| `DGIP_DB_POOL_MAX_SIZE` | `int` (`2..256`) | `16` | Maximum open connections in `deadpool-postgres` (live sync bulk loads open a separate dedicated connection). |
| `DGIP_HOST` | `str` | `0.0.0.0` | Axum HTTP bind address. |
| `DGIP_PORT` | `int` (`1..65535`) | `8090` | Axum HTTP bind port. |
| `DGIP_SWAGGER_ENABLED` | `bool` | `true` | Master process gate for `/docs`, `/openapi.json`, and `/docs/assets/*`. When `false`, docs return `404` regardless of DB settings. |
| `DGIP_ASSETS_DIR` | `path` | `/app/assets` | Filesystem directory containing `logo.svg`, `logo-dark.svg`, and `favicon.svg`. |
| `DGIP_CACHE_DIR` | `path` | `/tmp/dgip-cache` | Writable scratch directory hydrated on demand from `dgip_release_files` (`BYTEA`). |
| `DGIP_CATALOG_POLL_SECONDS` | `float` (`0.2..300`) | `2.0` | Maximum interval between `dgip_state.catalog_version` checks on active HTTP workers. |
| `DGIP_INITIAL_BOOTSTRAP_URL` | `str` | `https://github.com/daviante-org/dgip-data/releases/latest/download/bundle.tar.gz` | Seeded strictly once into `dgip_config.bootstrap_bundle_url` on an empty database. |
| `DGIP_INITIAL_SNAPSHOT_RETENTION` | `int` (`1..52`) | `5` | Seeded strictly once into `dgip_config.snapshot_retention` on an empty database. |
| `DGIP_CORS_ALLOW_ORIGINS` | `str` | `*` | Comma-separated allowed CORS origins (`*` for public read-only APIs, or empty to disable CORS). |
| `DGIP_ALLOW_LOCAL_FILES` | `bool` | `false` | Permits `file://` URLs strictly for offline unit test fixtures. Keep `false` in production. |

---

## 2. Dynamic Runtime Catalog (`dgip_config`)

Inspect or update any key below at runtime using `dgip config list`, `dgip config get <key>`, or `dgip config set <key>=<value>`. Statement-level PostgreSQL triggers increment `dgip_state.catalog_version`, and all running HTTP workers hot-reload changes within `DGIP_CATALOG_POLL_SECONDS` (`2.0s`).

| Key | Type & Valid Range | Default | Description |
| :--- | :--- | :--- | :--- |
| `bootstrap_enabled` | `bool` | `true` | Perform one-time fast bootstrap from `bootstrap_bundle_url` when `initial_bootstrapped = FALSE`. |
| `bootstrap_bundle_url` | `https://` URL (or `""`) | `https://github.com/daviante-org/dgip-data/releases/latest/download/bundle.tar.gz` | Archive URL used strictly once on initial empty-database startup. |
| `live_sync_interval_seconds` | `int` (`0..31536000`) | `86400` | Seconds between automatic Blue/Green live lookup refreshes from RIR/RIPE feeds (`0` disables). |
| `weekly_release_enabled` | `bool` | `true` | Enable scheduled weekly snapshot compilation into `dgip_releases` / `dgip_release_files`. |
| `weekly_release_weekday` | `int` (`0..6`) | `0` | UTC weekday to evaluate and cut weekly snapshots (`0` = Monday .. `6` = Sunday). |
| `weekly_release_utc_hour` | `int` (`0..23`) | `2` | UTC hour on `weekly_release_weekday` to evaluate and cut a snapshot (`02:00 UTC`). |
| `version_prefix` | `str` (`1..1024` chars) | `"v"` | Prefix prepended to ISO-8601 week codes (`v2026.W45`). |
| `release_title_template` | `str` (`1..1024` chars) | `"{version}"` | Release title template supporting `{version}` and `{date}`. |
| `snapshot_retention` | `int` (`1..100`) | `5` | Number of weekly snapshot binary blob sets retained in `dgip_release_files` and `/tmp/dgip-cache`. |
| `bgp_min_peers` | `int` (`1..10000`) | `5` | Minimum RIPE RIS BGP peer visibility count required to accept a BGP origin announcement. |
| `bgp_ipv4_min_prefixlen` | `int` (`1..32`) | `8` | Minimum IPv4 BGP prefix length accepted (rejects `0.0.0.0/0` default leaks). |
| `bgp_ipv6_min_prefixlen` | `int` (`1..128`) | `12` | Minimum IPv6 BGP prefix length accepted (rejects `::/0` default leaks). |
| `rpki_reject_invalid` | `bool` | `true` | Drop BGP route announcements that fail cryptographic RFC 6811 / RFC 7607 RPKI Route Origin Validation (`invalid`). |
| `enrichment_strict` | `bool` | `false` | When `false`, transient unavailability of an optional Layer 2–4 enrichment feed logs a warning without aborting Layer 1 RIR/RIS syncs. |
| `http_timeout_seconds` | `float` (`1.0..3600.0`) | `180.0` | Per-feed HTTPS download timeout in seconds (after `25s` primary RIR stall fallback check). |
| `max_redirects` | `int` (`0..20`) | `5` | Maximum HTTPS redirect hops allowed per upstream download (each hop SSRF-validated). |
| `upstream_user_agent` | `str` (`1..1024` chars) | `"DGIP/1.0 (+https://daviante.org; mailto:code@daviante.org)"` | `User-Agent` header sent when fetching public RIR/RIPE feeds. |
| `source_attribution` | `str` (`1..1024` chars) | `"Compiled by Daviante..."` | Attribution text embedded in `manifest.json` and snapshot API responses. |
| `asn_min_valid` | `int` (`1..4294967294`) | `1` | Minimum valid RFC 6793 Autonomous System Number. |
| `asn_max_valid` | `int` (`1..4294967294`) | `4294967294` | Maximum valid RFC 6793 Autonomous System Number. |
| `rate_limit_per_minute` | `int` (`1..1000000`) | `120` | Per-IP sliding-window request limit per window for lookup and metadata endpoints. |
| `download_rate_limit_per_minute` | `int` (`1..1000000`) | `30` | Per-IP sliding-window request limit per window for binary snapshot downloads. |
| `rate_limit_window_seconds` | `float` (`1.0..86400.0`) | `60.0` | Sliding-window duration in seconds for rate limiters. |
| `rate_limit_max_keys` | `int` (`128..5000000`) | `50000` | Maximum distinct client IPs tracked in memory before LRU eviction. |
| `max_batch_size` | `int` (`1..10000`) | `1000` | Maximum IP addresses accepted in a single `POST /v1/ip/batch` call. |
| `max_request_body_bytes` | `int` (`4096..16777216`) | `262144` | Maximum HTTP request body size (`256 KiB` default) enforced on both `Content-Length` and chunked streams. |
| `trusted_proxies` | `list[CIDR]` (`<= 512`) | `[]` | Trusted reverse-proxy CIDRs permitted to supply `X-Forwarded-For` (walked right-to-left). |
| `snapshot_latest_cache_max_age` | `int` (`0..315360000`) | `60` | `Cache-Control: max-age` seconds for `GET /v1/snapshots/latest`. |
| `snapshot_immutable_cache_max_age` | `int` (`0..315360000`) | `31536000` | `Cache-Control: max-age` seconds for immutable versioned snapshot artifacts (`1 year`). |
| `swagger_enabled` | `bool` | `true` | Live runtime toggle for `/docs` and `/openapi.json` (when `DGIP_SWAGGER_ENABLED=true`). |

---

## 3. Helm Chart Key Values (`charts/dgip/values.yaml`)

| Helm Value | Default | Description |
| :--- | :--- | :--- |
| `replicaCount` | `2` | Number of stateless DGIP API pods. |
| `image.repository` | `ghcr.io/daviante-org/dgip` | Official GHCR multi-arch container image. |
| `swagger.enabled` | `true` | Sets `DGIP_SWAGGER_ENABLED` on API pods. |
| `config.dbPoolMinSize` / `dbPoolMaxSize` | `2` / `16` | Async PostgreSQL connection pool sizing per pod. |
| `config.catalogPollSeconds` | `2.0` | Interval for checking `dgip_state.catalog_version`. |
| `database.internal.enabled` | `true` | Deploy bundled PostgreSQL 17 StatefulSet (`false` uses `database.external.*`). |
| `database.internal.persistence.size` | `10Gi` | PVC storage size for bundled PostgreSQL. |
| `database.external.existingSecret` | `""` | Pre-existing Secret containing `database-url` when `database.internal.enabled=false`. |
| `openshift.enabled` | `false` | Omit hardcoded `runAsUser`/`runAsGroup`/`fsGroup` for OpenShift `restricted-v2` SCC. |
| `openshift.route.enabled` | `false` | Create native `route.openshift.io/v1` Edge-TLS Route (`openshift.route.host`). |
| `ingress.enabled` | `false` | Create standard `networking.k8s.io/v1` Ingress. |
| `autoscaling.enabled` | `false` | Enable HorizontalPodAutoscaler (`minReplicas` / `maxReplicas`). |
| `pdb.enabled` | `true` | Create `PodDisruptionBudget` (`minAvailable: 1`). |
| `networkPolicy.enabled` | `false` | Create Kubernetes `NetworkPolicy` scoping pod ingress to TCP `8090`. |

---

## 4. Upstream Feeds & SSRF Allowlist Tables

- **`dgip_feed_sources` (`dgip feed list`)**: Stores all 25 Layer 1–4 feeds (`rir-*`, `ris-bgp-*`, `ripe-asnames`, `geo-*`, `rpki-vrps`, `asn-classes`, `cdn-*`, `cloud-github`, `threat-*`) across 14 parser kinds with per-feed `min_records`, `max_compressed_bytes`, and `max_uncompressed_bytes` caps.
- **`dgip_allowed_hosts` (`dgip host list`)**: Enforces exact lowercase FQDN allowlisting across all 26 default upstream HTTPS hosts (RIRs, RIPE RIS, `console.rpki-client.org`, `bgp.tools`, cloud/CDN geofeed hosts, Tor Project, Spamhaus, Abuse.ch, and GitHub Release CDN hosts).
