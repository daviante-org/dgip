# Troubleshooting & Operational Runbook

This runbook organizes common deployment, networking, database, and synchronization issues by symptom, root cause, diagnostic command, and resolution.

---

## 1. Quick Diagnostic Checklist

Run these three commands first on any unhealthy instance (`docker exec`, `podman exec`, `kubectl exec`, or `oc exec`):

```bash
# 1. Inspect container liveness & readiness HTTP probes
curl -i http://127.0.0.1:8090/healthz/live
curl -i http://127.0.0.1:8090/healthz/ready

# 2. Inspect PostgreSQL state, active Blue/Green slot, and last sync/release errors
dgip status

# 3. Inspect active runtime configuration, feed URLs, and SSRF allowlist
dgip catalog
```

---

## 2. Startup & Database Connectivity Issues

### Symptom A: Container exits on startup with PostgreSQL connection failure
- **Log Signature**:
  `Database error: ... password authentication failed` (or `Connection refused`).
- **Root Cause**:
  `DGIP_DATABASE_URL` points to an unreachable host/port, uses the wrong password, or an old Docker/Podman volume (`dgip_pgdata`) was initialized earlier with a different `POSTGRES_PASSWORD`.
- **Resolution**:
  1. Verify `DGIP_DATABASE_URL` matches the credentials in PostgreSQL (`postgresql://<user>:<url-encoded-password>@<host>:5432/<db>`).
  2. Note that PostgreSQL only reads `POSTGRES_PASSWORD` when initializing an empty `PGDATA` volume; if you changed `.env` after creating `dgip_pgdata`, either update the role password in `psql` (`ALTER USER dgip WITH PASSWORD '...';`) or recreate a fresh volume if no data needs to be kept.

### Symptom B: `/healthz/ready` returns `503 Dataset Not Ready`
- **Response Detail**: `"Initial IP lookup slot is still loading."`
- **Root Cause**:
  On first boot against an empty database, `dgip` downloads `bundle.tar.gz` (~18 MB) from `daviante-org/dgip-data`, verifies SHA-256 digests, streams `COPY` into `slot_a`, and builds 4 GiST indexes (~30–45 seconds). If outbound HTTPS to `github.com` / `objects.githubusercontent.com` is blocked by a firewall, `dgip` falls back to compiling directly from RIR/RIPE feeds (~85 seconds).
- **Diagnostic**:
  Check container logs (`docker logs dgip` / `kubectl logs deploy/dgip`) and run `dgip status`.
- **Resolution**:
  - Wait ~40 seconds on initial startup (the Helm chart's `startupProbe` allows up to `300s` automatically).
  - If running in an air-gapped cluster without GitHub or RIR internet access, host `bundle.tar.gz` on an internal HTTPS server, allow its hostname with `dgip host allow internal-mirror.corp`, and set `DGIP_INITIAL_BOOTSTRAP_URL=https://internal-mirror.corp/bundle.tar.gz`.

---

## 3. Upstream Registry Synchronization Issues

### Symptom A: Upstream RIR `ReadTimeout` or slow download during `dgip sync`
- **Log Signature**:
  `Primary RIR feed rir-arin stalled/failed (...); falling back to official RIPE NCC NRO mirror https://ftp.ripe.net/pub/stats/arin/delegated-arin-extended-latest`
- **Explanation**:
  `ftp.arin.net` and `ftp.apnic.net` occasionally throttle single HTTPS connections to `~35 KB/s`. When `ftp.ripe.net` is enabled in `dgip_allowed_hosts` (enabled by default), `dgip` automatically switches to RIPE NCC's official NRO mirror after `25s` and completes the full 8-feed sync in ~80–90 seconds.
- **If Fallback Fails**:
  Run `dgip host list` and verify `[ALLOW] ftp.ripe.net` is enabled:
  ```bash
  dgip host allow ftp.ripe.net --notes "RIPE NCC official stats & NRO mirror"
  dgip config set http_timeout_seconds=240
  dgip sync --force
  ```

### Symptom B: `Outbound HTTPS host '<host>' is not in dgip_allowed_hosts`
- **Root Cause**:
  You updated a feed URL (`dgip feed set-url ...`) or `bootstrap_bundle_url` whose hostname (or CDN redirect target) is not in `dgip_allowed_hosts`.
- **Resolution**:
  Add the exact lowercase FQDN (and any HTTPS redirect CDN host) via CLI:
  ```bash
  dgip host allow mirror.example.org --notes "Approved corporate RIR mirror"
  ```

### Symptom C: `Feed '<key>' yielded only N valid records (< min_records M)`
- **Root Cause**:
  An upstream registry published a truncated file during maintenance. `dgip` intentionally aborts the sync **before** modifying the inactive slot, leaving your live API serving the previous healthy slot uninterrupted.
- **Resolution**:
  Wait for the next scheduled sync or re-run `dgip sync` once upstream recovers. Only lower `--min-records` (`dgip feed set-url <key> <url> --min-records ...`) if testing a synthetic fixture.

### Symptom D: `dgip sync` reports `status = already_running`
- **Root Cause**:
  Another API replica or CLI session currently holds `pg_try_advisory_lock(5063961992970600449)`. PostgreSQL session-level advisory locks release automatically as soon as the holding connection closes (even if a pod crashes).
- **Diagnostic**:
  Inspect active lock holders in PostgreSQL if a connection appears hung:
  ```sql
  SELECT pid, application_name, state, query_start
  FROM pg_stat_activity
  WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype = 'advisory');
  ```

---

## 4. Rate Limiting, Reverse Proxies & HTTP Errors

### Symptom A: All external users hit `429 Too Many Requests` simultaneously
- **Root Cause**:
  `dgip` is deployed behind NGINX, Caddy, Traefik, AWS ALB, Cloudflare, or a Kubernetes/OpenShift Ingress controller, **and** `trusted_proxies` is still `[]` (empty). For security against `X-Forwarded-For` header spoofing, `dgip` ignores `X-Forwarded-For` unless the TCP peer IP matches `trusted_proxies`, causing every request from the ingress proxy IP to share one rate-limit bucket!
- **Resolution**:
  Configure your reverse-proxy / cluster pod network CIDR via `dgip config set` (takes effect within `2s`, zero restart):
  ```bash
  # Example: trust internal Kubernetes/proxy networks 10.0.0.0/8 and 172.16.0.0/12
  dgip config set trusted_proxies=10.0.0.0/8,172.16.0.0/12
  ```

### Symptom B: `/docs` or `/openapi.json` returns `404 Documentation Disabled`
- **Root Cause**:
  Swagger UI is gated by **both** the container environment variable `DGIP_SWAGGER_ENABLED` and the runtime catalog key `swagger_enabled`. If either is `false`, `/docs`, `/openapi.json`, and `/docs/assets/*` return `404`.
- **Resolution**:
  1. Check `dgip config get swagger_enabled` -> if `false`, run `dgip config set swagger_enabled=true`.
  2. Ensure container env `DGIP_SWAGGER_ENABLED=true` (or Helm `--set swagger.enabled=true`).

### Symptom C: Snapshot file download returns `410 Gone` (`Snapshot Artifacts Expired`)
- **Root Cause**:
  `dgip` retains full binary `BYTEA` blobs for the latest `snapshot_retention` releases (default `5` weeks) to keep PostgreSQL storage bounded, while preserving historical metadata rows in `dgip_releases`.
- **Resolution**:
  Download older historical archives from permanent GitHub Releases at `https://github.com/daviante-org/dgip-data/releases`, or increase retention going forward with `dgip config set snapshot_retention=12`.

### Symptom D: `POST /v1/ip/batch` returns `413 Payload Too Large` or `400 Batch Size Exceeded`
- **Root Cause**:
  Request body exceeded `max_request_body_bytes` (`262,144` bytes / `256 KiB` default) or `ips` array length exceeded `max_batch_size` (`1,000` default).
- **Resolution**:
  Split client batches into chunks of `<= 1,000` IPs, or raise limits for internal workloads:
  ```bash
  dgip config set max_batch_size=2500 max_request_body_bytes=524288
  ```

---

## 5. Container, Kubernetes & OpenShift Runtime Issues

### Symptom A: `Read-only file system (os error 30)` writing to `DGIP_CACHE_DIR`
- **Root Cause**:
  Container was started with `--read-only` (`readOnlyRootFilesystem: true`) **without** mounting a writable volume or `tmpfs` at `DGIP_CACHE_DIR` (`/tmp/dgip-cache` or `/var/cache/dgip`).
- **Resolution**:
  Mount a persistent volume (`-v dgip-cache:/var/cache/dgip:Z` with `DGIP_CACHE_DIR=/var/cache/dgip`) or `/tmp` (`--tmpfs /tmp:rw,noexec,nosuid,size=256m` in Docker/Podman, or `emptyDir` mounted at `/tmp` in Kubernetes/OpenShift).

### Symptom B: OpenShift Pod fails SCC admission (`unable to validate against any security context constraint: runAsUser`)
- **Root Cause**:
  Standard Kubernetes manifests hardcode `runAsUser: 10001`, whereas Red Hat OpenShift's `restricted-v2` SCC requires omitting `runAsUser`/`fsGroup` so OpenShift can inject a project-scoped UID (`1000xxxxxx:0`).
- **Resolution**:
  Deploy with `--set openshift.enabled=true` in Helm (or use `deploy/openshift/dgip.yaml`). The `dgip` container image already sets `GID 0` and `g=u` permissions so arbitrary OpenShift UIDs work natively.

### Symptom C: Pod `OOMKilled` (`Exit Code 137`) during `dgip release` or `dgip sync`
- **Root Cause**:
  Container memory limit was set below `512Mi`. While steady-state Rust HTTP serving uses `< 10 MiB`, cold archive unpacking and compiling all 25 feeds (~1,036,000 intervals) plus building dual-stack `.mmdb` trees transiently peaks around `~497 MiB` before releasing memory back to the OS.
- **Resolution**:
  Keep container memory limits at `>= 768Mi` (`768Mi` default in `charts/dgip/values.yaml`).
