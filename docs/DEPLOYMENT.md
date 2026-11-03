# End-to-End Production Deployment Guide

**Container Image:** `ghcr.io/daviante-org/dgip` (`linux/amd64`, `linux/arm64`)  
**OCI Helm Chart:** `oci://ghcr.io/daviante-org/charts/dgip`

All official container images and Helm charts are published exclusively on GitHub infrastructure with keyless OIDC SLSA build provenance attestations.

---

## 1. Prerequisites, Sizing & Network Egress

### 1.1 Compute & Storage Sizing

| Component | Minimum | Recommended Production | Notes |
| :--- | :--- | :--- | :--- |
| **DGIP API Container** | `0.25 vCPU`, `256 MiB RAM` | `1 vCPU`, `512 MiB RAM` (`>= 2` replicas) | Steady-state Rust binary uses `< 15 MiB` RAM (`FROM scratch`, `~10 MB` image); full 25-feed sync peaks around `~180–250 MiB` before returning pages cleanly to OS. |
| **Ephemeral `/tmp`** | `512 MiB` | `1 GiB` (`tmpfs` or `emptyDir`) | Hydrates active snapshot downloads (`~35 MiB` per retained version) on read-only rootfs. |
| **PostgreSQL 17+** | `1 vCPU`, `1 GiB RAM`, `5 GiB SSD` | `2 vCPU`, `2–4 GiB RAM`, `10 GiB SSD` | Stores Blue/Green GiST indexes (`~450 MiB` incl. indexes) + `snapshot_retention` `BYTEA` blobs (`~180 MiB` for 5 weeks). |

### 1.2 Outbound Firewall Allowlist (TCP `443` HTTPS Only)
`dgip` requires outbound `HTTPS` (`TCP 443`) to fetch upstream feeds (inspect the exact live list anytime via `dgip host list`):
- **Initial Bootstrap (used once on empty DB)**: `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`
- **Layer 1 — Primary RIRs & RIPE RIS**: `ftp.arin.net`, `ftp.ripe.net`, `ftp.apnic.net`, `ftp.lacnic.net`, `ftp.afrinic.net`, `www.ris.ripe.net`, `data.ris.ripe.net`
- **Layer 2 — Operator & Cloud Regional Geofeeds**: `ip-ranges.amazonaws.com`, `www.gstatic.com`, `docs.oracle.com`, `digitalocean.com`, `www.digitalocean.com`, `geoip.linode.com`, `geofeed.constant.com`, `mask-api.icloud.com`
- **Layer 3 — RPKI VRPs & AS Classification**: `console.rpki-client.org`, `bgp.tools`
- **Layer 4 — CDN, Tor Exit & Open Threat Feeds**: `www.cloudflare.com`, `api.fastly.com`, `api.github.com`, `check.torproject.org`, `www.spamhaus.org`, `feodotracker.abuse.ch`

---

## 2. Docker & Docker Compose

### Option A: Docker Compose (Recommended Single-Host Stack)
```bash
cp .env.example .env
# Edit .env: set a strong POSTGRES_PASSWORD (and DGIP_SWAGGER_ENABLED=false if desired)
docker compose up -d

# Watch first-boot bootstrap (~35s) and verify readiness:
docker compose exec dgip dgip status
curl -sS http://127.0.0.1:8090/healthz/ready
```

### Option B: Standalone `docker run` Against External PostgreSQL
```bash
docker run -d \
  --name dgip \
  --restart unless-stopped \
  -p 127.0.0.1:8090:8090 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -e DGIP_DATABASE_URL="postgresql://dgip:secret@pg.example.internal:5432/dgip" \
  -e DGIP_SWAGGER_ENABLED="true" \
  ghcr.io/daviante-org/dgip:1.0.0
```

---

## 3. Podman & Podman Compose (Rootless & Rootful)

`dgip` runs as unprivileged `UID 10001:0` with zero Linux capabilities required, making it natively compatible with rootless Podman.

### Option A: Podman Compose
```bash
cp .env.example .env
podman compose up -d
podman compose exec dgip dgip status
```

### Option B: Rootless `podman run`
```bash
podman network create dgip-net

podman run -d --name dgip-db --network dgip-net \
  -e POSTGRES_USER=dgip -e POSTGRES_PASSWORD=strong-secret -e POSTGRES_DB=dgip \
  -v dgip_pgdata:/var/lib/postgresql/data \
  docker.io/library/postgres:18.6-alpine

podman run -d --name dgip --network dgip-net \
  -p 127.0.0.1:8090:8090 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -e DGIP_DATABASE_URL="postgresql://dgip:strong-secret@dgip-db:5432/dgip" \
  ghcr.io/daviante-org/dgip:1.0.0
```

---

## 4. Reverse Proxy & TLS Termination (`trusted_proxies`)

When placing Caddy, NGINX, Traefik, Cloudflare, or an Ingress controller in front of `dgip`, configure `trusted_proxies` via `dgip config set` so per-IP rate limiting and `GET /v1/ip/me` inspect the real client IP (extracted right-to-left from `X-Forwarded-For`) instead of your proxy's internal IP:

```bash
# Example: trust local loopback and Docker/Kubernetes proxy subnets
docker compose exec dgip dgip config set trusted_proxies=127.0.0.1/32,172.16.0.0/12,10.0.0.0/8
```

Example **Caddyfile** for `dgip.daviante.org`:
```caddyfile
dgip.daviante.org {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8090
}
```

---

## 5. Kubernetes (Helm v3 & Declarative Manifests)

### Option A: Install via Official GitHub OCI Helm Chart (Bundled PostgreSQL)
```bash
helm install dgip oci://ghcr.io/daviante-org/charts/dgip \
  --namespace dgip \
  --create-namespace \
  --set swagger.enabled=true \
  --set ingress.enabled=true \
  --set "ingress.hosts[0].host=dgip.daviante.org" \
  --set "ingress.hosts[0].paths[0].path=/" \
  --set "ingress.hosts[0].paths[0].pathType=Prefix"

kubectl -n dgip rollout status deploy/dgip
kubectl -n dgip exec deploy/dgip -- dgip status
```

### Option B: Production HA Kubernetes with External PostgreSQL (CloudNativePG / RDS / Patroni)
```bash
kubectl create namespace dgip

kubectl -n dgip create secret generic dgip-external-db \
  --from-literal=database-url="postgresql://dgip:strong-secret@pg-rw.db.svc.cluster.local:5432/dgip?sslmode=require"

helm upgrade --install dgip oci://ghcr.io/daviante-org/charts/dgip \
  --namespace dgip \
  --set replicaCount=3 \
  --set database.internal.enabled=false \
  --set database.external.existingSecret=dgip-external-db \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=6 \
  --set swagger.enabled=false
```

### Option C: Standalone Kubernetes Manifest
```bash
# Edit placeholder database credentials in deploy/kubernetes/dgip.yaml first
kubectl apply -f deploy/kubernetes/dgip.yaml
```

---

## 6. Red Hat OpenShift Container Platform (`restricted-v2` SCC)

The `dgip` image assigns group ownership `GID 0` (`root` group) with `chmod -R g=u` across `/app` and `/tmp/dgip-cache`. Setting `openshift.enabled=true` omits hardcoded `runAsUser`/`runAsGroup`/`fsGroup` fields so OpenShift's `restricted-v2` Security Context Constraint (SCC) admission controller dynamically assigns a project-scoped UID (`1000xxxxxx:0`) without privilege escalation.

### Option A: OpenShift Helm Deployment + Native Edge-TLS `Route`
```bash
oc new-project dgip

helm upgrade --install dgip oci://ghcr.io/daviante-org/charts/dgip \
  --namespace dgip \
  --set openshift.enabled=true \
  --set openshift.route.enabled=true \
  --set openshift.route.host=dgip.daviante.org \
  --set swagger.enabled=true

oc -n dgip rollout status deploy/dgip
oc -n dgip exec deploy/dgip -- dgip status
```

### Option B: Standalone OpenShift Manifest
```bash
oc new-project dgip
# Edit `dgip-secrets` in deploy/openshift/dgip.yaml before applying
oc apply -f deploy/openshift/dgip.yaml
oc get route dgip
```

---

## 7. Air-Gapped / Restricted Network Deployment

1. On an internet-connected build host, compile a standalone release archive (or download `bundle.tar.gz` from `daviante-org/dgip-data`):
   ```bash
   podman run --rm -v ./dist:/dist:rw ghcr.io/daviante-org/dgip:1.0.0 \
     dgip build-release --output-dir /dist
   ```
2. Host `bundle.tar.gz` on an internal HTTPS artifact server (e.g. `https://artifacts.internal.corp/dgip/bundle.tar.gz`).
3. Start `dgip` with `DGIP_INITIAL_BOOTSTRAP_URL="https://artifacts.internal.corp/dgip/bundle.tar.gz"`, then permit your internal host and disable external syncs via CLI:
   ```bash
   dgip host allow artifacts.internal.corp --notes "Internal air-gapped mirror"
   dgip config set live_sync_interval_seconds=0 weekly_release_enabled=false
   ```

---

## 8. Upgrades, Backups & Swagger Toggle

- **Zero-Downtime Rolling Upgrades**: Because `SCHEMA_SQL` migrations are idempotent (`CREATE TABLE IF NOT EXISTS`) and multiple replicas share PostgreSQL safely via advisory locks, `helm upgrade` or `kubectl set image` performs rolling updates without lookup downtime.
- **Database Backups**: Standard `pg_dump -Fc dgip > dgip.dump` backs up all configuration, release history, and snapshot blobs. Even if a database is lost completely, a fresh `dgip` deployment automatically re-bootstraps from `daviante-org/dgip-data` in ~35 seconds.
- **Enabling / Disabling Branded Swagger UI**:
  - Startup flag: `DGIP_SWAGGER_ENABLED=false` (or Helm `--set swagger.enabled=false`).
  - Live zero-restart CLI toggle: `dgip config set swagger_enabled=false` (returns RFC 9457 `404` on `/docs`, `/openapi.json`, and `/docs/assets/*` within `2s`).
