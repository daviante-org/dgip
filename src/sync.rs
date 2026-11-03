//! Synchronization and snapshot lifecycle manager for DGIP.
//!
//! 1. First-Time Bootstrap (`bootstrap_once_from_bundle`):
//!    Loads `bundle.tar.gz` strictly once on an empty database from `dgip_config.bootstrap_bundle_url`,
//!    verifies SHA-256 digests against `manifest.json`, populates PostgreSQL slot `a` and `dgip_releases`,
//!    and sets `initial_bootstrapped = TRUE`.
//!
//! 2. Daily Live Lookup Refresh (`run_live_sync`):
//!    Downloads directly from upstream RIR/RIPE/RPKI/Geofeed/Security feeds in `dgip_feed_sources`,
//!    compiles disjoint intervals into the inactive Blue/Green GiST slot (`a` or `b`),
//!    and flips `active_slot` atomically without cutting snapshot blobs.
//!
//! 3. Weekly Snapshot Release (`run_weekly_release`):
//!    Compiles upstream feeds, compares normalized hashes against the previous weekly snapshot,
//!    packages CSV, RFC 8805 Geofeed, MaxMind MMDB v2.0, `bundle.tar.gz`, `manifest.json`, and
//!    `SHA256SUMS.txt`, and persists them to PostgreSQL + local disk cache.

use crate::compiler::{
    compile_feed_payloads, package_standard_snapshot, unpack_bootstrap_bundle, UnpackedBootstrap,
    CORE_FEED_KINDS,
};
use crate::config::Settings;
use crate::db::Database;
use crate::ip_utils::verify_public_upstream_host;
use crate::models::{CutReleaseResponse, SyncResponse};
use crate::release_notes::{
    compute_diff_and_release_notes, format_iso_week_version, format_release_title,
};
use crate::types::{
    CompiledTables, DgipError, DgipResult, FeedSourceSpec, PackagedSnapshot, RuntimeCatalog,
    SpecialRangeRuleV4, SpecialRangeRuleV6, ADVISORY_LOCK_KEY,
};
use chrono::{Datelike, SecondsFormat, Timelike, Utc};
use futures_util::future::try_join_all;
use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{watch, Mutex as AsyncMutex, Semaphore};

pub const PRIMARY_RIR_FAST_TIMEOUT_SECONDS: f64 = 25.0;

const MAX_BOOTSTRAP_BUNDLE_BYTES: usize = 256 * 1024 * 1024;
const MAX_BOOTSTRAP_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;

/// Official RIPE NCC NRO extended-delegation mirror URLs for non-RIPE RIRs.
pub fn rir_nro_mirror_url(source_url: &str) -> Option<&'static str> {
    match source_url {
        "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest" => {
            Some("https://ftp.ripe.net/pub/stats/arin/delegated-arin-extended-latest")
        }
        "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest" => {
            Some("https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-extended-latest")
        }
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest" => {
            Some("https://ftp.ripe.net/pub/stats/lacnic/delegated-lacnic-extended-latest")
        }
        "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest" => {
            Some("https://ftp.ripe.net/pub/stats/afrinic/delegated-afrinic-extended-latest")
        }
        _ => None,
    }
}

#[inline]
fn round_millis(secs: f64) -> f64 {
    (secs * 1000.0).round() / 1000.0
}

fn percent_decode_utf8(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read a bounded `file://` URL when `DGIP_ALLOW_LOCAL_FILES=true`.
pub fn load_local_file_url(file_url: &str, max_bytes: usize) -> DgipResult<Vec<u8>> {
    let parsed = url::Url::parse(file_url)
        .map_err(|e| DgipError::Compilation(format!("Invalid file URL {file_url:?}: {e}")))?;

    let target: PathBuf = match parsed.to_file_path() {
        Ok(p) => p,
        Err(()) => {
            let mut raw_path = percent_decode_utf8(parsed.path());
            let bytes = raw_path.as_bytes();
            if bytes.len() >= 3 && bytes[0] == b'/' && bytes[2] == b':' {
                raw_path.remove(0);
            }
            PathBuf::from(raw_path)
        }
    };

    if !target.is_file() {
        return Err(DgipError::Compilation(format!(
            "Local file not found: {}",
            target.display()
        )));
    }
    let meta = std::fs::metadata(&target)?;
    let size = meta.len();
    if size > max_bytes as u64 {
        return Err(DgipError::Compilation(format!(
            "Local file {} ({size} B) exceeds limit {max_bytes} B.",
            target.display()
        )));
    }
    Ok(std::fs::read(&target)?)
}

fn extract_normalized_hostname(parsed: &url::Url) -> String {
    match parsed.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        Some(url::Host::Ipv4(v4)) => v4.to_string(),
        Some(url::Host::Ipv6(v6)) => v6.to_string(),
        None => String::new(),
    }
}

enum HopOutcome {
    Redirect(String),
    Body(Vec<u8>),
    TransientError(String),
}

/// Download an HTTPS URL while validating every redirect hop against SSRF rules and pinning DNS.
#[allow(clippy::too_many_arguments)]
pub async fn download_https_bounded(
    url: &str,
    allowed_hosts: &HashSet<String>,
    timeout_seconds: f64,
    max_compressed_bytes: usize,
    max_redirects: usize,
    user_agent: &str,
    v4_rules: &[SpecialRangeRuleV4],
    v6_rules: &[SpecialRangeRuleV6],
    max_attempts: usize,
) -> DgipResult<Vec<u8>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let attempts = max_attempts.max(1);
    let clamped_timeout = timeout_seconds.max(0.1);
    let total_timeout = Duration::from_secs_f64(clamped_timeout);
    let connect_timeout = Duration::from_secs_f64(clamped_timeout.min(45.0));

    let mut last_err_detail = String::new();

    for attempt in 0..attempts {
        let mut current_url = url.to_string();
        let mut transient_fail: Option<String> = None;

        for hop in 0..=max_redirects {
            let parsed = url::Url::parse(&current_url).map_err(|e| {
                DgipError::Compilation(format!("Blocked malformed URL {current_url:?}: {e}"))
            })?;

            if !parsed.scheme().eq_ignore_ascii_case("https") {
                return Err(DgipError::Compilation(format!(
                    "Blocked non-HTTPS URL scheme: {current_url:?}"
                )));
            }

            let hostname = extract_normalized_hostname(&parsed);
            if hostname.is_empty() || !allowed_hosts.contains(&hostname) {
                return Err(DgipError::Compilation(format!(
                    "Host {hostname:?} is not enabled in PostgreSQL dgip_allowed_hosts."
                )));
            }

            let host_for_dns = hostname.clone();
            let v4_owned = v4_rules.to_vec();
            let v6_owned = v6_rules.to_vec();
            let verified_addrs = tokio::task::spawn_blocking(move || {
                verify_public_upstream_host(&host_for_dns, &v4_owned, &v6_owned)
            })
            .await
            .map_err(|e| DgipError::Compilation(format!("DNS verification task failed: {e}")))??;

            let target_port = parsed.port_or_known_default().unwrap_or(443);
            let pinned_addrs: Vec<SocketAddr> = verified_addrs
                .into_iter()
                .map(|sa| SocketAddr::new(sa.ip(), target_port))
                .collect();

            let mut builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(connect_timeout)
                .timeout(total_timeout)
                .user_agent(user_agent);

            if matches!(parsed.host(), Some(url::Host::Domain(_))) {
                builder = builder.resolve_to_addrs(&hostname, &pinned_addrs);
            }

            let client = builder.build().map_err(|e| {
                DgipError::Compilation(format!("Failed constructing HTTPS client: {e}"))
            })?;

            let req_url = current_url.clone();
            let hop_res: DgipResult<HopOutcome> =
                match tokio::time::timeout(total_timeout, async {
                    let mut resp = match client.get(&req_url).send().await {
                        Ok(r) => r,
                        Err(e) => return Ok(HopOutcome::TransientError(e.to_string())),
                    };

                    let status_code = resp.status().as_u16();
                    if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
                        let Some(loc_hdr) = resp.headers().get(reqwest::header::LOCATION) else {
                            return Err(DgipError::Compilation(format!(
                                "Redirect from {req_url:?} missing Location header."
                            )));
                        };
                        let loc_str = loc_hdr.to_str().map_err(|_| {
                            DgipError::Compilation(format!(
                                "Redirect from {req_url:?} has invalid UTF-8 Location header."
                            ))
                        })?;
                        let joined = parsed.join(loc_str).map_err(|e| {
                            DgipError::Compilation(format!(
                                "Redirect from {req_url:?} invalid target {loc_str:?}: {e}"
                            ))
                        })?;
                        return Ok(HopOutcome::Redirect(joined.to_string()));
                    }

                    if matches!(status_code, 429 | 502 | 503 | 504) && attempt + 1 < attempts {
                        return Ok(HopOutcome::TransientError(format!(
                            "Transient HTTP {status_code} from {req_url:?}"
                        )));
                    }

                    if status_code != 200 {
                        return Err(DgipError::Compilation(format!(
                            "Upstream {req_url:?} returned HTTP {status_code}."
                        )));
                    }

                    if let Some(cl) = resp.content_length() {
                        if cl > max_compressed_bytes as u64 {
                            return Err(DgipError::Compilation(format!(
                                "Download {req_url:?} exceeded maximum size {max_compressed_bytes} bytes."
                            )));
                        }
                    }

                    let mut buf = Vec::new();
                    loop {
                        match resp.chunk().await {
                            Ok(Some(chunk)) => {
                                if buf.len().saturating_add(chunk.len()) > max_compressed_bytes {
                                    return Err(DgipError::Compilation(format!(
                                        "Download {req_url:?} exceeded maximum size {max_compressed_bytes} bytes."
                                    )));
                                }
                                buf.extend_from_slice(&chunk);
                            }
                            Ok(None) => return Ok(HopOutcome::Body(buf)),
                            Err(e) => return Ok(HopOutcome::TransientError(e.to_string())),
                        }
                    }
                })
                .await
                {
                    Ok(inner) => inner,
                    Err(_) => Ok(HopOutcome::TransientError(format!(
                        "Timed out after {clamped_timeout:.1}s"
                    ))),
                };

            match hop_res? {
                HopOutcome::Body(data) => return Ok(data),
                HopOutcome::Redirect(next_url) => {
                    if hop == max_redirects {
                        return Err(DgipError::Compilation(format!(
                            "Exceeded {max_redirects} redirects downloading {url:?}."
                        )));
                    }
                    current_url = next_url;
                }
                HopOutcome::TransientError(detail) => {
                    transient_fail = Some(detail);
                    break;
                }
            }
        }

        if let Some(detail) = transient_fail {
            last_err_detail = detail;
            if attempt + 1 < attempts {
                let delay_secs = 1.5 * 2_f64.powi(attempt as i32);
                tracing::warn!(
                    "Transient error fetching {} ({}); retrying in {:.1}s ({}/{})...",
                    current_url,
                    last_err_detail,
                    delay_secs,
                    attempt + 1,
                    attempts
                );
                tokio::time::sleep(Duration::from_secs_f64(delay_secs)).await;
                continue;
            }
            return Err(DgipError::Compilation(format!(
                "Failed downloading {current_url:?} after {attempts} attempts ({last_err_detail})."
            )));
        }
    }

    Err(DgipError::Compilation(format!(
        "Failed downloading {url:?}: {last_err_detail}"
    )))
}

/// Download a single feed specification with automatic RIPE NCC NRO mirror fallback on RIR stall/outage,
/// using an injectable async `fetcher(url, timeout_seconds)` closure for deterministic testing.
pub async fn fetch_single_feed_with_fallback<F, Fut>(
    spec: &FeedSourceSpec,
    allowed_hosts: &HashSet<String>,
    default_timeout: f64,
    enrichment_strict: bool,
    mut fetcher: F,
) -> DgipResult<Option<Vec<u8>>>
where
    F: FnMut(String, f64) -> Fut,
    Fut: Future<Output = DgipResult<Vec<u8>>>,
{
    let mirror_opt = rir_nro_mirror_url(&spec.source_url)
        .filter(|&m| m != spec.source_url && allowed_hosts.contains("ftp.ripe.net"));

    let fetch_result: DgipResult<Vec<u8>> = if let Some(mirror_url) = mirror_opt {
        let fast_timeout = default_timeout.clamp(0.1, PRIMARY_RIR_FAST_TIMEOUT_SECONDS);
        match tokio::time::timeout(
            Duration::from_secs_f64(fast_timeout),
            fetcher(spec.source_url.clone(), fast_timeout),
        )
        .await
        {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(primary_err)) => {
                tracing::warn!(
                    "Primary RIR origin {} stalled or failed ({}); falling back to official NRO mirror {}",
                    spec.source_url,
                    primary_err,
                    mirror_url
                );
                fetcher(mirror_url.to_string(), default_timeout).await
            }
            Err(_) => {
                tracing::warn!(
                    "Primary RIR origin {} timed out after {:.1}s; falling back to official NRO mirror {}",
                    spec.source_url,
                    fast_timeout,
                    mirror_url
                );
                fetcher(mirror_url.to_string(), default_timeout).await
            }
        }
    } else {
        fetcher(spec.source_url.clone(), default_timeout).await
    };

    match fetch_result {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) => {
            let is_core = CORE_FEED_KINDS.contains(&spec.kind.as_str());
            if is_core || enrichment_strict {
                Err(err)
            } else {
                tracing::warn!(
                    "Skipping unreachable enrichment feed {} ({}): {}",
                    spec.feed_key,
                    spec.source_url,
                    err
                );
                Ok(None)
            }
        }
    }
}

/// Download a single feed specification using `download_https_bounded` (or `file://` if enabled)
/// with automatic RIPE NCC NRO mirror fallback.
pub async fn fetch_feed_with_nro_fallback(
    spec: &FeedSourceSpec,
    catalog: &RuntimeCatalog,
    allow_local_files: bool,
) -> DgipResult<Option<(FeedSourceSpec, Vec<u8>)>> {
    let max_bytes = usize::try_from(spec.max_compressed_bytes.max(1)).unwrap_or(usize::MAX);
    let primary_url = spec.source_url.clone();
    let has_mirror = rir_nro_mirror_url(&primary_url).is_some()
        && catalog.allowed_hosts.contains("ftp.ripe.net");

    let raw_opt = fetch_single_feed_with_fallback(
        spec,
        &catalog.allowed_hosts,
        catalog.http_timeout_seconds,
        catalog.enrichment_strict,
        |url, timeout| {
            let is_primary_with_mirror = has_mirror && url == primary_url;
            let attempts = if is_primary_with_mirror { 1 } else { 3 };
            async move {
                if url.starts_with("file://") {
                    if !allow_local_files {
                        return Err(DgipError::Compilation(
                            "file:// URLs require DGIP_ALLOW_LOCAL_FILES=true.".to_string(),
                        ));
                    }
                    tokio::task::spawn_blocking(move || load_local_file_url(&url, max_bytes))
                        .await
                        .map_err(|e| {
                            DgipError::Compilation(format!("Local file read task failed: {e}"))
                        })?
                } else {
                    download_https_bounded(
                        &url,
                        &catalog.allowed_hosts,
                        timeout,
                        max_bytes,
                        catalog.max_redirects,
                        &catalog.upstream_user_agent,
                        &catalog.special_v4_rules,
                        &catalog.special_v6_rules,
                        attempts,
                    )
                    .await
                }
            }
        },
    )
    .await?;

    Ok(raw_opt.map(|bytes| (spec.clone(), bytes)))
}

struct AdvisoryLockGuard {
    client: tokio_postgres::Client,
}

impl AdvisoryLockGuard {
    async fn try_acquire(db: &Database) -> DgipResult<Option<Self>> {
        let client = db.connect_standalone().await?;
        let row = client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&ADVISORY_LOCK_KEY])
            .await
            .map_err(|e| DgipError::Database(format!("pg_try_advisory_lock failed: {e}")))?;
        let locked: bool = row
            .try_get(0)
            .map_err(|e| DgipError::Database(e.to_string()))?;
        if locked {
            Ok(Some(Self { client }))
        } else {
            Ok(None)
        }
    }

    async fn unlock(self) {
        let _ = self
            .client
            .execute("SELECT pg_advisory_unlock($1)", &[&ADVISORY_LOCK_KEY])
            .await;
    }
}

/// Coordinates one-time `dgip-data` bootstrap, daily RIR live sync, and weekly snapshot cuts.
pub struct SyncManager {
    pub settings: Settings,
    pub db: Arc<Database>,
    local_lock: AsyncMutex<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl SyncManager {
    pub fn new(settings: Settings, db: Arc<Database>) -> Arc<Self> {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Arc::new(Self {
            settings,
            db,
            local_lock: AsyncMutex::new(()),
            shutdown_tx,
        })
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    fn is_stopping(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    async fn fetch_url(
        &self,
        url: &str,
        max_bytes: usize,
        catalog: &RuntimeCatalog,
    ) -> DgipResult<Vec<u8>> {
        if url.starts_with("file://") {
            if !self.settings.allow_local_files {
                return Err(DgipError::Compilation(
                    "file:// URLs require DGIP_ALLOW_LOCAL_FILES=true.".to_string(),
                ));
            }
            let url_owned = url.to_string();
            return tokio::task::spawn_blocking(move || load_local_file_url(&url_owned, max_bytes))
                .await
                .map_err(|e| DgipError::Compilation(format!("File load task failed: {e}")))?;
        }

        download_https_bounded(
            url,
            &catalog.allowed_hosts,
            catalog.http_timeout_seconds,
            max_bytes,
            catalog.max_redirects,
            &catalog.upstream_user_agent,
            &catalog.special_v4_rules,
            &catalog.special_v6_rules,
            3,
        )
        .await
    }

    async fn download_enabled_feeds(
        &self,
        catalog: &Arc<RuntimeCatalog>,
    ) -> DgipResult<Vec<(FeedSourceSpec, Vec<u8>)>> {
        let enabled: Vec<FeedSourceSpec> = catalog
            .feed_sources
            .iter()
            .filter(|f| f.enabled)
            .cloned()
            .collect();

        let has_rir = enabled.iter().any(|f| f.kind == "rir_delegated");
        let has_bgp = enabled.iter().any(|f| f.kind == "ris_bgp");
        if !has_rir || !has_bgp {
            return Err(DgipError::Compilation(
                "At least one 'rir_delegated' feed and one 'ris_bgp' feed must be enabled in dgip_feed_sources."
                    .to_string(),
            ));
        }

        let t_dl = Instant::now();
        let sem = Arc::new(Semaphore::new(10));
        let allow_local = self.settings.allow_local_files;

        let tasks = enabled.iter().map(|spec| {
            let sem_ref = Arc::clone(&sem);
            let cat_ref = Arc::clone(catalog);
            let spec_owned = spec.clone();
            async move {
                let _permit = sem_ref.acquire().await.map_err(|_| {
                    DgipError::Compilation("Download semaphore closed.".to_string())
                })?;
                fetch_feed_with_nro_fallback(&spec_owned, &cat_ref, allow_local).await
            }
        });

        let results = try_join_all(tasks).await?;
        let downloaded: Vec<(FeedSourceSpec, Vec<u8>)> = results.into_iter().flatten().collect();
        let total_mb: f64 =
            downloaded.iter().map(|(_, raw)| raw.len()).sum::<usize>() as f64 / (1024.0 * 1024.0);

        tracing::info!(
            "Downloaded {}/{} upstream feeds ({:.2} MiB) in {:.2}s.",
            downloaded.len(),
            enabled.len(),
            total_mb,
            t_dl.elapsed().as_secs_f64()
        );

        Ok(downloaded)
    }

    async fn download_and_compile_upstream_registries(
        &self,
        catalog: &Arc<RuntimeCatalog>,
    ) -> DgipResult<CompiledTables> {
        let downloaded = self.download_enabled_feeds(catalog).await?;
        let cat_clone = Arc::clone(catalog);

        tokio::task::spawn_blocking(move || {
            compile_feed_payloads(
                &downloaded,
                &cat_clone.valid_country_codes,
                &cat_clone.special_v4_rules,
                &cat_clone.special_v6_rules,
                cat_clone.bgp_min_peers,
                cat_clone.bgp_ipv4_min_prefixlen,
                cat_clone.bgp_ipv6_min_prefixlen,
                cat_clone.asn_min_valid,
                cat_clone.asn_max_valid,
                cat_clone.rpki_reject_invalid,
                cat_clone.enrichment_strict,
            )
        })
        .await
        .map_err(|e| DgipError::Compilation(format!("Feed compilation task panicked: {e}")))?
    }

    async fn warm_and_prune_cache(
        &self,
        packaged: &PackagedSnapshot,
        retained_versions: &HashSet<String>,
    ) -> DgipResult<()> {
        let db = Arc::clone(&self.db);
        let pkg = packaged.clone();
        let retained = retained_versions.clone();

        tokio::task::spawn_blocking(move || -> DgipResult<()> {
            db.write_cache_file(
                &pkg.version,
                "bundle.tar.gz",
                &pkg.bundle_bytes,
                Some("application/gzip"),
                Some(&pkg.bundle_sha256),
            )?;
            db.write_cache_file(
                &pkg.version,
                "manifest.json",
                &pkg.manifest_bytes,
                Some("application/json"),
                Some(&pkg.manifest_sha256),
            )?;
            db.write_cache_file(
                &pkg.version,
                "SHA256SUMS.txt",
                &pkg.sha256sums_bytes,
                Some("text/plain; charset=utf-8"),
                Some(&pkg.sha256sums_sha256),
            )?;
            for (fname, art) in &pkg.dataset_artifacts {
                db.write_cache_file(
                    &pkg.version,
                    fname,
                    &art.payload,
                    Some(&art.content_type),
                    Some(&art.sha256),
                )?;
            }
            db.prune_local_cache(&retained);
            Ok(())
        })
        .await
        .map_err(|e| DgipError::Database(format!("Cache warm task panicked: {e}")))?
    }

    /// Mode 1: One-time initial bootstrap from `daviante-org/dgip-data` `bundle.tar.gz`.
    pub async fn bootstrap_once_from_bundle(&self) -> DgipResult<bool> {
        let _local_guard = self.local_lock.lock().await;
        let Some(pg_lock) = AdvisoryLockGuard::try_acquire(&self.db).await? else {
            return Ok(false);
        };

        let result = self.bootstrap_once_locked().await;
        pg_lock.unlock().await;
        result
    }

    async fn bootstrap_once_locked(&self) -> DgipResult<bool> {
        let state = self.db.get_state().await?;
        if state.initial_bootstrapped {
            return Ok(true);
        }

        let catalog = self.db.ensure_catalog_fresh(true).await?;
        if !catalog.bootstrap_enabled || catalog.bootstrap_bundle_url.is_empty() {
            return Ok(false);
        }

        tracing::info!(
            "One-time initial bootstrap: loading pre-built snapshot from {} ...",
            catalog.bootstrap_bundle_url
        );

        let bundle_bytes = self
            .fetch_url(
                &catalog.bootstrap_bundle_url,
                MAX_BOOTSTRAP_BUNDLE_BYTES,
                &catalog,
            )
            .await?;

        let bundle_for_unpack = bundle_bytes.clone();
        let unpacked: UnpackedBootstrap = tokio::task::spawn_blocking(move || {
            unpack_bootstrap_bundle(&bundle_for_unpack, MAX_BOOTSTRAP_ARCHIVE_BYTES)
        })
        .await
        .map_err(|e| DgipError::Compilation(format!("Bootstrap unpack task panicked: {e}")))??;

        let version = unpacked.version.clone();
        let released_at = unpacked.released_at;
        let source_attr = if unpacked.source_attribution.is_empty() {
            catalog.source_attribution.clone()
        } else {
            unpacked.source_attribution.clone()
        };

        let packaged = PackagedSnapshot {
            version: unpacked.version,
            release_title: unpacked.release_title,
            released_iso: released_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            manifest: unpacked.manifest,
            manifest_bytes: unpacked.manifest_bytes,
            manifest_sha256: unpacked.manifest_sha256,
            bundle_bytes,
            bundle_sha256: unpacked.bundle_sha256,
            sha256sums_bytes: unpacked.sha256sums_bytes,
            sha256sums_sha256: unpacked.sha256sums_sha256,
            dataset_artifacts: unpacked.dataset_artifacts,
        };
        let tables = unpacked.tables;

        let pkg_for_diff = packaged.clone();
        let tables_for_diff = tables.clone();
        let attr_for_diff = source_attr.clone();
        let diff_notes = tokio::task::spawn_blocking(move || {
            compute_diff_and_release_notes(
                &pkg_for_diff,
                &tables_for_diff,
                None,
                None,
                None,
                &attr_for_diff,
                Some("Initial bootstrap snapshot loaded from daviante-org/dgip-data."),
            )
        })
        .await
        .map_err(|e| DgipError::Compilation(format!("Bootstrap diff task panicked: {e}")))??;

        self.db.populate_inactive_slot("a", &tables).await?;
        let (_build_num, retained) = self
            .db
            .commit_snapshot_transaction(
                &packaged,
                &tables,
                released_at,
                None,
                &diff_notes.diff_summary,
                &diff_notes.release_notes_md,
                None,
                "a",
                true,
                catalog.snapshot_retention,
                &source_attr,
            )
            .await?;

        self.warm_and_prune_cache(&packaged, &retained).await?;
        tracing::info!("Initial bootstrap from dgip-data completed ({version} on slot 'a').");
        Ok(true)
    }

    /// Mode 2: Daily live lookup table refresh from primary RIR/RIPE feeds into inactive GiST slot.
    pub async fn run_live_sync(&self, force: bool) -> DgipResult<SyncResponse> {
        let t0 = Instant::now();
        let Ok(_local_guard) = self.local_lock.try_lock() else {
            return Ok(SyncResponse {
                status: "already_running".to_string(),
                active_slot: None,
                live_row_counts: None,
                duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
                detail: "Another sync or snapshot operation is already running.".to_string(),
            });
        };

        let Some(pg_lock) = AdvisoryLockGuard::try_acquire(&self.db).await? else {
            return Ok(SyncResponse {
                status: "already_running".to_string(),
                active_slot: None,
                live_row_counts: None,
                duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
                detail: "Another DGIP replica holds the PostgreSQL advisory lock.".to_string(),
            });
        };

        let _ = self.db.record_sync_attempt().await;
        let res = self.run_live_sync_locked(force, t0).await;
        if let Err(ref e) = res {
            tracing::error!("Live registry sync failed: {e}");
            let _ = self.db.record_sync_error(&e.to_string()).await;
        }
        pg_lock.unlock().await;
        res
    }

    async fn run_live_sync_locked(&self, force: bool, t0: Instant) -> DgipResult<SyncResponse> {
        let catalog = self.db.ensure_catalog_fresh(true).await?;
        let state_before = self.db.get_state().await?;
        let active_slot = state_before.active_slot;
        let prev_sha = if active_slot == "a" || active_slot == "b" {
            state_before.live_feed_sha256
        } else {
            None
        };

        let t_comp = Instant::now();
        let tables = self
            .download_and_compile_upstream_registries(&catalog)
            .await?;
        let row_counts = tables.row_counts();
        let norm_sha = tables.normalized_sha256.clone();

        tracing::info!(
            "Compiled live registry intervals in {:.2}s (sha256={}...).",
            t_comp.elapsed().as_secs_f64(),
            &norm_sha[..norm_sha.len().min(12)]
        );

        if !force && prev_sha.as_deref() == Some(norm_sha.as_str()) {
            self.db.record_sync_unchanged().await?;
            return Ok(SyncResponse {
                status: "unchanged".to_string(),
                active_slot: Some(active_slot),
                live_row_counts: Some(row_counts),
                duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
                detail: "Normalized upstream registry data matches active live slot.".to_string(),
            });
        }

        let target_slot = if active_slot == "a" { "b" } else { "a" };
        let t_db = Instant::now();
        self.db.populate_inactive_slot(target_slot, &tables).await?;
        self.db
            .flip_live_slot_only(target_slot, &norm_sha, &row_counts)
            .await?;

        tracing::info!(
            "Populated PostgreSQL GiST slot '{}' and flipped atomically in {:.2}s.",
            target_slot,
            t_db.elapsed().as_secs_f64()
        );

        Ok(SyncResponse {
            status: "updated".to_string(),
            active_slot: Some(target_slot.to_string()),
            live_row_counts: Some(row_counts),
            duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
            detail: format!(
                "Refreshed live IP lookup slot '{target_slot}' from primary registries."
            ),
        })
    }

    /// Mode 3: Weekly snapshot release compilation & persistence (`/v1/snapshots/*`).
    pub async fn run_weekly_release(
        &self,
        force: bool,
        operator_note: Option<&str>,
    ) -> DgipResult<CutReleaseResponse> {
        let t0 = Instant::now();
        let Ok(_local_guard) = self.local_lock.try_lock() else {
            return Ok(CutReleaseResponse {
                status: "already_running".to_string(),
                version: None,
                release_title: None,
                build_number: None,
                previous_version: None,
                active_slot: None,
                row_counts: None,
                duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
                detail: "Another sync or snapshot operation is already running.".to_string(),
            });
        };

        let Some(pg_lock) = AdvisoryLockGuard::try_acquire(&self.db).await? else {
            return Ok(CutReleaseResponse {
                status: "already_running".to_string(),
                version: None,
                release_title: None,
                build_number: None,
                previous_version: None,
                active_slot: None,
                row_counts: None,
                duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
                detail: "Another DGIP replica holds the PostgreSQL advisory lock.".to_string(),
            });
        };

        let _ = self.db.record_release_attempt().await;
        let res = self
            .run_weekly_release_locked(force, operator_note, t0)
            .await;
        if let Err(ref e) = res {
            tracing::error!("Weekly snapshot release failed: {e}");
            let _ = self.db.record_release_error(&e.to_string()).await;
        }
        pg_lock.unlock().await;
        res
    }

    async fn run_weekly_release_locked(
        &self,
        force: bool,
        operator_note: Option<&str>,
        t0: Instant,
    ) -> DgipResult<CutReleaseResponse> {
        let catalog = self.db.ensure_catalog_fresh(true).await?;
        let tables = self
            .download_and_compile_upstream_registries(&catalog)
            .await?;
        let (prev_rel, prev_csv_gz) = self.db.get_latest_release_for_diff().await?;
        let state = self.db.get_state().await?;

        let mut active_slot = state.active_slot;
        let row_counts = tables.row_counts();

        let live_rebuilt = if (active_slot != "a" && active_slot != "b")
            || state.live_feed_sha256.as_deref() != Some(tables.normalized_sha256.as_str())
        {
            let target_slot = if active_slot == "a" { "b" } else { "a" };
            self.db.populate_inactive_slot(target_slot, &tables).await?;
            active_slot = target_slot.to_string();
            true
        } else {
            false
        };

        if !force {
            if let Some(ref prev) = prev_rel {
                if prev.combined_feed_sha256.as_deref() == Some(tables.normalized_sha256.as_str()) {
                    if live_rebuilt {
                        self.db
                            .flip_live_slot_only(
                                &active_slot,
                                &tables.normalized_sha256,
                                &row_counts,
                            )
                            .await?;
                    }
                    self.db.record_release_unchanged().await?;
                    return Ok(CutReleaseResponse {
                        status: "unchanged".to_string(),
                        version: Some(prev.version.clone()),
                        release_title: None,
                        build_number: Some(prev.build_number),
                        previous_version: None,
                        active_slot: Some(active_slot),
                        row_counts: Some(row_counts),
                        duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
                        detail: format!(
                            "Normalized registry data matches snapshot {}; skipped duplicate snapshot.",
                            prev.version
                        ),
                    });
                }
            }
        }

        let now_utc = Utc::now();
        let iso_wk = now_utc.iso_week();
        let week_base = format!(
            "{}{}.W{:02}",
            catalog.version_prefix,
            iso_wk.year(),
            iso_wk.week()
        );
        let existing = self.db.list_versions_matching(&week_base).await?;
        let version = format_iso_week_version(now_utc, &existing, &catalog.version_prefix);
        let release_title =
            format_release_title(&catalog.release_title_template, &version, now_utc);
        let previous_version = prev_rel.as_ref().map(|r| r.version.clone());
        let previous_row_counts = prev_rel
            .as_ref()
            .filter(|r| !r.row_counts.is_empty())
            .map(|r| r.row_counts.clone());

        let tables_for_pkg = tables.clone();
        let ver_for_pkg = version.clone();
        let title_for_pkg = release_title.clone();
        let prev_ver_for_pkg = previous_version.clone();
        let cat_for_pkg = Arc::clone(&catalog);
        let operator_note_owned = operator_note.map(str::to_string);

        let (packaged, diff_notes) = tokio::task::spawn_blocking(move || {
            let packaged = package_standard_snapshot(
                &tables_for_pkg,
                &ver_for_pkg,
                &title_for_pkg,
                now_utc,
                prev_ver_for_pkg.as_deref(),
                &cat_for_pkg.source_attribution,
                &cat_for_pkg.country_details,
            )?;
            let diff_notes = compute_diff_and_release_notes(
                &packaged,
                &tables_for_pkg,
                prev_ver_for_pkg.as_deref(),
                prev_csv_gz.as_ref(),
                previous_row_counts.as_ref(),
                &cat_for_pkg.source_attribution,
                operator_note_owned.as_deref(),
            )?;
            Ok::<_, DgipError>((packaged, diff_notes))
        })
        .await
        .map_err(|e| DgipError::Compilation(format!("Snapshot packaging task panicked: {e}")))??;

        let (build_number, retained) = self
            .db
            .commit_snapshot_transaction(
                &packaged,
                &tables,
                now_utc,
                previous_version.as_deref(),
                &diff_notes.diff_summary,
                &diff_notes.release_notes_md,
                operator_note,
                &active_slot,
                live_rebuilt,
                catalog.snapshot_retention,
                &catalog.source_attribution,
            )
            .await?;

        self.warm_and_prune_cache(&packaged, &retained).await?;

        Ok(CutReleaseResponse {
            status: "released".to_string(),
            version: Some(version.clone()),
            release_title: Some(release_title),
            build_number: Some(build_number),
            previous_version,
            active_slot: Some(active_slot),
            row_counts: Some(row_counts),
            duration_seconds: round_millis(t0.elapsed().as_secs_f64()),
            detail: format!("Cut snapshot {version} (build #{build_number})."),
        })
    }

    /// Spawn background bootstrap, daily live-sync, and weekly snapshot scheduler task.
    pub fn start_background_tasks(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mgr = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            match (
                mgr.db.get_state().await,
                mgr.db.ensure_catalog_fresh(false).await,
            ) {
                (Ok(state), Ok(cat)) => {
                    if !state.initial_bootstrapped && !mgr.is_stopping() {
                        let mut bootstrapped = false;
                        if cat.bootstrap_enabled && !cat.bootstrap_bundle_url.is_empty() {
                            match mgr.bootstrap_once_from_bundle().await {
                                Ok(done) => bootstrapped = done,
                                Err(e) => {
                                    tracing::warn!(
                                        "One-time dgip-data bootstrap failed ({e}); falling back to primary RIR sync."
                                    );
                                }
                            }
                        }
                        if !bootstrapped && !mgr.is_stopping() {
                            if let Err(e) = mgr.run_weekly_release(false, None).await {
                                tracing::error!("Initial primary registry build failed: {e}");
                            }
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    tracing::error!("Startup initialization check failed: {e}");
                }
            }

            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                }
                if *shutdown_rx.borrow() {
                    break;
                }

                let cat = match mgr.db.ensure_catalog_fresh(false).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Background scheduler catalog check error: {e}");
                        continue;
                    }
                };
                let mut state = match mgr.db.get_state().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Background scheduler state check error: {e}");
                        continue;
                    }
                };

                let now_utc = Utc::now();
                let current_weekday = now_utc.weekday().num_days_from_monday() as i32;
                let current_hour = now_utc.hour() as i32;

                if cat.weekly_release_enabled
                    && current_weekday == cat.weekly_release_weekday
                    && current_hour >= cat.weekly_release_utc_hour
                {
                    let last_rel_ref = state
                        .last_release_attempt_at
                        .or(state.last_release_success_at);
                    let already_ran_today = last_rel_ref
                        .map(|dt| dt.date_naive() == now_utc.date_naive())
                        .unwrap_or(false);

                    if !already_ran_today {
                        if let Err(e) = mgr.run_weekly_release(false, None).await {
                            tracing::warn!("Background weekly release error: {e}");
                        }
                        if let Ok(updated_state) = mgr.db.get_state().await {
                            state = updated_state;
                        }
                    }
                }

                if *shutdown_rx.borrow() {
                    break;
                }

                if cat.live_sync_interval_seconds > 0 {
                    let last_sync_ref = state.last_sync_attempt_at.or(state.last_sync_success_at);
                    let due = match last_sync_ref {
                        None => true,
                        Some(dt) => (now_utc - dt).num_seconds() >= cat.live_sync_interval_seconds,
                    };
                    if due {
                        if let Err(e) = mgr.run_live_sync(false).await {
                            tracing::warn!("Background live sync error: {e}");
                        }
                    }
                }
            }
        })
    }
}
