//! Read-only Axum HTTP service, streaming body-limit & CSP middleware, and lifecycle runner for DGIP.
//!
//! Provides 1-to-1 HTTP route, RFC 9457 `application/problem+json`, rate-limit header, ETag / `304`,
//! streaming snapshot download, CSP, and Daviante-branded Portal/Swagger parity with `app/main.py`
//! and `openapi.yaml`.

use crate::config::Settings;
use crate::db::Database;
use crate::ip_utils::{extract_client_ip, parse_and_classify_ip, ParsedIp};
use crate::models::{
    ASNInfo, BatchIPItemResult, BatchIPRequest, BatchIPResponse, GeoInfo, HealthLiveResponse,
    HealthReadyResponse, IPLookupResponse, ProblemDetails, SecurityInfo, SnapshotFileMetadata,
    SnapshotListResponse, SnapshotMetadataResponse,
};
use crate::ratelimit::SlidingWindowRateLimiter;
use crate::swagger::{
    build_branded_home_html, build_branded_openapi_schema, build_branded_swagger_html,
    resolve_brand_asset, ALLOWED_BRAND_ASSETS, DEFAULT_SWAGGER_TITLE,
};
use crate::sync::SyncManager;
use crate::types::{
    CachedArtifact, DgipError, DgipResult, RawDbMatch, ReleaseRow, RuntimeCatalog,
    ASN_IPV4_FILENAME, ASN_IPV6_FILENAME, ASN_MMDB_FILENAME, COUNTRY_IPV4_FILENAME,
    COUNTRY_IPV6_FILENAME, COUNTRY_MMDB_FILENAME, GEOFEED_FILENAME, SECURITY_IPV4_FILENAME,
    SECURITY_IPV6_FILENAME, SECURITY_MMDB_FILENAME, SEC_CDN, SEC_CLOUD, SEC_DATACENTER,
    SEC_PRIVACY_RELAY, SEC_THREAT, SEC_TOR_EXIT, VERSION,
};
use axum::body::{Body, Bytes};
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{ConnectInfo, Path as AxumPath, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Default in-memory TTL for cached `dgip_state` reads on hot lookup endpoints.
pub const STATE_CACHE_TTL_SECONDS: f64 = 1.0;

/// Fallback request body cap (256 KiB) before PostgreSQL `dgip_config` has been loaded.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 262_144;

const PROBLEM_JSON_CONTENT_TYPE: &str = "application/problem+json";

/// Strict snapshot version tag syntax (`^[A-Za-z0-9._-]{3,64}$`).
pub static VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{3,64}$").expect("Valid VERSION_RE regex"));

/// Whitelisted downloadable artifact filenames per snapshot release.
pub const ALLOWED_DOWNLOAD_FILENAMES: &[&str] = &[
    ASN_IPV4_FILENAME,
    ASN_IPV6_FILENAME,
    COUNTRY_IPV4_FILENAME,
    COUNTRY_IPV6_FILENAME,
    SECURITY_IPV4_FILENAME,
    SECURITY_IPV6_FILENAME,
    GEOFEED_FILENAME,
    ASN_MMDB_FILENAME,
    COUNTRY_MMDB_FILENAME,
    SECURITY_MMDB_FILENAME,
    "manifest.json",
    "SHA256SUMS.txt",
    "bundle.tar.gz",
];

/// Shared read-only HTTP server state.
pub struct AppState {
    pub settings: Settings,
    pub db: Arc<Database>,
    pub api_limiter: SlidingWindowRateLimiter,
    pub download_limiter: SlidingWindowRateLimiter,
}

impl AppState {
    /// Construct `AppState` with default sliding-window limiters wired to hot-reload on PostgreSQL catalog updates.
    pub fn new(settings: Settings, db: Arc<Database>) -> Arc<Self> {
        let (init_api_rpm, init_dl_rpm, init_win, init_keys) = match db.get_catalog_cached() {
            Some(cat) => (
                cat.rate_limit_per_minute,
                cat.download_rate_limit_per_minute,
                cat.rate_limit_window_seconds,
                cat.rate_limit_max_keys,
            ),
            None => (120, 30, 60.0, 50_000),
        };

        let state = Arc::new(Self {
            settings,
            db,
            api_limiter: SlidingWindowRateLimiter::new(init_api_rpm, init_win, init_keys),
            download_limiter: SlidingWindowRateLimiter::new(init_dl_rpm, init_win, init_keys),
        });

        let weak = Arc::downgrade(&state);
        state.db.add_catalog_listener(move |cat: &RuntimeCatalog| {
            if let Some(st) = weak.upgrade() {
                st.api_limiter.reconfigure(
                    cat.rate_limit_per_minute,
                    cat.rate_limit_window_seconds,
                    cat.rate_limit_max_keys,
                );
                st.download_limiter.reconfigure(
                    cat.download_rate_limit_per_minute,
                    cat.rate_limit_window_seconds,
                    cat.rate_limit_max_keys,
                );
            }
        });

        state
    }
}

/// Return the route-scoped `Content-Security-Policy` directive for `path`.
pub fn csp_for_path(path: &str) -> &'static str {
    if path == "/" {
        concat!(
            "default-src 'self'; ",
            "script-src 'self' 'unsafe-inline'; ",
            "style-src 'self' 'unsafe-inline'; ",
            "img-src 'self' data:; ",
            "connect-src 'self'; ",
            "frame-ancestors 'none'; ",
            "base-uri 'self'; ",
            "form-action 'self'"
        )
    } else if path.starts_with("/docs/assets/") {
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    } else if path == "/docs" || path.starts_with("/docs/") {
        concat!(
            "default-src 'self'; ",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; ",
            "img-src 'self' data:; ",
            "font-src 'self' https://cdn.jsdelivr.net data:; ",
            "connect-src 'self'; ",
            "frame-ancestors 'none'; ",
            "base-uri 'self'"
        )
    } else {
        "default-src 'none'; frame-ancestors 'none'"
    }
}

fn inject_security_headers(headers: &mut HeaderMap, path: &str) {
    let defaults: [(HeaderName, HeaderValue); 5] = [
        (
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        (
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ),
        (
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ),
        (
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(csp_for_path(path)),
        ),
    ];

    for (name, val) in defaults {
        if !headers.contains_key(&name) {
            headers.insert(name, val);
        }
    }
}

fn problem_response_with_headers(
    status: StatusCode,
    title: impl Into<String>,
    detail: impl Into<String>,
    instance: &str,
    extra_headers: Option<&HeaderMap>,
) -> Response {
    let body_struct =
        ProblemDetails::new(status.as_u16(), title, detail, Some(instance.to_string()));
    let payload = serde_json::to_vec(&body_struct).unwrap_or_else(|_| {
        b"{\"type\":\"about:blank\",\"title\":\"Internal Server Error\",\"status\":500,\"detail\":\"Serialization error.\"}".to_vec()
    });

    let mut resp = Response::new(Body::from(payload));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROBLEM_JSON_CONTENT_TYPE),
    );
    if let Some(extra) = extra_headers {
        for (k, v) in extra.iter() {
            resp.headers_mut().insert(k.clone(), v.clone());
        }
    }
    resp
}

fn problem_response(
    status: StatusCode,
    title: impl Into<String>,
    detail: impl Into<String>,
    instance: &str,
) -> Response {
    problem_response_with_headers(status, title, detail, instance, None)
}

fn dgip_error_response(
    err: DgipError,
    instance: &str,
    extra_headers: Option<&HeaderMap>,
) -> Response {
    match err {
        DgipError::InvalidIp(msg) => problem_response_with_headers(
            StatusCode::BAD_REQUEST,
            "Invalid IP Address",
            msg,
            instance,
            extra_headers,
        ),
        DgipError::InvalidConfig(msg) => problem_response_with_headers(
            StatusCode::BAD_REQUEST,
            "Invalid Request",
            msg,
            instance,
            extra_headers,
        ),
        DgipError::Database(msg) => {
            tracing::error!("Database error serving {instance}: {msg}");
            problem_response_with_headers(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                "Database temporarily unavailable.",
                instance,
                extra_headers,
            )
        }
        DgipError::Io(io_err) => {
            tracing::error!("I/O error serving {instance}: {io_err}");
            problem_response_with_headers(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "Artifact I/O error.",
                instance,
                extra_headers,
            )
        }
        DgipError::Compilation(msg) => {
            tracing::error!("Compilation error serving {instance}: {msg}");
            problem_response_with_headers(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                msg,
                instance,
                extra_headers,
            )
        }
    }
}

fn json_response_with_headers<T: serde::Serialize>(
    status: StatusCode,
    value: &T,
    extra_headers: Option<&HeaderMap>,
) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = status;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if let Some(extra) = extra_headers {
                for (k, v) in extra.iter() {
                    resp.headers_mut().insert(k.clone(), v.clone());
                }
            }
            resp
        }
        Err(err) => {
            tracing::error!("JSON response serialization failed: {err}");
            problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "Failed serializing JSON response.",
                "/",
            )
        }
    }
}

fn html_response(html: String) -> Response {
    let mut resp = Response::new(Body::from(html));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

#[derive(Debug, Clone)]
struct RequestMeta {
    path: String,
    peer_ip: String,
    xff: Option<String>,
    if_none_match: Option<String>,
}

impl RequestMeta {
    fn from_request(req: &Request) -> Self {
        let path = req.uri().path().to_string();
        let peer_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let if_none_match = req
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Self {
            path,
            peer_ip,
            xff,
            if_none_match,
        }
    }
}

#[allow(clippy::result_large_err)]
fn enforce_rate_limit(
    meta: &RequestMeta,
    cat: &RuntimeCatalog,
    limiter: &SlidingWindowRateLimiter,
) -> Result<(String, HeaderMap), Response> {
    let caller_ip = extract_client_ip(&meta.peer_ip, meta.xff.as_deref(), &cat.trusted_proxies);
    let decision = limiter.check(&caller_ip);

    let mut rl_headers = HeaderMap::with_capacity(4);
    for (k, v) in decision.headers() {
        if let (Ok(hname), Ok(hval)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(&v),
        ) {
            rl_headers.insert(hname, hval);
        }
    }

    if !decision.allowed {
        return Err(problem_response_with_headers(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Requests",
            "Rate limit exceeded. Retry after the indicated window.",
            &meta.path,
            Some(&rl_headers),
        ));
    }

    Ok((caller_ip, rl_headers))
}

/// Convert a parsed IP and optional PostgreSQL GiST lookup match into the public 4-layer `IPLookupResponse`.
pub fn format_lookup_response(
    parsed: &ParsedIp,
    raw_match: Option<&RawDbMatch>,
    snapshot_version: Option<&str>,
    live_updated_at: Option<DateTime<Utc>>,
) -> IPLookupResponse {
    let Some(rm) = raw_match.filter(|_| !parsed.is_bogon) else {
        return IPLookupResponse {
            ip: parsed.canonical.clone(),
            ip_version: parsed.version,
            is_ipv4_mapped: parsed.is_ipv4_mapped,
            is_bogon: parsed.is_bogon,
            bogon_type: parsed.bogon_type.clone(),
            found: false,
            asn: None,
            geo: None,
            security: None,
            snapshot_version: snapshot_version.map(str::to_string),
            live_updated_at,
        };
    };

    let asn = match (
        rm.asn,
        rm.asn_start_ip.as_deref().filter(|s| !s.is_empty()),
        rm.asn_end_ip.as_deref().filter(|s| !s.is_empty()),
    ) {
        (Some(num), Some(start), Some(end)) => Some(ASNInfo {
            number: num,
            code: format!("AS{num}"),
            organization: rm.asn_org.clone(),
            network_type: rm.network_type.clone(),
            rpki_status: Some(
                rm.rpki_status
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            range_start: start.to_string(),
            range_end: end.to_string(),
        }),
        _ => None,
    };

    let geo = match (
        rm.country_code.as_deref().filter(|s| !s.is_empty()),
        rm.country_start_ip.as_deref().filter(|s| !s.is_empty()),
        rm.country_end_ip.as_deref().filter(|s| !s.is_empty()),
    ) {
        (Some(cc), Some(start), Some(end)) => Some(GeoInfo {
            country_code: cc.to_string(),
            country_name: rm.country_name.clone(),
            continent_code: rm.continent_code.clone(),
            continent_name: rm.continent_name.clone(),
            region_code: rm.region_code.clone(),
            city: rm.city.clone(),
            source: Some(
                rm.geo_source
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "rir".to_string()),
            ),
            range_start: start.to_string(),
            range_end: end.to_string(),
        }),
        _ => None,
    };

    let sec_matched = rm.sec_flags.is_some();
    let found = asn.is_some() || geo.is_some() || sec_matched;
    let security = if found {
        if let Some(raw_flags) = rm.sec_flags {
            let flags = raw_flags.max(0) as u16;
            let threat_feeds = rm
                .sec_threat_feeds
                .as_deref()
                .map(|tf| {
                    tf.split(',')
                        .filter(|t| !t.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();

            Some(SecurityInfo {
                is_cloud: (flags & SEC_CLOUD) != 0,
                is_datacenter: (flags & SEC_DATACENTER) != 0,
                is_cdn: (flags & SEC_CDN) != 0,
                is_tor_exit: (flags & SEC_TOR_EXIT) != 0,
                is_privacy_relay: (flags & SEC_PRIVACY_RELAY) != 0,
                is_threat: (flags & SEC_THREAT) != 0,
                provider: rm.sec_provider.clone().filter(|s| !s.is_empty()),
                threat_feeds,
                range_start: rm.sec_start_ip.clone(),
                range_end: rm.sec_end_ip.clone(),
            })
        } else {
            Some(SecurityInfo::default())
        }
    } else {
        None
    };

    IPLookupResponse {
        ip: parsed.canonical.clone(),
        ip_version: parsed.version,
        is_ipv4_mapped: parsed.is_ipv4_mapped,
        is_bogon: false,
        bogon_type: None,
        found,
        asn,
        geo,
        security,
        snapshot_version: snapshot_version.map(str::to_string),
        live_updated_at,
    }
}

/// Convert a `dgip_releases` database row into `SnapshotMetadataResponse`.
pub fn row_to_snapshot_metadata(
    row: &ReleaseRow,
    current_version: Option<&str>,
) -> SnapshotMetadataResponse {
    let ver = row.version.clone();
    let manifest = if row.manifest_json.is_object() {
        row.manifest_json.clone()
    } else {
        Value::Object(Map::new())
    };

    let mut files_meta = Vec::new();
    if let Some(files_obj) = manifest.get("files").and_then(Value::as_object) {
        let mut sorted_names: Vec<&String> = files_obj.keys().collect();
        sorted_names.sort();
        for fname in sorted_names {
            if let Some(finfo) = files_obj.get(fname) {
                let sha256 = finfo
                    .get("sha256")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let size_bytes = finfo
                    .get("size_bytes")
                    .and_then(|v| {
                        v.as_u64()
                            .or_else(|| v.as_i64().filter(|&n| n >= 0).map(|n| n as u64))
                    })
                    .unwrap_or(0);
                let record_count = finfo.get("record_count").and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_i64().filter(|&n| n >= 0).map(|n| n as u64))
                });
                files_meta.push(SnapshotFileMetadata {
                    filename: fname.clone(),
                    sha256,
                    size_bytes,
                    record_count,
                    download_path: format!("/v1/snapshots/{ver}/files/{fname}"),
                });
            }
        }
    }

    let diff_summary = if row.diff_summary_json.is_object() {
        row.diff_summary_json.clone()
    } else {
        Value::Object(Map::new())
    };

    let update_available = current_version.map(|cv| cv.trim() != ver);

    SnapshotMetadataResponse {
        version: ver.clone(),
        release_title: row.release_title.clone(),
        build_number: row.build_number,
        released_at: row.released_at,
        previous_version: row.previous_version.clone(),
        bundle_sha256: row.bundle_sha256.clone(),
        bundle_size_bytes: row.bundle_size_bytes,
        bundle_download_path: format!("/v1/snapshots/{ver}/bundle.tar.gz"),
        sha256sums_download_path: format!("/v1/snapshots/{ver}/files/SHA256SUMS.txt"),
        has_blobs: row.has_blobs,
        row_counts: row.row_counts.clone(),
        diff_summary,
        release_notes_md: row.release_notes_md.clone(),
        operator_note: row.operator_note.clone(),
        files: files_meta,
        manifest,
        source_attribution: row.source_attribution.clone(),
        installed_version: current_version.map(str::to_string),
        update_available,
    }
}

fn etag_matches(if_none_match: &str, strong_etag: &str) -> bool {
    let weak_etag = format!("W/{strong_etag}");
    if_none_match.split(',').any(|raw_item| {
        let candidate = raw_item.trim();
        candidate == "*" || candidate == strong_etag || candidate == weak_etag
    })
}

async fn serve_artifact(
    if_none_match: Option<&str>,
    artifact: CachedArtifact,
    cache_control_value: &str,
    rl_headers: &HeaderMap,
    instance: &str,
) -> Response {
    let etag = format!("\"{}\"", artifact.sha256);

    let mut common_headers = rl_headers.clone();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        common_headers.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&artifact.sha256) {
        common_headers.insert(HeaderName::from_static("x-checksum-sha256"), v);
    }
    if let Ok(v) = HeaderValue::from_str(cache_control_value) {
        common_headers.insert(header::CACHE_CONTROL, v);
    }
    let disposition = format!("attachment; filename=\"{}\"", artifact.filename);
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        common_headers.insert(header::CONTENT_DISPOSITION, v);
    }

    if let Some(inm) = if_none_match {
        if etag_matches(inm, &etag) {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            for (k, v) in common_headers.iter() {
                resp.headers_mut().insert(k.clone(), v.clone());
            }
            return resp;
        }
    }

    let file = match tokio::fs::File::open(&artifact.path).await {
        Ok(f) => f,
        Err(io_err) => {
            return dgip_error_response(DgipError::Io(io_err), instance, Some(rl_headers));
        }
    };

    let stream = ReaderStream::new(file);
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = StatusCode::OK;

    let ctype = HeaderValue::from_str(&artifact.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    resp.headers_mut().insert(header::CONTENT_TYPE, ctype);

    if let Ok(cl_val) = HeaderValue::from_str(&artifact.size_bytes.to_string()) {
        resp.headers_mut().insert(header::CONTENT_LENGTH, cl_val);
    }

    for (k, v) in common_headers.iter() {
        resp.headers_mut().insert(k.clone(), v.clone());
    }
    resp
}

async fn is_swagger_enabled(state: &AppState) -> bool {
    if !state.settings.swagger_enabled {
        return false;
    }
    if state.db.get_catalog_cached().is_some() {
        let cat = state
            .db
            .ensure_catalog_fresh(false)
            .await
            .ok()
            .or_else(|| state.db.get_catalog_cached());
        if let Some(c) = cat {
            return c.swagger_enabled;
        }
    }
    true
}

#[allow(clippy::result_large_err)]
async fn ensure_swagger_enabled(state: &AppState, instance: &str) -> Result<(), Response> {
    if !state.settings.swagger_enabled {
        return Err(problem_response(
            StatusCode::NOT_FOUND,
            "Documentation Disabled",
            "Interactive Swagger documentation is disabled (DGIP_SWAGGER_ENABLED=false).",
            instance,
        ));
    }

    if state.db.get_catalog_cached().is_some() {
        let cat = state
            .db
            .ensure_catalog_fresh(false)
            .await
            .ok()
            .or_else(|| state.db.get_catalog_cached());
        if let Some(c) = cat {
            if !c.swagger_enabled {
                return Err(problem_response(
                    StatusCode::NOT_FOUND,
                    "Documentation Disabled",
                    "Interactive Swagger documentation is disabled in runtime configuration.",
                    instance,
                ));
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Middleware: Streaming Body Limit + Security Headers + Route-Aware CSP
// -----------------------------------------------------------------------------

async fn outer_security_headers_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let mut resp = next.run(req).await;
    inject_security_headers(resp.headers_mut(), &path);
    resp
}

async fn security_and_body_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method_str = req.method().to_string();
    let max_body = state
        .db
        .get_catalog_cached()
        .map(|c| c.max_request_body_bytes)
        .unwrap_or(DEFAULT_MAX_REQUEST_BODY_BYTES);

    // 1. Fast-reject oversized Content-Length before reading socket chunks.
    if let Some(cl_hdr) = req.headers().get(header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_hdr.to_str() {
            if let Ok(cl_val) = cl_str.trim().parse::<i64>() {
                if cl_val < 0 || usize::try_from(cl_val).map_or(true, |n| n > max_body) {
                    let mut resp = problem_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Payload Too Large",
                        format!("Request body exceeds maximum size of {max_body} bytes."),
                        &path,
                    );
                    inject_security_headers(resp.headers_mut(), &path);
                    return resp;
                }
            }
        }
    }

    // 2. Stream chunk-by-chunk so `Transfer-Encoding: chunked` payloads are bounded byte-by-byte.
    let (parts, body) = req.into_parts();
    let mut stream = body.into_data_stream();
    let mut buf = BytesMut::new();

    while let Some(chunk_res) = stream.next().await {
        match chunk_res {
            Ok(chunk) => {
                if buf.len().saturating_add(chunk.len()) > max_body {
                    let mut resp = problem_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Payload Too Large",
                        format!("Request body exceeds maximum size of {max_body} bytes."),
                        &path,
                    );
                    inject_security_headers(resp.headers_mut(), &path);
                    return resp;
                }
                buf.extend_from_slice(&chunk);
            }
            Err(err) => {
                let mut resp = problem_response(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    format!("Failed reading request body: {err}"),
                    &path,
                );
                inject_security_headers(resp.headers_mut(), &path);
                return resp;
            }
        }
    }

    let rebuilt = Request::from_parts(parts, Body::from(buf.freeze()));
    let mut resp = next.run(rebuilt).await;

    if resp.status() == StatusCode::METHOD_NOT_ALLOWED
        && resp.headers().get(header::CONTENT_TYPE).is_none()
    {
        let allow_hdr = resp.headers().get(header::ALLOW).cloned();
        resp = problem_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
            format!("HTTP method {method_str} is not allowed for this resource."),
            &path,
        );
        if let Some(allow) = allow_hdr {
            resp.headers_mut().insert(header::ALLOW, allow);
        }
    }

    inject_security_headers(resp.headers_mut(), &path);
    resp
}

// -----------------------------------------------------------------------------
// Route Handlers
// -----------------------------------------------------------------------------

async fn home_portal(State(state): State<Arc<AppState>>) -> Response {
    let swagger_on = is_swagger_enabled(&state).await;
    html_response(build_branded_home_html(VERSION, swagger_on))
}

async fn swagger_documentation(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    drop(req);
    if let Err(err_resp) = ensure_swagger_enabled(&state, &path).await {
        return err_resp;
    }
    html_response(build_branded_swagger_html(
        DEFAULT_SWAGGER_TITLE,
        "/openapi.json",
    ))
}

async fn openapi_json_spec(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    drop(req);
    if let Err(err_resp) = ensure_swagger_enabled(&state, &path).await {
        return err_resp;
    }
    let schema = build_branded_openapi_schema();
    json_response_with_headers(StatusCode::OK, &schema, None)
}

async fn swagger_brand_asset(
    State(state): State<Arc<AppState>>,
    asset_param: Result<AxumPath<String>, PathRejection>,
    req: Request,
) -> Response {
    let path = req.uri().path().to_string();
    drop(req);
    if let Err(err_resp) = ensure_swagger_enabled(&state, &path).await {
        return err_resp;
    }

    let AxumPath(asset_name) = match asset_param {
        Ok(p) => p,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &path,
            );
        }
    };

    if !ALLOWED_BRAND_ASSETS
        .iter()
        .any(|&(allowed, _)| allowed == asset_name)
    {
        return problem_response(
            StatusCode::NOT_FOUND,
            "Asset Not Found",
            format!("Unknown brand asset: {asset_name:?}"),
            &path,
        );
    }

    let Some((svg_bytes, content_type)) =
        resolve_brand_asset(&state.settings.assets_dir, &asset_name)
    else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "Asset Not Found",
            format!("Brand asset {asset_name:?} is unavailable on disk."),
            &path,
        );
    };

    let mut resp = Response::new(Body::from(svg_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("image/svg+xml")),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    resp
}

async fn health_live() -> Response {
    let body = HealthLiveResponse {
        status: "ok".to_string(),
        version: VERSION.to_string(),
    };
    json_response_with_headers(StatusCode::OK, &body, None)
}

async fn health_ready(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    drop(req);
    if !state.db.ping().await {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "PostgreSQL connection check failed.",
            &path,
        );
    }

    let db_state = match state.db.get_state().await {
        Ok(s) => s,
        Err(err) => return dgip_error_response(err, &path, None),
    };

    if db_state.active_slot != "a" && db_state.active_slot != "b" {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Dataset Not Ready",
            "Initial IP lookup slot is still loading.",
            &path,
        );
    }

    let body = HealthReadyResponse {
        status: "ready".to_string(),
        active_slot: db_state.active_slot,
        active_version: db_state.active_version,
        initial_bootstrapped: db_state.initial_bootstrapped,
    };
    json_response_with_headers(StatusCode::OK, &body, None)
}

async fn lookup_caller_ip(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.api_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let parsed = match parse_and_classify_ip(
        &caller_ip,
        Some(&cat.special_v4_rules),
        Some(&cat.special_v6_rules),
    ) {
        Ok(p) => p,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let db_state = match state.db.get_state_cached(STATE_CACHE_TTL_SECONDS).await {
        Ok(s) => s,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    if db_state.active_slot != "a" && db_state.active_slot != "b" {
        return problem_response_with_headers(
            StatusCode::SERVICE_UNAVAILABLE,
            "Dataset Not Ready",
            "IP lookup tables are still initializing.",
            &meta.path,
            Some(&rl_headers),
        );
    }

    let raw_match = if parsed.is_bogon {
        None
    } else {
        match state
            .db
            .lookup_single(
                &db_state.active_slot,
                parsed.version,
                parsed.v4_int,
                parsed.v6_int,
            )
            .await
        {
            Ok(m) => Some(m),
            Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
        }
    };

    let payload = format_lookup_response(
        &parsed,
        raw_match.as_ref(),
        db_state.active_version.as_deref(),
        db_state.live_updated_at,
    );
    json_response_with_headers(StatusCode::OK, &payload, Some(&rl_headers))
}

async fn lookup_single_ip(
    State(state): State<Arc<AppState>>,
    ip_param: Result<AxumPath<String>, PathRejection>,
    req: Request,
) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let AxumPath(raw_ip) = match ip_param {
        Ok(p) => p,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &meta.path,
            );
        }
    };

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.api_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let parsed = match parse_and_classify_ip(
        &raw_ip,
        Some(&cat.special_v4_rules),
        Some(&cat.special_v6_rules),
    ) {
        Ok(p) => p,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let db_state = match state.db.get_state_cached(STATE_CACHE_TTL_SECONDS).await {
        Ok(s) => s,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    if db_state.active_slot != "a" && db_state.active_slot != "b" {
        return problem_response_with_headers(
            StatusCode::SERVICE_UNAVAILABLE,
            "Dataset Not Ready",
            "IP lookup tables are still initializing.",
            &meta.path,
            Some(&rl_headers),
        );
    }

    let raw_match = if parsed.is_bogon {
        None
    } else {
        match state
            .db
            .lookup_single(
                &db_state.active_slot,
                parsed.version,
                parsed.v4_int,
                parsed.v6_int,
            )
            .await
        {
            Ok(m) => Some(m),
            Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
        }
    };

    let payload = format_lookup_response(
        &parsed,
        raw_match.as_ref(),
        db_state.active_version.as_deref(),
        db_state.live_updated_at,
    );
    json_response_with_headers(StatusCode::OK, &payload, Some(&rl_headers))
}

async fn lookup_batch_ips(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let meta = RequestMeta::from_request(&req);
    let body_bytes: Bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(err) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
                format!("Failed reading request body: {err}"),
                &meta.path,
            );
        }
    };

    let batch_req: BatchIPRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed_req) => parsed_req,
        Err(err) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                format!("Invalid batch request JSON: {err}"),
                &meta.path,
            );
        }
    };

    if batch_req.ips.is_empty() {
        return problem_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unprocessable Content",
            "List 'ips' must contain at least 1 item.",
            &meta.path,
        );
    }

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.api_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    if batch_req.ips.len() > cat.max_batch_size {
        return problem_response_with_headers(
            StatusCode::BAD_REQUEST,
            "Batch Size Exceeded",
            format!("Maximum batch size is {} IP addresses.", cat.max_batch_size),
            &meta.path,
            Some(&rl_headers),
        );
    }

    let db_state = match state.db.get_state_cached(STATE_CACHE_TTL_SECONDS).await {
        Ok(s) => s,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    if db_state.active_slot != "a" && db_state.active_slot != "b" {
        return problem_response_with_headers(
            StatusCode::SERVICE_UNAVAILABLE,
            "Dataset Not Ready",
            "IP lookup tables are still initializing.",
            &meta.path,
            Some(&rl_headers),
        );
    }

    let mut parsed_items: Vec<(String, Result<ParsedIp, String>)> =
        Vec::with_capacity(batch_req.ips.len());
    let mut v4_set: BTreeSet<u32> = BTreeSet::new();
    let mut v6_set: BTreeSet<u128> = BTreeSet::new();

    for raw_ip in batch_req.ips {
        match parse_and_classify_ip(
            &raw_ip,
            Some(&cat.special_v4_rules),
            Some(&cat.special_v6_rules),
        ) {
            Ok(p) => {
                if !p.is_bogon {
                    if p.version == 4 {
                        v4_set.insert(p.v4_int);
                    } else {
                        v6_set.insert(p.v6_int);
                    }
                }
                parsed_items.push((raw_ip, Ok(p)));
            }
            Err(err) => {
                parsed_items.push((raw_ip, Err(err.to_string())));
            }
        }
    }

    let v4_vec: Vec<u32> = v4_set.into_iter().collect();
    let v6_vec: Vec<u128> = v6_set.into_iter().collect();

    let (v4_map, v6_map) = match state
        .db
        .lookup_batch(&db_state.active_slot, &v4_vec, &v6_vec)
        .await
    {
        Ok(maps) => maps,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let snap_ver = db_state.active_version.clone();
    let live_ts = db_state.live_updated_at;

    let mut results = Vec::with_capacity(parsed_items.len());
    for (raw_ip, item_res) in parsed_items {
        match item_res {
            Ok(parsed_ip) => {
                let raw_match = if parsed_ip.is_bogon {
                    None
                } else if parsed_ip.version == 4 {
                    v4_map.get(&parsed_ip.v4_int)
                } else {
                    v6_map.get(&parsed_ip.v6_int)
                };
                results.push(BatchIPItemResult {
                    input: raw_ip,
                    ok: true,
                    data: Some(format_lookup_response(
                        &parsed_ip,
                        raw_match,
                        snap_ver.as_deref(),
                        live_ts,
                    )),
                    error: None,
                });
            }
            Err(err_msg) => {
                results.push(BatchIPItemResult {
                    input: raw_ip,
                    ok: false,
                    data: None,
                    error: Some(err_msg),
                });
            }
        }
    }

    let response_body = BatchIPResponse {
        count: results.len(),
        snapshot_version: snap_ver,
        live_updated_at: live_ts,
        results,
    };
    json_response_with_headers(StatusCode::OK, &response_body, Some(&rl_headers))
}

async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    query_res: Result<Query<HashMap<String, String>>, QueryRejection>,
    req: Request,
) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let Query(params) = match query_res {
        Ok(q) => q,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &meta.path,
            );
        }
    };

    let limit: i64 = match params.get("limit") {
        None => 20,
        Some(raw) => match raw.trim().parse::<i64>() {
            Ok(val) if (1..=100).contains(&val) => val,
            _ => {
                return problem_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Unprocessable Content",
                    "Query parameter 'limit' must be an integer between 1 and 100.",
                    &meta.path,
                );
            }
        },
    };

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.api_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let db_state = match state.db.get_state_cached(STATE_CACHE_TTL_SECONDS).await {
        Ok(s) => s,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let rows = match state.db.list_releases(limit).await {
        Ok(r) => r,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let body = SnapshotListResponse {
        active_version: db_state.active_version,
        retention_limit: cat.snapshot_retention,
        snapshots: rows
            .iter()
            .map(|r| row_to_snapshot_metadata(r, None))
            .collect(),
    };
    json_response_with_headers(StatusCode::OK, &body, Some(&rl_headers))
}

async fn get_latest_snapshot(
    State(state): State<Arc<AppState>>,
    query_res: Result<Query<HashMap<String, String>>, QueryRejection>,
    req: Request,
) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let Query(params) = match query_res {
        Ok(q) => q,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &meta.path,
            );
        }
    };

    let current_version = params.get("current_version").cloned();
    if let Some(ref cv) = current_version {
        if cv.chars().count() > 64 {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                "Query parameter 'current_version' must be at most 64 characters.",
                &meta.path,
            );
        }
    }

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, mut rl_headers) = match enforce_rate_limit(&meta, &cat, &state.api_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let row_opt = match state.db.get_release(None).await {
        Ok(r) => r,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let Some(row) = row_opt else {
        return problem_response_with_headers(
            StatusCode::SERVICE_UNAVAILABLE,
            "Snapshot Unavailable",
            "No dataset snapshot has been cut yet.",
            &meta.path,
            Some(&rl_headers),
        );
    };

    let cc_val = format!("public, max-age={}", cat.snapshot_latest_cache_max_age);
    if let Ok(hv) = HeaderValue::from_str(&cc_val) {
        rl_headers.insert(header::CACHE_CONTROL, hv);
    }

    let body = row_to_snapshot_metadata(&row, current_version.as_deref());
    json_response_with_headers(StatusCode::OK, &body, Some(&rl_headers))
}

async fn get_snapshot_by_version(
    State(state): State<Arc<AppState>>,
    ver_param: Result<AxumPath<String>, PathRejection>,
    req: Request,
) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let AxumPath(version) = match ver_param {
        Ok(v) => v,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &meta.path,
            );
        }
    };

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.api_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    if !VERSION_RE.is_match(&version) {
        return problem_response_with_headers(
            StatusCode::BAD_REQUEST,
            "Invalid Version Tag",
            format!("Malformed snapshot version identifier: {version:?}"),
            &meta.path,
            Some(&rl_headers),
        );
    }

    let row_opt = match state.db.get_release(Some(&version)).await {
        Ok(r) => r,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let Some(row) = row_opt else {
        return problem_response_with_headers(
            StatusCode::NOT_FOUND,
            "Snapshot Not Found",
            format!("Snapshot {version:?} does not exist."),
            &meta.path,
            Some(&rl_headers),
        );
    };

    let body = row_to_snapshot_metadata(&row, None);
    json_response_with_headers(StatusCode::OK, &body, Some(&rl_headers))
}

async fn download_snapshot_bundle(
    State(state): State<Arc<AppState>>,
    ver_param: Result<AxumPath<String>, PathRejection>,
    req: Request,
) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let AxumPath(version) = match ver_param {
        Ok(v) => v,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &meta.path,
            );
        }
    };

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.download_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let (resolved_version, cache_control) = if version == "latest" {
        let rel_opt = match state.db.get_release(None).await {
            Ok(r) => r,
            Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
        };
        let Some(rel) = rel_opt else {
            return problem_response_with_headers(
                StatusCode::SERVICE_UNAVAILABLE,
                "Snapshot Unavailable",
                "No dataset snapshot has been cut yet.",
                &meta.path,
                Some(&rl_headers),
            );
        };
        (
            rel.version,
            format!("public, max-age={}", cat.snapshot_latest_cache_max_age),
        )
    } else {
        if !VERSION_RE.is_match(&version) {
            return problem_response_with_headers(
                StatusCode::BAD_REQUEST,
                "Invalid Version Tag",
                format!("Malformed snapshot version identifier: {version:?}"),
                &meta.path,
                Some(&rl_headers),
            );
        }
        (
            version,
            format!(
                "public, max-age={}, immutable",
                cat.snapshot_immutable_cache_max_age
            ),
        )
    };

    let artifact_opt = match state
        .db
        .resolve_download_artifact(&resolved_version, "bundle.tar.gz")
        .await
    {
        Ok(a) => a,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let Some(artifact) = artifact_opt else {
        let rel_opt = match state.db.get_release(Some(&resolved_version)).await {
            Ok(r) => r,
            Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
        };
        if let Some(rel) = rel_opt {
            if !rel.has_blobs {
                return problem_response_with_headers(
                    StatusCode::GONE,
                    "Snapshot Artifacts Expired",
                    format!(
                        "Binary artifacts for {resolved_version:?} have been pruned by retention policy."
                    ),
                    &meta.path,
                    Some(&rl_headers),
                );
            }
        }
        return problem_response_with_headers(
            StatusCode::NOT_FOUND,
            "Snapshot Not Found",
            format!("Bundle for snapshot {resolved_version:?} was not found."),
            &meta.path,
            Some(&rl_headers),
        );
    };

    serve_artifact(
        meta.if_none_match.as_deref(),
        artifact,
        &cache_control,
        &rl_headers,
        &meta.path,
    )
    .await
}

async fn download_snapshot_file(
    State(state): State<Arc<AppState>>,
    params_res: Result<AxumPath<(String, String)>, PathRejection>,
    req: Request,
) -> Response {
    let meta = RequestMeta::from_request(&req);
    drop(req);

    let AxumPath((version, filename)) = match params_res {
        Ok(p) => p,
        Err(rej) => {
            return problem_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Content",
                rej.body_text(),
                &meta.path,
            );
        }
    };

    let cat = match state.db.ensure_catalog_fresh(false).await {
        Ok(c) => c,
        Err(err) => return dgip_error_response(err, &meta.path, None),
    };

    let (_caller_ip, rl_headers) = match enforce_rate_limit(&meta, &cat, &state.download_limiter) {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };

    let (resolved_version, cache_control) = if version == "latest" {
        if !ALLOWED_DOWNLOAD_FILENAMES.contains(&filename.as_str()) {
            return problem_response_with_headers(
                StatusCode::NOT_FOUND,
                "Artifact Not Found",
                format!("Unknown snapshot artifact filename: {filename:?}"),
                &meta.path,
                Some(&rl_headers),
            );
        }
        let rel_opt = match state.db.get_release(None).await {
            Ok(r) => r,
            Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
        };
        let Some(rel) = rel_opt else {
            return problem_response_with_headers(
                StatusCode::SERVICE_UNAVAILABLE,
                "Snapshot Unavailable",
                "No dataset snapshot has been cut yet.",
                &meta.path,
                Some(&rl_headers),
            );
        };
        (
            rel.version,
            format!("public, max-age={}", cat.snapshot_latest_cache_max_age),
        )
    } else {
        if !VERSION_RE.is_match(&version) {
            return problem_response_with_headers(
                StatusCode::BAD_REQUEST,
                "Invalid Version Tag",
                format!("Malformed snapshot version identifier: {version:?}"),
                &meta.path,
                Some(&rl_headers),
            );
        }
        if !ALLOWED_DOWNLOAD_FILENAMES.contains(&filename.as_str()) {
            return problem_response_with_headers(
                StatusCode::NOT_FOUND,
                "Artifact Not Found",
                format!("Unknown snapshot artifact filename: {filename:?}"),
                &meta.path,
                Some(&rl_headers),
            );
        }
        (
            version,
            format!(
                "public, max-age={}, immutable",
                cat.snapshot_immutable_cache_max_age
            ),
        )
    };

    let artifact_opt = match state
        .db
        .resolve_download_artifact(&resolved_version, &filename)
        .await
    {
        Ok(a) => a,
        Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
    };

    let Some(artifact) = artifact_opt else {
        let rel_opt = match state.db.get_release(Some(&resolved_version)).await {
            Ok(r) => r,
            Err(err) => return dgip_error_response(err, &meta.path, Some(&rl_headers)),
        };
        if let Some(rel) = rel_opt {
            if !rel.has_blobs {
                return problem_response_with_headers(
                    StatusCode::GONE,
                    "Snapshot Artifacts Expired",
                    format!(
                        "Binary artifacts for {resolved_version:?} have been pruned by retention policy."
                    ),
                    &meta.path,
                    Some(&rl_headers),
                );
            }
        }
        return problem_response_with_headers(
            StatusCode::NOT_FOUND,
            "Artifact Not Found",
            format!("File {filename:?} for snapshot {resolved_version:?} was not found."),
            &meta.path,
            Some(&rl_headers),
        );
    };

    serve_artifact(
        meta.if_none_match.as_deref(),
        artifact,
        &cache_control,
        &rl_headers,
        &meta.path,
    )
    .await
}

async fn not_found_fallback(req: Request) -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "Not Found",
        "The requested resource was not found.",
        req.uri().path(),
    )
}

fn build_cors_layer(settings: &Settings) -> Option<CorsLayer> {
    let origins = settings.parsed_cors_origins();
    if origins.is_empty() {
        return None;
    }

    let allow_origin = if origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        let parsed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        if parsed.is_empty() {
            return None;
        }
        AllowOrigin::list(parsed)
    };

    Some(
        CorsLayer::new()
            .allow_origin(allow_origin)
            .allow_methods([Method::GET, Method::POST, Method::HEAD, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::IF_NONE_MATCH])
            .expose_headers([
                header::ETAG,
                HeaderName::from_static("x-checksum-sha256"),
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderName::from_static("x-ratelimit-reset"),
                header::RETRY_AFTER,
            ]),
    )
}

/// Construct the read-only Axum `Router` with streaming body limits, security headers, CSP, and CORS.
pub fn build_router(state: Arc<AppState>) -> Router {
    let baseline_ver = state.db.get_catalog_cached().map(|c| c.catalog_version);
    let weak = Arc::downgrade(&state);
    state.db.add_catalog_listener(move |cat: &RuntimeCatalog| {
        if baseline_ver.map_or(cat.catalog_version > 1, |bv| cat.catalog_version > bv) {
            if let Some(st) = weak.upgrade() {
                st.api_limiter.reconfigure(
                    cat.rate_limit_per_minute,
                    cat.rate_limit_window_seconds,
                    cat.rate_limit_max_keys,
                );
                st.download_limiter.reconfigure(
                    cat.download_rate_limit_per_minute,
                    cat.rate_limit_window_seconds,
                    cat.rate_limit_max_keys,
                );
            }
        }
    });

    let cors_opt = build_cors_layer(&state.settings);

    let mut router = Router::new()
        .route("/", get(home_portal))
        .route("/docs", get(swagger_documentation))
        .route("/openapi.json", get(openapi_json_spec))
        .route("/docs/assets/:asset_name", get(swagger_brand_asset))
        .route("/healthz/live", get(health_live))
        .route("/healthz/ready", get(health_ready))
        .route("/v1/ip/me", get(lookup_caller_ip))
        .route("/v1/ip/:ip", get(lookup_single_ip))
        .route("/v1/ip/batch", post(lookup_batch_ips))
        .route("/v1/snapshots", get(list_snapshots))
        .route("/v1/snapshots/latest", get(get_latest_snapshot))
        .route("/v1/snapshots/:version", get(get_snapshot_by_version))
        .route(
            "/v1/snapshots/:version/bundle.tar.gz",
            get(download_snapshot_bundle),
        )
        .route(
            "/v1/snapshots/:version/files/:filename",
            get(download_snapshot_file),
        )
        .fallback(not_found_fallback)
        .with_state(Arc::clone(&state))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            security_and_body_limit_middleware,
        ));

    if let Some(cors) = cors_opt {
        router = router.layer(cors);
    }

    router.layer(middleware::from_fn(outer_security_headers_middleware))
}

/// Construct an offline-capable `(Router, Arc<AppState>)` pair from `Settings`.
pub fn create_app(settings: Settings) -> DgipResult<(Router, Arc<AppState>)> {
    let db = Database::new(settings.clone())?;
    let state = AppState::new(settings, db);
    let router = build_router(Arc::clone(&state));
    Ok((router, state))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("Shutdown signal received; draining HTTP server and background tasks...");
}

/// Initialize PostgreSQL schema/catalog, start background bootstrap & sync scheduler, and serve Axum HTTP.
pub async fn run_http_server(settings: Settings) -> DgipResult<()> {
    let db = Database::new(settings.clone())?;
    let state = AppState::new(settings.clone(), Arc::clone(&db));
    let sync_manager = SyncManager::new(settings.clone(), Arc::clone(&db));

    db.startup().await?;
    let sched_handle = sync_manager.start_background_tasks();

    let router = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind((settings.host.as_str(), settings.port)).await?;
    let bound_addr = listener.local_addr()?;
    tracing::info!(
        "DGIP v{} read-only HTTP server listening on http://{}",
        VERSION,
        bound_addr
    );

    let serve_result = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;

    sync_manager.shutdown().await;
    sched_handle.abort();
    let _ = sched_handle.await;
    db.shutdown().await;

    serve_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    async fn read_body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
            .await
            .expect("read response body");
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    #[tokio::test]
    async fn test_portal_swagger_openapi_csp_and_disabled_gate() {
        let (app_on, _) = create_app(Settings {
            swagger_enabled: true,
            ..Settings::default()
        })
        .expect("create_app");

        // 1. GET /healthz/live + hardened default CSP
        let live_resp = app_on
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live_resp.status(), StatusCode::OK);
        assert_eq!(
            live_resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(live_resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            live_resp.headers().get("referrer-policy").unwrap(),
            "no-referrer"
        );
        assert!(live_resp
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("default-src 'none'"));

        // 2. GET / zero-CDN interactive portal
        let home_resp = app_on
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(home_resp.status(), StatusCode::OK);
        let home_csp = home_resp
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!home_csp.contains("cdn.jsdelivr.net"));
        assert!(home_csp.contains("script-src 'self' 'unsafe-inline'"));
        let home_html = read_body_string(home_resp).await;
        assert!(home_html.contains("Network Registry &amp; Routing Intelligence"));
        assert!(home_html.contains("id=\"dg-lookup-form\""));
        assert!(home_html.contains("href=\"/docs\""));

        // 3. GET /docs + GET /openapi.json + GET /docs/assets/*.svg
        let docs_resp = app_on
            .clone()
            .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(docs_resp.status(), StatusCode::OK);
        assert!(docs_resp
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("https://cdn.jsdelivr.net"));
        let docs_html = read_body_string(docs_resp).await;
        assert!(docs_html.contains("SwaggerUIBundle"));

        let schema_resp = app_on
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(schema_resp.status(), StatusCode::OK);
        let schema_txt = read_body_string(schema_resp).await;
        let schema: Value = serde_json::from_str(&schema_txt).unwrap();
        assert_eq!(schema["info"]["license"]["name"], "Apache-2.0");
        assert!(schema["components"].get("securitySchemes").is_none());

        for svg_name in ["logo.svg", "logo-dark.svg", "favicon.svg"] {
            let svg_resp = app_on
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/docs/assets/{svg_name}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(svg_resp.status(), StatusCode::OK);
            assert!(svg_resp
                .headers()
                .get("content-security-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("style-src 'unsafe-inline'"));
            let svg_body = read_body_string(svg_resp).await;
            assert!(svg_body.contains("<svg"));
        }

        // 4. Disabled Swagger mode gates /docs, /openapi.json, and /docs/assets/* with 404 ProblemDetails
        let (app_off, _) = create_app(Settings {
            swagger_enabled: false,
            ..Settings::default()
        })
        .expect("create_app off");

        for blocked in ["/docs", "/openapi.json", "/docs/assets/logo.svg"] {
            let off_resp = app_off
                .clone()
                .oneshot(Request::builder().uri(blocked).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(off_resp.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                off_resp.headers().get(header::CONTENT_TYPE).unwrap(),
                PROBLEM_JSON_CONTENT_TYPE
            );
        }

        let home_off = app_off
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(home_off.status(), StatusCode::OK);
        let home_off_html = read_body_string(home_off).await;
        assert!(!home_off_html.contains("href=\"/docs\""));
        assert!(!home_off_html.contains("href=\"/openapi.json\""));
    }

    #[tokio::test]
    async fn test_streaming_body_limit_and_readonly_surface() {
        let (app, _) = create_app(Settings::default()).expect("create_app");

        // Streaming chunked body without Content-Length exceeding 256 KiB -> 413 ProblemDetails
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            (0..40).map(|_| Ok(Bytes::from(vec![b'a'; 8192]))).collect();
        let stream_body = Body::from_stream(futures_util::stream::iter(chunks));

        let resp_413 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/ip/batch")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(stream_body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_413.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp_413.headers().get(header::CONTENT_TYPE).unwrap(),
            PROBLEM_JSON_CONTENT_TYPE
        );

        // No /v1/admin/* routes exist
        for (method, admin_path) in [
            (Method::GET, "/v1/admin/status"),
            (Method::GET, "/v1/admin/catalog"),
            (Method::POST, "/v1/admin/sync"),
            (Method::POST, "/v1/admin/releases"),
            (Method::PATCH, "/v1/admin/config"),
            (Method::POST, "/v1/admin/reload"),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(admin_path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                PROBLEM_JSON_CONTENT_TYPE
            );
        }
    }
}
