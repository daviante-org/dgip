//! PostgreSQL connection pool, dynamic catalog loader, GiST range queries, and BYTEA cache.

use crate::config::Settings;
use crate::ip_utils::compile_special_ranges;
use crate::seed_data::{
    build_default_config_entries, build_default_feed_sources, DEFAULT_ALLOWED_HOSTS,
    DEFAULT_CONTINENTS, DEFAULT_COUNTRIES, DEFAULT_SOURCE_ATTRIBUTION, DEFAULT_SPECIAL_RANGES,
};
use crate::types::{
    format_ipv4, format_ipv6, AsnRow, CachedArtifact, CompiledTables, CountryRow, DbState,
    DgipError, DgipResult, FeedSourceSpec, IpNet, PackagedSnapshot, RawDbMatch, ReleaseRow,
    RuntimeCatalog, SecurityRow, ADVISORY_LOCK_KEY,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures_util::SinkExt;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;
use tokio_postgres::config::SslMode;
use tokio_postgres::Row;
use tokio_postgres_rustls::MakeRustlsConnect;

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS dgip_state (
    id                      SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    catalog_seeded          BOOLEAN NOT NULL DEFAULT FALSE,
    catalog_version         BIGINT NOT NULL DEFAULT 1,
    initial_bootstrapped    BOOLEAN NOT NULL DEFAULT FALSE,
    active_slot             TEXT NOT NULL DEFAULT '',
    live_feed_sha256        TEXT,
    live_row_counts         JSONB,
    live_updated_at         TIMESTAMPTZ,
    active_version          TEXT,
    last_sync_attempt_at    TIMESTAMPTZ,
    last_sync_success_at    TIMESTAMPTZ,
    last_sync_error         TEXT,
    last_release_attempt_at TIMESTAMPTZ,
    last_release_success_at TIMESTAMPTZ,
    last_release_error      TEXT,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO dgip_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS dgip_config (
    key         TEXT PRIMARY KEY,
    value_json  JSONB NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgip_feed_sources (
    feed_key                TEXT PRIMARY KEY,
    kind                    TEXT NOT NULL CHECK (kind IN (
                                'rir_delegated', 'ris_bgp', 'asn_names',
                                'geofeed_rfc8805', 'cloud_gcp_json', 'cloud_oracle_json',
                                'rpki_vrps_csv', 'asn_classes_csv',
                                'cdn_cidr_list', 'cdn_fastly_json', 'cloud_github_json',
                                'tor_exit_list', 'spamhaus_drop_json', 'threat_ip_list'
                            )),
    ip_version              SMALLINT NOT NULL CHECK (ip_version IN (0, 4, 6)),
    source_url              TEXT NOT NULL,
    min_records             INTEGER NOT NULL DEFAULT 1000,
    max_compressed_bytes    BIGINT NOT NULL DEFAULT 67108864,
    max_uncompressed_bytes  BIGINT NOT NULL DEFAULT 268435456,
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    display_order           SMALLINT NOT NULL DEFAULT 10,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgip_allowed_hosts (
    hostname    TEXT PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    notes       TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgip_continents (
    continent_code CHAR(2) PRIMARY KEY,
    continent_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dgip_countries (
    country_code   CHAR(2) PRIMARY KEY,
    country_name   TEXT NOT NULL,
    continent_code CHAR(2) NOT NULL REFERENCES dgip_continents(continent_code),
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgip_special_ranges (
    cidr          TEXT PRIMARY KEY,
    ip_version    SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
    category      TEXT NOT NULL,
    rfc_reference TEXT,
    priority      SMALLINT NOT NULL DEFAULT 10,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION dgip_bump_catalog_version()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    UPDATE dgip_state
    SET catalog_version = catalog_version + 1,
        updated_at = now()
    WHERE id = 1;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_dgip_config_ver ON dgip_config;
CREATE TRIGGER trg_dgip_config_ver
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dgip_config
FOR EACH STATEMENT EXECUTE FUNCTION dgip_bump_catalog_version();

DROP TRIGGER IF EXISTS trg_dgip_feeds_ver ON dgip_feed_sources;
CREATE TRIGGER trg_dgip_feeds_ver
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dgip_feed_sources
FOR EACH STATEMENT EXECUTE FUNCTION dgip_bump_catalog_version();

DROP TRIGGER IF EXISTS trg_dgip_hosts_ver ON dgip_allowed_hosts;
CREATE TRIGGER trg_dgip_hosts_ver
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dgip_allowed_hosts
FOR EACH STATEMENT EXECUTE FUNCTION dgip_bump_catalog_version();

DROP TRIGGER IF EXISTS trg_dgip_continents_ver ON dgip_continents;
CREATE TRIGGER trg_dgip_continents_ver
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dgip_continents
FOR EACH STATEMENT EXECUTE FUNCTION dgip_bump_catalog_version();

DROP TRIGGER IF EXISTS trg_dgip_countries_ver ON dgip_countries;
CREATE TRIGGER trg_dgip_countries_ver
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dgip_countries
FOR EACH STATEMENT EXECUTE FUNCTION dgip_bump_catalog_version();

DROP TRIGGER IF EXISTS trg_dgip_special_ver ON dgip_special_ranges;
CREATE TRIGGER trg_dgip_special_ver
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dgip_special_ranges
FOR EACH STATEMENT EXECUTE FUNCTION dgip_bump_catalog_version();

CREATE TABLE IF NOT EXISTS dgip_releases (
    build_number         BIGSERIAL PRIMARY KEY,
    version              TEXT NOT NULL UNIQUE,
    release_title        TEXT NOT NULL,
    released_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    previous_version     TEXT,
    combined_feed_sha256 TEXT NOT NULL,
    bundle_sha256        TEXT NOT NULL,
    bundle_size_bytes    BIGINT NOT NULL,
    manifest_json        JSONB NOT NULL,
    row_counts           JSONB NOT NULL,
    diff_summary_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    release_notes_md     TEXT NOT NULL DEFAULT '',
    operator_note        TEXT,
    source_attribution   TEXT NOT NULL,
    has_blobs            BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS dgip_release_files (
    version      TEXT NOT NULL REFERENCES dgip_releases(version) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    record_count INTEGER,
    payload      BYTEA NOT NULL,
    PRIMARY KEY (version, filename)
);

CREATE TABLE IF NOT EXISTS dgip_asn_v4_a (
    ip_range     int8range NOT NULL,
    start_ip     TEXT NOT NULL,
    end_ip       TEXT NOT NULL,
    asn          BIGINT NOT NULL,
    asn_org      TEXT NOT NULL,
    network_type TEXT NOT NULL DEFAULT '',
    rpki_status  TEXT NOT NULL DEFAULT 'unknown'
);
CREATE TABLE IF NOT EXISTS dgip_asn_v4_b (LIKE dgip_asn_v4_a INCLUDING ALL);

CREATE TABLE IF NOT EXISTS dgip_asn_v6_a (
    ip_range     numrange NOT NULL,
    start_ip     TEXT NOT NULL,
    end_ip       TEXT NOT NULL,
    asn          BIGINT NOT NULL,
    asn_org      TEXT NOT NULL,
    network_type TEXT NOT NULL DEFAULT '',
    rpki_status  TEXT NOT NULL DEFAULT 'unknown'
);
CREATE TABLE IF NOT EXISTS dgip_asn_v6_b (LIKE dgip_asn_v6_a INCLUDING ALL);

CREATE TABLE IF NOT EXISTS dgip_country_v4_a (
    ip_range     int8range NOT NULL,
    start_ip     TEXT NOT NULL,
    end_ip       TEXT NOT NULL,
    country_code CHAR(2) NOT NULL,
    region_code  TEXT NOT NULL DEFAULT '',
    city         TEXT NOT NULL DEFAULT '',
    geo_source   TEXT NOT NULL DEFAULT 'rir'
);
CREATE TABLE IF NOT EXISTS dgip_country_v4_b (LIKE dgip_country_v4_a INCLUDING ALL);

CREATE TABLE IF NOT EXISTS dgip_country_v6_a (
    ip_range     numrange NOT NULL,
    start_ip     TEXT NOT NULL,
    end_ip       TEXT NOT NULL,
    country_code CHAR(2) NOT NULL,
    region_code  TEXT NOT NULL DEFAULT '',
    city         TEXT NOT NULL DEFAULT '',
    geo_source   TEXT NOT NULL DEFAULT 'rir'
);
CREATE TABLE IF NOT EXISTS dgip_country_v6_b (LIKE dgip_country_v6_a INCLUDING ALL);

CREATE TABLE IF NOT EXISTS dgip_security_v4_a (
    ip_range     int8range NOT NULL,
    start_ip     TEXT NOT NULL,
    end_ip       TEXT NOT NULL,
    flags        SMALLINT NOT NULL,
    provider     TEXT NOT NULL DEFAULT '',
    threat_feeds TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS dgip_security_v4_b (LIKE dgip_security_v4_a INCLUDING ALL);

CREATE TABLE IF NOT EXISTS dgip_security_v6_a (
    ip_range     numrange NOT NULL,
    start_ip     TEXT NOT NULL,
    end_ip       TEXT NOT NULL,
    flags        SMALLINT NOT NULL,
    provider     TEXT NOT NULL DEFAULT '',
    threat_feeds TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS dgip_security_v6_b (LIKE dgip_security_v6_a INCLUDING ALL);
"#;

const COPY_CHUNK_BYTES: usize = 64 * 1024;

static HOSTNAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$").expect("valid regex"));

/// Escape text field per PostgreSQL `COPY` text-format specification (stripping NUL bytes).
pub fn escape_copy_text(val: &str) -> String {
    if !val
        .bytes()
        .any(|b| matches!(b, b'\\' | b'\t' | b'\n' | b'\r' | b'\0'))
    {
        return val.to_string();
    }
    let mut out = String::with_capacity(val.len() + 8);
    push_escaped_copy_text(&mut out, val);
    out
}

#[inline]
fn push_escaped_copy_text(out: &mut String, val: &str) {
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => {}
            c => out.push(c),
        }
    }
}

fn parse_cidr_or_host_ip(raw: &str) -> Result<IpNet, String> {
    let trimmed = raw.trim();
    if trimmed.contains('/') {
        IpNet::parse_non_strict(trimmed)
    } else {
        if trimmed.contains('%') {
            return Err(format!("Zone IDs not allowed in CIDR: {raw:?}"));
        }
        let ip: IpAddr = trimmed
            .parse()
            .map_err(|_| format!("Invalid IP or CIDR: {raw:?}"))?;
        match ip {
            IpAddr::V4(_) => IpNet::parse_non_strict(&format!("{trimmed}/32")),
            IpAddr::V6(_) => IpNet::parse_non_strict(&format!("{trimmed}/128")),
        }
    }
}

fn parse_bool_strict(key: &str, val: &Value) -> DgipResult<bool> {
    match val {
        Value::Bool(b) => Ok(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(DgipError::InvalidConfig(format!(
                "Config key {key:?} expects a boolean, got {val}."
            ))),
        },
        _ => Err(DgipError::InvalidConfig(format!(
            "Config key {key:?} expects a boolean, got {val}."
        ))),
    }
}

fn parse_int_strict(key: &str, val: &Value, min_val: i64, max_val: i64) -> DgipResult<i64> {
    if val.is_boolean() {
        return Err(DgipError::InvalidConfig(format!(
            "Config key {key:?} expects an integer, got boolean."
        )));
    }
    let parsed: i64 = match val {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(u) = n.as_u64() {
                i64::try_from(u).map_err(|_| {
                    DgipError::InvalidConfig(format!(
                        "Config key {key:?} must be between {min_val} and {max_val}, got {u}."
                    ))
                })?
            } else {
                return Err(DgipError::InvalidConfig(format!(
                    "Config key {key:?} expects an integer, got {val}."
                )));
            }
        }
        Value::String(s) => s.trim().parse::<i64>().map_err(|_| {
            DgipError::InvalidConfig(format!("Config key {key:?} expects an integer, got {val}."))
        })?,
        _ => {
            return Err(DgipError::InvalidConfig(format!(
                "Config key {key:?} expects an integer, got {val}."
            )));
        }
    };
    if parsed < min_val || parsed > max_val {
        return Err(DgipError::InvalidConfig(format!(
            "Config key {key:?} must be between {min_val} and {max_val}, got {parsed}."
        )));
    }
    Ok(parsed)
}

fn parse_float_strict(key: &str, val: &Value, min_val: f64, max_val: f64) -> DgipResult<f64> {
    if val.is_boolean() {
        return Err(DgipError::InvalidConfig(format!(
            "Config key {key:?} expects a number, got boolean."
        )));
    }
    let parsed: f64 = match val {
        Value::Number(n) => n.as_f64().ok_or_else(|| {
            DgipError::InvalidConfig(format!("Config key {key:?} expects a number, got {val}."))
        })?,
        Value::String(s) => s.trim().parse::<f64>().map_err(|_| {
            DgipError::InvalidConfig(format!("Config key {key:?} expects a number, got {val}."))
        })?,
        _ => {
            return Err(DgipError::InvalidConfig(format!(
                "Config key {key:?} expects a number, got {val}."
            )));
        }
    };
    if !parsed.is_finite() || parsed < min_val || parsed > max_val {
        return Err(DgipError::InvalidConfig(format!(
            "Config key {key:?} must be between {min_val} and {max_val}, got {parsed}."
        )));
    }
    Ok(parsed)
}

fn safe_bool(val: Option<&Value>, default: bool) -> bool {
    match val {
        Some(v) => parse_bool_strict("catalog", v).unwrap_or(default),
        None => default,
    }
}

fn safe_i64(val: Option<&Value>, default: i64, min_val: i64, max_val: Option<i64>) -> i64 {
    let Some(v) = val else {
        return default;
    };
    if v.is_boolean() {
        return default;
    }
    let parsed = match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok())),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    };
    let Some(mut p) = parsed else {
        return default;
    };
    if let Some(mx) = max_val {
        p = p.min(mx);
    }
    p.max(min_val)
}

fn safe_f64(val: Option<&Value>, default: f64, min_val: f64) -> f64 {
    let Some(v) = val else {
        return default;
    };
    if v.is_boolean() {
        return default;
    }
    let parsed = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match parsed {
        Some(p) if p.is_finite() => p.max(min_val),
        _ => default,
    }
}

fn safe_string(val: Option<&Value>, default: &str) -> String {
    match val {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => default.to_string(),
        Some(other) => other.to_string(),
    }
}

/// Validate keys, types, and ranges for `dgip config set` before SQL persistence.
pub fn validate_and_normalize_config_updates(
    updates: &HashMap<String, Value>,
    allow_local_files: bool,
) -> DgipResult<HashMap<String, Value>> {
    let mut normalized = HashMap::with_capacity(updates.len());

    for (key, val) in updates {
        match key.as_str() {
            "bootstrap_enabled"
            | "weekly_release_enabled"
            | "swagger_enabled"
            | "rpki_reject_invalid"
            | "enrichment_strict" => {
                normalized.insert(key.clone(), Value::Bool(parse_bool_strict(key, val)?));
            }
            "bootstrap_bundle_url" => {
                let Some(s) = val.as_str() else {
                    return Err(DgipError::InvalidConfig(format!(
                        "Config key {key:?} expects a URL string."
                    )));
                };
                let cleaned = s.trim();
                if !cleaned.is_empty() {
                    if cleaned.starts_with("file://") {
                        if !allow_local_files {
                            return Err(DgipError::InvalidConfig(
                                "file:// bootstrap_bundle_url requires DGIP_ALLOW_LOCAL_FILES=true."
                                    .to_string(),
                            ));
                        }
                    } else if !cleaned.starts_with("https://") {
                        return Err(DgipError::InvalidConfig(
                            "Config key 'bootstrap_bundle_url' must use https:// (or be empty)."
                                .to_string(),
                        ));
                    }
                }
                normalized.insert(key.clone(), Value::String(cleaned.to_string()));
            }
            "live_sync_interval_seconds" => {
                let v = parse_int_strict(key, val, 0, 31_536_000)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "weekly_release_weekday" => {
                let v = parse_int_strict(key, val, 0, 6)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "weekly_release_utc_hour" => {
                let v = parse_int_strict(key, val, 0, 23)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "version_prefix"
            | "release_title_template"
            | "upstream_user_agent"
            | "source_attribution" => {
                let Some(s) = val.as_str() else {
                    return Err(DgipError::InvalidConfig(format!(
                        "Config key {key:?} must be a non-empty string (<= 1024 chars)."
                    )));
                };
                let trimmed = s.trim();
                if trimmed.is_empty() || s.chars().count() > 1024 {
                    return Err(DgipError::InvalidConfig(format!(
                        "Config key {key:?} must be a non-empty string (<= 1024 chars)."
                    )));
                }
                normalized.insert(key.clone(), Value::String(trimmed.to_string()));
            }
            "snapshot_retention" => {
                let v = parse_int_strict(key, val, 1, 100)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "bgp_min_peers" => {
                let v = parse_int_strict(key, val, 1, 10_000)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "bgp_ipv4_min_prefixlen" => {
                let v = parse_int_strict(key, val, 1, 32)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "bgp_ipv6_min_prefixlen" => {
                let v = parse_int_strict(key, val, 1, 128)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "http_timeout_seconds" => {
                let v = parse_float_strict(key, val, 1.0, 3_600.0)?;
                normalized.insert(key.clone(), json!(v));
            }
            "max_redirects" => {
                let v = parse_int_strict(key, val, 0, 20)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "asn_min_valid" | "asn_max_valid" => {
                let v = parse_int_strict(key, val, 1, 4_294_967_294)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "rate_limit_per_minute" | "download_rate_limit_per_minute" => {
                let v = parse_int_strict(key, val, 1, 1_000_000)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "rate_limit_window_seconds" => {
                let v = parse_float_strict(key, val, 1.0, 86_400.0)?;
                normalized.insert(key.clone(), json!(v));
            }
            "rate_limit_max_keys" => {
                let v = parse_int_strict(key, val, 128, 5_000_000)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "max_batch_size" => {
                let v = parse_int_strict(key, val, 1, 10_000)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "max_request_body_bytes" => {
                let v = parse_int_strict(key, val, 4_096, 16_777_216)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            "trusted_proxies" => {
                let Some(arr) = val.as_array() else {
                    return Err(DgipError::InvalidConfig(
                        "Config key 'trusted_proxies' must be a JSON list of CIDR strings."
                            .to_string(),
                    ));
                };
                if arr.len() > 512 {
                    return Err(DgipError::InvalidConfig(
                        "Config key 'trusted_proxies' must be a JSON list of CIDR strings."
                            .to_string(),
                    ));
                }
                let mut cleaned_cidrs = Vec::with_capacity(arr.len());
                for item in arr {
                    let Some(s) = item.as_str() else {
                        return Err(DgipError::InvalidConfig(format!(
                            "Invalid CIDR entry in 'trusted_proxies': {item}"
                        )));
                    };
                    let net = parse_cidr_or_host_ip(s).map_err(|_| {
                        DgipError::InvalidConfig(format!(
                            "Invalid CIDR entry in 'trusted_proxies': {s:?}"
                        ))
                    })?;
                    cleaned_cidrs.push(Value::String(net.canonical_cidr()));
                }
                normalized.insert(key.clone(), Value::Array(cleaned_cidrs));
            }
            "snapshot_latest_cache_max_age" | "snapshot_immutable_cache_max_age" => {
                let v = parse_int_strict(key, val, 0, 315_360_000)?;
                normalized.insert(key.clone(), Value::from(v));
            }
            _ => {
                return Err(DgipError::InvalidConfig(format!(
                    "Unknown configuration key: {key:?}"
                )));
            }
        }
    }

    Ok(normalized)
}

fn parse_pg_config_and_tls(
    database_url: &str,
) -> DgipResult<(tokio_postgres::Config, Option<MakeRustlsConnect>)> {
    let mut use_tls = false;
    let mut normalized_url = database_url.trim().to_string();

    if normalized_url.starts_with("postgres://") || normalized_url.starts_with("postgresql://") {
        if let Ok(mut parsed) = url::Url::parse(&normalized_url) {
            let mut rewritten_pairs: Vec<(String, String)> = Vec::new();
            let mut mutated = false;
            for (k, v) in parsed.query_pairs() {
                if k.eq_ignore_ascii_case("sslmode") {
                    match v.to_ascii_lowercase().as_str() {
                        "require" => {
                            use_tls = true;
                            rewritten_pairs.push((k.into_owned(), "require".to_string()));
                        }
                        "verify-ca" | "verify-full" => {
                            use_tls = true;
                            mutated = true;
                            rewritten_pairs.push((k.into_owned(), "require".to_string()));
                        }
                        _ => {
                            use_tls = false;
                            rewritten_pairs.push((k.into_owned(), v.into_owned()));
                        }
                    }
                } else {
                    rewritten_pairs.push((k.into_owned(), v.into_owned()));
                }
            }
            if mutated {
                parsed.query_pairs_mut().clear();
                for (k, v) in &rewritten_pairs {
                    parsed.query_pairs_mut().append_pair(k, v);
                }
                normalized_url = parsed.to_string();
            }
        }
    } else {
        let mut out_tokens = Vec::new();
        for tok in normalized_url.split_whitespace() {
            if let Some((k, v)) = tok.split_once('=') {
                if k.eq_ignore_ascii_case("sslmode") {
                    let vl = v.trim_matches('\'').to_ascii_lowercase();
                    if matches!(vl.as_str(), "require" | "verify-ca" | "verify-full") {
                        use_tls = true;
                        out_tokens.push("sslmode=require".to_string());
                        continue;
                    }
                }
            }
            out_tokens.push(tok.to_string());
        }
        normalized_url = out_tokens.join(" ");
    }

    let mut pg_cfg: tokio_postgres::Config = normalized_url
        .parse()
        .map_err(|e| DgipError::Database(format!("Invalid PostgreSQL connection URL: {e}")))?;

    if use_tls {
        pg_cfg.ssl_mode(SslMode::Require);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok((pg_cfg, Some(MakeRustlsConnect::new(tls_cfg))))
    } else {
        Ok((pg_cfg, None))
    }
}

struct CatalogState {
    catalog: Option<Arc<RuntimeCatalog>>,
    last_check: Option<Instant>,
}

struct DbStateCache {
    state: Option<DbState>,
    last_check: Option<Instant>,
}

type CatalogListener = Box<dyn Fn(&RuntimeCatalog) + Send + Sync + 'static>;

/// Manages PostgreSQL connections, hot-reloaded catalog state, GiST lookups, and snapshot blobs.
pub struct Database {
    pub settings: Settings,
    pub cache_root: PathBuf,
    pool: Pool,
    pg_config: tokio_postgres::Config,
    tls_connector: Option<MakeRustlsConnect>,
    catalog_state: StdRwLock<CatalogState>,
    reload_lock: AsyncMutex<()>,
    catalog_listeners: StdMutex<Vec<CatalogListener>>,
    state_cache: StdRwLock<DbStateCache>,
    state_lock: AsyncMutex<()>,
    artifact_locks: StdMutex<ArtifactLockMap>,
}

type ArtifactLockMap = HashMap<(String, String), Arc<AsyncMutex<()>>>;

impl Database {
    pub fn new(settings: Settings) -> DgipResult<Arc<Self>> {
        let (pg_config, tls_connector) = parse_pg_config_and_tls(&settings.database_url)?;
        let mgr_cfg = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = match &tls_connector {
            Some(tls) => Manager::from_config(pg_config.clone(), tls.clone(), mgr_cfg),
            None => Manager::from_config(pg_config.clone(), tokio_postgres::NoTls, mgr_cfg),
        };
        let pool = Pool::builder(mgr)
            .max_size(settings.db_pool_max_size.max(2))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| DgipError::Database(format!("Failed creating PostgreSQL pool: {e}")))?;

        let cache_root = settings.cache_dir.clone();
        Ok(Arc::new(Self {
            settings,
            cache_root,
            pool,
            pg_config,
            tls_connector,
            catalog_state: StdRwLock::new(CatalogState {
                catalog: None,
                last_check: None,
            }),
            reload_lock: AsyncMutex::new(()),
            catalog_listeners: StdMutex::new(Vec::new()),
            state_cache: StdRwLock::new(DbStateCache {
                state: None,
                last_check: None,
            }),
            state_lock: AsyncMutex::new(()),
            artifact_locks: StdMutex::new(HashMap::new()),
        }))
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub fn add_catalog_listener<F>(&self, listener: F)
    where
        F: Fn(&RuntimeCatalog) + Send + Sync + 'static,
    {
        if let Ok(mut listeners) = self.catalog_listeners.lock() {
            listeners.push(Box::new(listener));
        }
    }

    /// Open an unpooled standalone PostgreSQL connection for session advisory locks or `COPY` bulk loads.
    pub async fn connect_standalone(&self) -> DgipResult<tokio_postgres::Client> {
        match &self.tls_connector {
            Some(tls) => {
                let (client, conn) = self.pg_config.connect(tls.clone()).await.map_err(|e| {
                    DgipError::Database(format!("PostgreSQL standalone connect failed: {e}"))
                })?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("PostgreSQL standalone TLS connection ended: {e}");
                    }
                });
                Ok(client)
            }
            None => {
                let (client, conn) = self
                    .pg_config
                    .connect(tokio_postgres::NoTls)
                    .await
                    .map_err(|e| {
                        DgipError::Database(format!("PostgreSQL standalone connect failed: {e}"))
                    })?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("PostgreSQL standalone connection ended: {e}");
                    }
                });
                Ok(client)
            }
        }
    }

    pub async fn startup(&self) -> DgipResult<()> {
        std::fs::create_dir_all(&self.cache_root)?;

        let mut client = self.pool.get().await.map_err(|e| {
            DgipError::Database(format!("Pool checkout failed during startup: {e}"))
        })?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| DgipError::Database(format!("Startup transaction begin failed: {e}")))?;

        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_KEY])
            .await
            .map_err(|e| DgipError::Database(format!("Startup advisory lock failed: {e}")))?;

        tx.batch_execute(SCHEMA_SQL)
            .await
            .map_err(|e| DgipError::Database(format!("Schema DDL execution failed: {e}")))?;

        let row_opt = tx
            .query_opt("SELECT catalog_seeded FROM dgip_state WHERE id = 1", &[])
            .await
            .map_err(|e| DgipError::Database(format!("Querying catalog_seeded failed: {e}")))?;

        let seeded = row_opt
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false);

        if !seeded {
            self.seed_initial_catalog(&tx).await?;
            tx.execute(
                "UPDATE dgip_state SET catalog_seeded = TRUE, updated_at = now() WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(format!("Marking catalog_seeded failed: {e}")))?;
            tracing::info!("Seeded initial DGIP PostgreSQL catalog tables.");
        }

        tx.commit()
            .await
            .map_err(|e| DgipError::Database(format!("Startup transaction commit failed: {e}")))?;
        drop(client);

        self.ensure_catalog_fresh(true).await?;
        Ok(())
    }

    async fn seed_initial_catalog(&self, tx: &tokio_postgres::Transaction<'_>) -> DgipResult<()> {
        let cont_stmt = tx
            .prepare(
                "INSERT INTO dgip_continents (continent_code, continent_name)
                 VALUES ($1, $2)
                 ON CONFLICT (continent_code) DO NOTHING",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        for &(code, name) in DEFAULT_CONTINENTS {
            tx.execute(&cont_stmt, &[&code, &name])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        let cc_stmt = tx
            .prepare(
                "INSERT INTO dgip_countries (country_code, country_name, continent_code, enabled)
                 VALUES ($1, $2, $3, TRUE)
                 ON CONFLICT (country_code) DO NOTHING",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        for &(cc, name, cont) in DEFAULT_COUNTRIES {
            tx.execute(&cc_stmt, &[&cc, &name, &cont])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        let spec_stmt = tx
            .prepare(
                "INSERT INTO dgip_special_ranges (cidr, ip_version, category, rfc_reference, priority, enabled)
                 VALUES ($1, $2, $3, $4, $5, TRUE)
                 ON CONFLICT (cidr) DO NOTHING",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        for &(cidr, ip_ver, cat, rfc, prio) in DEFAULT_SPECIAL_RANGES {
            tx.execute(&spec_stmt, &[&cidr, &ip_ver, &cat, &rfc, &prio])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        let host_stmt = tx
            .prepare(
                "INSERT INTO dgip_allowed_hosts (hostname, notes, enabled)
                 VALUES ($1, $2, TRUE)
                 ON CONFLICT (hostname) DO NOTHING",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        for &(host, notes) in DEFAULT_ALLOWED_HOSTS {
            tx.execute(&host_stmt, &[&host, &notes])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        let feed_stmt = tx
            .prepare(
                "INSERT INTO dgip_feed_sources (
                     feed_key, kind, ip_version, source_url,
                     min_records, max_compressed_bytes, max_uncompressed_bytes, display_order, enabled
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
                 ON CONFLICT (feed_key) DO NOTHING",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        for (feed_key, kind, ip_ver, url, min_rec, max_comp, max_uncomp, order) in
            build_default_feed_sources()
        {
            tx.execute(
                &feed_stmt,
                &[
                    &feed_key,
                    &kind,
                    &ip_ver,
                    &url,
                    &min_rec,
                    &max_comp,
                    &max_uncomp,
                    &order,
                ],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        let cfg_stmt = tx
            .prepare(
                "INSERT INTO dgip_config (key, value_json, description)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (key) DO NOTHING",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        for (key, val, desc) in build_default_config_entries(
            &self.settings.initial_bootstrap_url,
            self.settings.initial_snapshot_retention,
        ) {
            tx.execute(&cfg_stmt, &[&key, &val, &desc])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn shutdown(&self) {
        self.pool.close();
    }

    pub async fn ping(&self) -> bool {
        let Ok(client) = self.pool.get().await else {
            return false;
        };
        match client.query_one("SELECT 1", &[]).await {
            Ok(row) => row.try_get::<_, i32>(0).ok() == Some(1),
            Err(_) => false,
        }
    }

    pub fn get_catalog_cached(&self) -> Option<Arc<RuntimeCatalog>> {
        self.catalog_state
            .read()
            .ok()
            .and_then(|st| st.catalog.clone())
    }

    pub async fn ensure_catalog_fresh(&self, force: bool) -> DgipResult<Arc<RuntimeCatalog>> {
        if !force {
            if let Ok(st) = self.catalog_state.read() {
                if let (Some(cat), Some(last)) = (&st.catalog, st.last_check) {
                    if last.elapsed().as_secs_f64() < self.settings.catalog_poll_seconds {
                        return Ok(Arc::clone(cat));
                    }
                }
            }
        }

        let _guard = self.reload_lock.lock().await;

        if !force {
            if let Ok(st) = self.catalog_state.read() {
                if let (Some(cat), Some(last)) = (&st.catalog, st.last_check) {
                    if last.elapsed().as_secs_f64() < self.settings.catalog_poll_seconds {
                        return Ok(Arc::clone(cat));
                    }
                }
            }
        }

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(format!("Pool checkout failed: {e}")))?;

        let ver_row = client
            .query_opt("SELECT catalog_version FROM dgip_state WHERE id = 1", &[])
            .await
            .map_err(|e| DgipError::Database(format!("Querying catalog_version failed: {e}")))?;

        let db_ver: i64 = ver_row
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .unwrap_or(1);

        let now = Instant::now();
        if !force {
            if let Ok(mut st) = self.catalog_state.write() {
                st.last_check = Some(now);
                if let Some(cat) = &st.catalog {
                    if cat.catalog_version == db_ver {
                        return Ok(Arc::clone(cat));
                    }
                }
            }
        }

        let loaded = Arc::new(self.load_full_catalog(&client, db_ver).await?);
        if let Ok(mut st) = self.catalog_state.write() {
            st.catalog = Some(Arc::clone(&loaded));
            st.last_check = Some(Instant::now());
        }
        if let Ok(listeners) = self.catalog_listeners.lock() {
            for listener in listeners.iter() {
                listener(&loaded);
            }
        }
        Ok(loaded)
    }

    async fn load_full_catalog(
        &self,
        client: &tokio_postgres::Client,
        db_ver: i64,
    ) -> DgipResult<RuntimeCatalog> {
        let cfg_rows = client
            .query("SELECT key, value_json FROM dgip_config", &[])
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let mut cfg_map: HashMap<String, Value> = HashMap::with_capacity(cfg_rows.len());
        for r in cfg_rows {
            let k: String = r
                .try_get(0)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let v: Value = r
                .try_get(1)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            cfg_map.insert(k, v);
        }

        let feed_rows = client
            .query(
                "SELECT feed_key, kind, ip_version, source_url,
                        min_records, max_compressed_bytes, max_uncompressed_bytes,
                        enabled, display_order
                 FROM dgip_feed_sources
                 ORDER BY display_order ASC, feed_key ASC",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let mut feed_sources = Vec::with_capacity(feed_rows.len());
        for r in feed_rows {
            feed_sources.push(FeedSourceSpec {
                feed_key: r
                    .try_get(0)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                kind: r
                    .try_get(1)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                ip_version: r
                    .try_get(2)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                source_url: r
                    .try_get(3)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                min_records: r
                    .try_get(4)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                max_compressed_bytes: r
                    .try_get(5)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                max_uncompressed_bytes: r
                    .try_get(6)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                enabled: r
                    .try_get(7)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                display_order: r
                    .try_get(8)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
            });
        }

        let host_rows_db = client
            .query(
                "SELECT hostname, enabled, notes FROM dgip_allowed_hosts ORDER BY hostname ASC",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let mut allowed_host_rows = Vec::with_capacity(host_rows_db.len());
        let mut allowed_hosts = HashSet::new();
        for r in host_rows_db {
            let raw_h: String = r
                .try_get(0)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let en: bool = r
                .try_get(1)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let notes: Option<String> = r
                .try_get(2)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let h = raw_h.trim().to_ascii_lowercase();
            if en && !h.is_empty() {
                allowed_hosts.insert(h.clone());
            }
            allowed_host_rows.push((h, en, notes));
        }

        let cont_row = client
            .query_one("SELECT COUNT(*) FROM dgip_continents", &[])
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let continents_count = cont_row
            .try_get::<_, i64>(0)
            .map(|c| c.max(0) as usize)
            .unwrap_or(0);

        let cc_rows = client
            .query(
                "SELECT c.country_code, c.country_name, c.continent_code, cont.continent_name
                 FROM dgip_countries c
                 JOIN dgip_continents cont ON cont.continent_code = c.continent_code
                 WHERE c.enabled = TRUE",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let mut country_details: HashMap<String, (String, String, String)> =
            HashMap::with_capacity(cc_rows.len());
        for r in cc_rows {
            let cc_raw: String = r
                .try_get(0)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let c_name: String = r
                .try_get(1)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let cont_raw: String = r
                .try_get(2)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let cont_name: String = r
                .try_get(3)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let cc = cc_raw.trim().to_ascii_uppercase();
            country_details.insert(
                cc,
                (c_name, cont_raw.trim().to_ascii_uppercase(), cont_name),
            );
        }
        let valid_country_codes: HashSet<String> = country_details.keys().cloned().collect();

        let spec_rows = client
            .query(
                "SELECT cidr, ip_version, category, priority
                 FROM dgip_special_ranges
                 WHERE enabled = TRUE",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let mut raw_specials: Vec<(String, i16, String, i16)> = Vec::with_capacity(spec_rows.len());
        for r in spec_rows {
            raw_specials.push((
                r.try_get(0)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                r.try_get(1)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                r.try_get(2)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
                r.try_get(3)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
            ));
        }
        let (special_v4_rules, special_v6_rules) = compile_special_ranges(
            raw_specials
                .iter()
                .map(|(cidr, ver, cat, prio)| (cidr.as_str(), *ver, cat.as_str(), *prio)),
        );

        let mut trusted_proxies = Vec::new();
        if let Some(Value::Array(arr)) = cfg_map.get("trusted_proxies") {
            for item in arr {
                if let Some(s) = item.as_str() {
                    match parse_cidr_or_host_ip(s) {
                        Ok(net) => trusted_proxies.push(net),
                        Err(_) => {
                            tracing::warn!(
                                "Ignoring invalid CIDR in dgip_config.trusted_proxies: {s:?}"
                            );
                        }
                    }
                }
            }
        }

        let bootstrap_bundle_url = safe_string(
            cfg_map.get("bootstrap_bundle_url"),
            "https://github.com/daviante-org/dgip-data/releases/latest/download/bundle.tar.gz",
        )
        .trim()
        .to_string();

        Ok(RuntimeCatalog {
            catalog_version: db_ver,
            bootstrap_enabled: safe_bool(cfg_map.get("bootstrap_enabled"), true),
            bootstrap_bundle_url,
            live_sync_interval_seconds: safe_i64(
                cfg_map.get("live_sync_interval_seconds"),
                86_400,
                0,
                None,
            ),
            weekly_release_enabled: safe_bool(cfg_map.get("weekly_release_enabled"), true),
            weekly_release_weekday: safe_i64(cfg_map.get("weekly_release_weekday"), 0, 0, Some(6))
                as i32,
            weekly_release_utc_hour: safe_i64(
                cfg_map.get("weekly_release_utc_hour"),
                2,
                0,
                Some(23),
            ) as i32,
            version_prefix: safe_string(cfg_map.get("version_prefix"), "v"),
            release_title_template: safe_string(cfg_map.get("release_title_template"), "{version}"),
            snapshot_retention: safe_i64(cfg_map.get("snapshot_retention"), 5, 1, Some(100)) as i32,
            bgp_min_peers: safe_i64(cfg_map.get("bgp_min_peers"), 5, 1, Some(10_000)) as i32,
            bgp_ipv4_min_prefixlen: safe_i64(cfg_map.get("bgp_ipv4_min_prefixlen"), 8, 1, Some(32))
                as u8,
            bgp_ipv6_min_prefixlen: safe_i64(
                cfg_map.get("bgp_ipv6_min_prefixlen"),
                12,
                1,
                Some(128),
            ) as u8,
            rpki_reject_invalid: safe_bool(cfg_map.get("rpki_reject_invalid"), true),
            enrichment_strict: safe_bool(cfg_map.get("enrichment_strict"), false),
            http_timeout_seconds: safe_f64(cfg_map.get("http_timeout_seconds"), 180.0, 1.0),
            max_redirects: safe_i64(cfg_map.get("max_redirects"), 5, 0, Some(20)) as usize,
            upstream_user_agent: safe_string(
                cfg_map.get("upstream_user_agent"),
                "DGIP/1.0 (+https://daviante.org; mailto:code@daviante.org)",
            ),
            source_attribution: safe_string(
                cfg_map.get("source_attribution"),
                DEFAULT_SOURCE_ATTRIBUTION,
            ),
            asn_min_valid: safe_i64(cfg_map.get("asn_min_valid"), 1, 1, Some(4_294_967_294)) as u32,
            asn_max_valid: safe_i64(
                cfg_map.get("asn_max_valid"),
                4_294_967_294,
                1,
                Some(4_294_967_294),
            ) as u32,
            rate_limit_per_minute: safe_i64(
                cfg_map.get("rate_limit_per_minute"),
                120,
                1,
                Some(1_000_000),
            ) as usize,
            download_rate_limit_per_minute: safe_i64(
                cfg_map.get("download_rate_limit_per_minute"),
                30,
                1,
                Some(1_000_000),
            ) as usize,
            rate_limit_window_seconds: safe_f64(
                cfg_map.get("rate_limit_window_seconds"),
                60.0,
                1.0,
            ),
            rate_limit_max_keys: safe_i64(
                cfg_map.get("rate_limit_max_keys"),
                50_000,
                128,
                Some(5_000_000),
            ) as usize,
            max_batch_size: safe_i64(cfg_map.get("max_batch_size"), 1_000, 1, Some(10_000))
                as usize,
            max_request_body_bytes: safe_i64(
                cfg_map.get("max_request_body_bytes"),
                262_144,
                4_096,
                Some(16_777_216),
            ) as usize,
            trusted_proxies,
            snapshot_latest_cache_max_age: safe_i64(
                cfg_map.get("snapshot_latest_cache_max_age"),
                60,
                0,
                Some(315_360_000),
            ),
            snapshot_immutable_cache_max_age: safe_i64(
                cfg_map.get("snapshot_immutable_cache_max_age"),
                31_536_000,
                0,
                Some(315_360_000),
            ),
            swagger_enabled: safe_bool(cfg_map.get("swagger_enabled"), true),
            raw_config: cfg_map,
            feed_sources,
            allowed_hosts,
            allowed_host_rows,
            valid_country_codes,
            country_details,
            continents_count,
            special_v4_rules,
            special_v6_rules,
        })
    }

    pub async fn update_config_entries(
        &self,
        updates: &HashMap<String, Value>,
    ) -> DgipResult<Arc<RuntimeCatalog>> {
        let normalized =
            validate_and_normalize_config_updates(updates, self.settings.allow_local_files)?;

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let stmt = tx
            .prepare(
                "INSERT INTO dgip_config (key, value_json, description, updated_at)
                 VALUES ($1, $2, 'Updated via dgip CLI', now())
                 ON CONFLICT (key) DO UPDATE
                 SET value_json = EXCLUDED.value_json,
                     updated_at = now()",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        for (key, val) in &normalized {
            tx.execute(&stmt, &[key, val])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        drop(client);

        self.invalidate_state_cache();
        self.ensure_catalog_fresh(true).await
    }

    pub async fn set_feed_source(
        &self,
        feed_key: &str,
        enabled: Option<bool>,
        source_url: Option<&str>,
        min_records: Option<i32>,
    ) -> DgipResult<Arc<RuntimeCatalog>> {
        let cleaned_key = feed_key.trim();
        if cleaned_key.is_empty() {
            return Err(DgipError::InvalidConfig(
                "feed_key must be non-empty.".to_string(),
            ));
        }

        let cleaned_url: Option<String> = match source_url {
            Some(u) => {
                let cu = u.trim();
                if cu.is_empty() {
                    return Err(DgipError::InvalidConfig(
                        "source_url must be non-empty.".to_string(),
                    ));
                }
                if cu.starts_with("file://") {
                    if !self.settings.allow_local_files {
                        return Err(DgipError::InvalidConfig(
                            "file:// feed source_url requires DGIP_ALLOW_LOCAL_FILES=true."
                                .to_string(),
                        ));
                    }
                } else if !cu.starts_with("https://") {
                    return Err(DgipError::InvalidConfig(
                        "Feed source_url must use https://.".to_string(),
                    ));
                }
                Some(cu.to_string())
            }
            None => None,
        };

        if let Some(mr) = min_records {
            if mr < 1 {
                return Err(DgipError::InvalidConfig(
                    "min_records must be a positive integer (>= 1).".to_string(),
                ));
            }
        }

        if enabled.is_none() && cleaned_url.is_none() && min_records.is_none() {
            return Err(DgipError::InvalidConfig(
                "Specify at least one feed property to update.".to_string(),
            ));
        }

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let exists = tx
            .query_opt(
                "SELECT 1 FROM dgip_feed_sources WHERE feed_key = $1",
                &[&cleaned_key],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        if exists.is_none() {
            return Err(DgipError::InvalidConfig(format!(
                "Unknown feed_key: {cleaned_key:?}"
            )));
        }

        tx.execute(
            "UPDATE dgip_feed_sources
             SET enabled = COALESCE($1, enabled),
                 source_url = COALESCE($2, source_url),
                 min_records = COALESCE($3, min_records),
                 updated_at = now()
             WHERE feed_key = $4",
            &[&enabled, &cleaned_url, &min_records, &cleaned_key],
        )
        .await
        .map_err(|e| DgipError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        drop(client);

        self.invalidate_state_cache();
        self.ensure_catalog_fresh(true).await
    }

    pub async fn set_allowed_host(
        &self,
        hostname: &str,
        enabled: bool,
        notes: Option<&str>,
    ) -> DgipResult<Arc<RuntimeCatalog>> {
        let norm_host = hostname.trim().to_ascii_lowercase();
        if norm_host.is_empty() || norm_host.contains("..") || !HOSTNAME_RE.is_match(&norm_host) {
            return Err(DgipError::InvalidConfig(format!(
                "Invalid hostname: {hostname:?}"
            )));
        }

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        tx.execute(
            "INSERT INTO dgip_allowed_hosts (hostname, enabled, notes, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (hostname) DO UPDATE
             SET enabled = EXCLUDED.enabled,
                 notes = COALESCE(EXCLUDED.notes, dgip_allowed_hosts.notes),
                 updated_at = now()",
            &[&norm_host, &enabled, &notes],
        )
        .await
        .map_err(|e| DgipError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        drop(client);

        self.invalidate_state_cache();
        self.ensure_catalog_fresh(true).await
    }

    pub fn invalidate_state_cache(&self) {
        if let Ok(mut st) = self.state_cache.write() {
            st.last_check = None;
        }
    }

    pub async fn get_state_cached(&self, max_age_secs: f64) -> DgipResult<DbState> {
        if max_age_secs > 0.0 {
            if let Ok(st) = self.state_cache.read() {
                if let (Some(cached), Some(last)) = (&st.state, st.last_check) {
                    if last.elapsed().as_secs_f64() < max_age_secs {
                        return Ok(cached.clone());
                    }
                }
            }
        }

        let _guard = self.state_lock.lock().await;

        if max_age_secs > 0.0 {
            if let Ok(st) = self.state_cache.read() {
                if let (Some(cached), Some(last)) = (&st.state, st.last_check) {
                    if last.elapsed().as_secs_f64() < max_age_secs {
                        return Ok(cached.clone());
                    }
                }
            }
        }

        self.get_state().await
    }

    pub async fn get_state(&self) -> DgipResult<DbState> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let row_opt = client
            .query_opt(
                "SELECT initial_bootstrapped, active_slot, live_feed_sha256, live_row_counts,
                        live_updated_at, active_version, catalog_version,
                        last_sync_attempt_at, last_sync_success_at, last_sync_error,
                        last_release_attempt_at, last_release_success_at, last_release_error,
                        updated_at
                 FROM dgip_state
                 WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let Some(row) = row_opt else {
            return Ok(DbState {
                catalog_version: 1,
                ..Default::default()
            });
        };

        let raw_counts: Option<Value> = row
            .try_get("live_row_counts")
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let live_row_counts = raw_counts.and_then(|v| json_to_row_counts(&v));

        let state = DbState {
            initial_bootstrapped: row
                .try_get("initial_bootstrapped")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            active_slot: row
                .try_get("active_slot")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            live_feed_sha256: row
                .try_get("live_feed_sha256")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            live_row_counts,
            live_updated_at: row
                .try_get("live_updated_at")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            active_version: row
                .try_get("active_version")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            catalog_version: row
                .try_get("catalog_version")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            last_sync_attempt_at: row
                .try_get("last_sync_attempt_at")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            last_sync_success_at: row
                .try_get("last_sync_success_at")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            last_sync_error: row
                .try_get("last_sync_error")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            last_release_attempt_at: row
                .try_get("last_release_attempt_at")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            last_release_success_at: row
                .try_get("last_release_success_at")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            last_release_error: row
                .try_get("last_release_error")
                .map_err(|e| DgipError::Database(e.to_string()))?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        };

        if let Ok(mut st) = self.state_cache.write() {
            st.state = Some(state.clone());
            st.last_check = Some(Instant::now());
        }
        Ok(state)
    }

    pub async fn record_sync_attempt(&self) -> DgipResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state SET last_sync_attempt_at = now(), updated_at = now() WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    pub async fn record_sync_error(&self, error_msg: &str) -> DgipResult<()> {
        let truncated: String = error_msg.chars().take(2000).collect();
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state SET last_sync_error = $1, updated_at = now() WHERE id = 1",
                &[&truncated],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    pub async fn record_sync_unchanged(&self) -> DgipResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state
                 SET last_sync_success_at = now(), last_sync_error = NULL, updated_at = now()
                 WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    pub async fn flip_live_slot_only(
        &self,
        target_slot: &str,
        live_sha256: &str,
        row_counts: &HashMap<String, usize>,
    ) -> DgipResult<()> {
        if target_slot != "a" && target_slot != "b" {
            return Err(DgipError::Database(format!(
                "Invalid target slot: {target_slot:?}"
            )));
        }
        let counts_json = serde_json::to_value(row_counts)
            .map_err(|e| DgipError::Database(format!("Failed serializing row_counts: {e}")))?;

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state
                 SET initial_bootstrapped = TRUE,
                     active_slot = $1,
                     live_feed_sha256 = $2,
                     live_row_counts = $3,
                     live_updated_at = now(),
                     last_sync_success_at = now(),
                     last_sync_error = NULL,
                     updated_at = now()
                 WHERE id = 1",
                &[&target_slot, &live_sha256, &counts_json],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    pub async fn record_release_attempt(&self) -> DgipResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state SET last_release_attempt_at = now(), updated_at = now() WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    pub async fn record_release_error(&self, error_msg: &str) -> DgipResult<()> {
        let truncated: String = error_msg.chars().take(2000).collect();
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state SET last_release_error = $1, updated_at = now() WHERE id = 1",
                &[&truncated],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    pub async fn record_release_unchanged(&self) -> DgipResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgip_state
                 SET last_release_success_at = now(), last_release_error = NULL, updated_at = now()
                 WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        self.invalidate_state_cache();
        Ok(())
    }

    /// Populate inactive Blue/Green slot (`a` or `b`) over a dedicated bulk connection using
    /// streamed 64 KB `COPY ... FROM STDIN` chunks, GiST index creation, and `ANALYZE`.
    pub async fn populate_inactive_slot(
        &self,
        slot: &str,
        tables: &CompiledTables,
    ) -> DgipResult<()> {
        if slot != "a" && slot != "b" {
            return Err(DgipError::Database(format!(
                "Invalid target slot: {slot:?}"
            )));
        }

        let mut load_client = self.connect_standalone().await?;
        {
            let mut tx = load_client
                .transaction()
                .await
                .map_err(|e| DgipError::Database(format!("Slot load transaction failed: {e}")))?;

            tx.batch_execute("SET LOCAL synchronous_commit = off")
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;

            if let Ok(sp) = tx.transaction().await {
                if sp
                    .batch_execute("SET LOCAL maintenance_work_mem = '128MB'")
                    .await
                    .is_ok()
                {
                    let _ = sp.commit().await;
                }
            }

            tx.batch_execute(&format!(
                "DROP INDEX IF EXISTS idx_dgip_asn_v4_{slot}_range;
                 DROP INDEX IF EXISTS idx_dgip_asn_v6_{slot}_range;
                 DROP INDEX IF EXISTS idx_dgip_country_v4_{slot}_range;
                 DROP INDEX IF EXISTS idx_dgip_country_v6_{slot}_range;
                 DROP INDEX IF EXISTS idx_dgip_security_v4_{slot}_range;
                 DROP INDEX IF EXISTS idx_dgip_security_v6_{slot}_range;
                 TRUNCATE TABLE
                     dgip_asn_v4_{slot},
                     dgip_asn_v6_{slot},
                     dgip_country_v4_{slot},
                     dgip_country_v6_{slot},
                     dgip_security_v4_{slot},
                     dgip_security_v6_{slot};"
            ))
            .await
            .map_err(|e| DgipError::Database(format!("Slot truncate failed: {e}")))?;

            copy_asn_rows(
                &tx,
                &format!("dgip_asn_v4_{slot}"),
                &tables.asn_v4,
                format_ipv4,
            )
            .await?;
            copy_asn_rows(
                &tx,
                &format!("dgip_asn_v6_{slot}"),
                &tables.asn_v6,
                format_ipv6,
            )
            .await?;
            copy_country_rows(
                &tx,
                &format!("dgip_country_v4_{slot}"),
                &tables.country_v4,
                format_ipv4,
            )
            .await?;
            copy_country_rows(
                &tx,
                &format!("dgip_country_v6_{slot}"),
                &tables.country_v6,
                format_ipv6,
            )
            .await?;
            copy_security_rows(
                &tx,
                &format!("dgip_security_v4_{slot}"),
                &tables.security_v4,
                format_ipv4,
            )
            .await?;
            copy_security_rows(
                &tx,
                &format!("dgip_security_v6_{slot}"),
                &tables.security_v6,
                format_ipv6,
            )
            .await?;

            tx.batch_execute(&format!(
                "CREATE INDEX idx_dgip_asn_v4_{slot}_range ON dgip_asn_v4_{slot} USING gist (ip_range);
                 CREATE INDEX idx_dgip_asn_v6_{slot}_range ON dgip_asn_v6_{slot} USING gist (ip_range);
                 CREATE INDEX idx_dgip_country_v4_{slot}_range ON dgip_country_v4_{slot} USING gist (ip_range);
                 CREATE INDEX idx_dgip_country_v6_{slot}_range ON dgip_country_v6_{slot} USING gist (ip_range);
                 CREATE INDEX idx_dgip_security_v4_{slot}_range ON dgip_security_v4_{slot} USING gist (ip_range);
                 CREATE INDEX idx_dgip_security_v6_{slot}_range ON dgip_security_v6_{slot} USING gist (ip_range);"
            ))
            .await
            .map_err(|e| DgipError::Database(format!("GiST index build failed: {e}")))?;

            tx.commit()
                .await
                .map_err(|e| DgipError::Database(format!("Slot load commit failed: {e}")))?;
        }

        load_client
            .batch_execute(&format!(
                "ANALYZE dgip_asn_v4_{slot};
                 ANALYZE dgip_asn_v6_{slot};
                 ANALYZE dgip_country_v4_{slot};
                 ANALYZE dgip_country_v6_{slot};
                 ANALYZE dgip_security_v4_{slot};
                 ANALYZE dgip_security_v6_{slot};"
            ))
            .await
            .map_err(|e| DgipError::Database(format!("Slot ANALYZE failed: {e}")))?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_snapshot_transaction(
        &self,
        packaged: &PackagedSnapshot,
        tables: &CompiledTables,
        released_at: DateTime<Utc>,
        previous_version: Option<&str>,
        diff_summary: &Value,
        release_notes_md: &str,
        operator_note: Option<&str>,
        active_slot: &str,
        live_slot_was_rebuilt: bool,
        retention_limit: i32,
        source_attribution: &str,
    ) -> DgipResult<(i64, HashSet<String>)> {
        let row_counts = tables.row_counts();
        let row_counts_json = serde_json::to_value(&row_counts)
            .map_err(|e| DgipError::Database(format!("Failed serializing row_counts: {e}")))?;
        let bundle_size_i64 = i64::try_from(packaged.bundle_bytes.len()).unwrap_or(i64::MAX);

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let rel_row = tx
            .query_one(
                "INSERT INTO dgip_releases (
                     version, release_title, released_at, previous_version,
                     combined_feed_sha256, bundle_sha256, bundle_size_bytes,
                     manifest_json, row_counts, diff_summary_json,
                     release_notes_md, operator_note, source_attribution, has_blobs
                 )
                 VALUES (
                     $1, $2, $3, $4,
                     $5, $6, $7,
                     $8, $9, $10,
                     $11, $12, $13, TRUE
                 )
                 RETURNING build_number",
                &[
                    &packaged.version,
                    &packaged.release_title,
                    &released_at,
                    &previous_version,
                    &tables.normalized_sha256,
                    &packaged.bundle_sha256,
                    &bundle_size_i64,
                    &packaged.manifest,
                    &row_counts_json,
                    diff_summary,
                    &release_notes_md,
                    &operator_note,
                    &source_attribution,
                ],
            )
            .await
            .map_err(|e| DgipError::Database(format!("Inserting dgip_releases failed: {e}")))?;
        let build_number: i64 = rel_row
            .try_get(0)
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let file_stmt = tx
            .prepare(
                "INSERT INTO dgip_release_files (
                     version, filename, content_type, sha256, size_bytes, record_count, payload
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let mut sorted_keys: Vec<&String> = packaged.dataset_artifacts.keys().collect();
        sorted_keys.sort();

        type TopFileEntry<'a> = (&'a str, &'a str, &'a str, Option<i32>, &'a [u8]);
        let top_files: [TopFileEntry<'_>; 3] = [
            (
                "bundle.tar.gz",
                "application/gzip",
                &packaged.bundle_sha256,
                None,
                &packaged.bundle_bytes,
            ),
            (
                "manifest.json",
                "application/json",
                &packaged.manifest_sha256,
                None,
                &packaged.manifest_bytes,
            ),
            (
                "SHA256SUMS.txt",
                "text/plain; charset=utf-8",
                &packaged.sha256sums_sha256,
                None,
                &packaged.sha256sums_bytes,
            ),
        ];

        for (fname, ctype, sha, rec_cnt, payload) in top_files {
            let sz = i64::try_from(payload.len()).unwrap_or(i64::MAX);
            tx.execute(
                &file_stmt,
                &[
                    &packaged.version,
                    &fname,
                    &ctype,
                    &sha,
                    &sz,
                    &rec_cnt,
                    &payload,
                ],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        for k in sorted_keys {
            let art = &packaged.dataset_artifacts[k];
            let sz = i64::try_from(art.payload.len()).unwrap_or(i64::MAX);
            let rec_cnt: Option<i32> = art.record_count.and_then(|c| i32::try_from(c).ok());
            let payload_slice: &[u8] = &art.payload;
            tx.execute(
                &file_stmt,
                &[
                    &packaged.version,
                    &art.filename,
                    &art.content_type,
                    &art.sha256,
                    &sz,
                    &rec_cnt,
                    &payload_slice,
                ],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        let limit_i64 = i64::from(retention_limit.max(1));
        let retained_rows = tx
            .query(
                "SELECT version
                 FROM dgip_releases
                 ORDER BY build_number DESC
                 LIMIT $1",
                &[&limit_i64],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let mut retained = HashSet::with_capacity(retained_rows.len());
        for r in retained_rows {
            let v: String = r
                .try_get(0)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            retained.insert(v);
        }

        if !retained.is_empty() {
            let keep_list: Vec<String> = retained.iter().cloned().collect();
            tx.execute(
                "DELETE FROM dgip_release_files WHERE NOT (version = ANY($1::text[]))",
                &[&keep_list],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

            tx.execute(
                "UPDATE dgip_releases
                 SET has_blobs = FALSE
                 WHERE has_blobs = TRUE AND NOT (version = ANY($1::text[]))",
                &[&keep_list],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        }

        tx.execute(
            "UPDATE dgip_state
             SET initial_bootstrapped = TRUE,
                 active_slot = $1,
                 live_feed_sha256 = $2,
                 live_row_counts = $3,
                 live_updated_at = CASE WHEN $4::bool THEN now() ELSE COALESCE(live_updated_at, now()) END,
                 active_version = $5,
                 last_sync_attempt_at = COALESCE(last_sync_attempt_at, now()),
                 last_sync_success_at = now(),
                 last_sync_error = NULL,
                 last_release_attempt_at = COALESCE(last_release_attempt_at, now()),
                 last_release_success_at = now(),
                 last_release_error = NULL,
                 updated_at = now()
             WHERE id = 1",
            &[
                &active_slot,
                &tables.normalized_sha256,
                &row_counts_json,
                &live_slot_was_rebuilt,
                &packaged.version,
            ],
        )
        .await
        .map_err(|e| DgipError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        drop(client);

        self.invalidate_state_cache();
        Ok((build_number, retained))
    }

    pub async fn lookup_single(
        &self,
        slot: &str,
        version: u8,
        v4_int: u32,
        v6_int: u128,
    ) -> DgipResult<RawDbMatch> {
        if slot != "a" && slot != "b" {
            return Err(DgipError::Database(format!(
                "Invalid active slot: {slot:?}"
            )));
        }

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let row_opt = if version == 4 {
            let ip_param = i64::from(v4_int);
            let query = format!(
                "SELECT
                     a.asn, a.asn_org, a.network_type, a.rpki_status,
                     a.start_ip AS asn_start, a.end_ip AS asn_end,
                     c.country_code, dc.country_name, dc.continent_code, dcont.continent_name,
                     c.region_code, c.city, c.geo_source,
                     c.start_ip AS country_start, c.end_ip AS country_end,
                     s.flags AS sec_flags, s.provider AS sec_provider, s.threat_feeds AS sec_threat_feeds,
                     s.start_ip AS sec_start, s.end_ip AS sec_end
                 FROM (SELECT 1) AS dummy
                 LEFT JOIN LATERAL (
                     SELECT asn, asn_org, network_type, rpki_status, start_ip, end_ip
                     FROM dgip_asn_v4_{slot}
                     WHERE ip_range @> $1::bigint
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) a ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT country_code, region_code, city, geo_source, start_ip, end_ip
                     FROM dgip_country_v4_{slot}
                     WHERE ip_range @> $1::bigint
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) c ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT flags, provider, threat_feeds, start_ip, end_ip
                     FROM dgip_security_v4_{slot}
                     WHERE ip_range @> $1::bigint
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) s ON TRUE
                 LEFT JOIN dgip_countries dc
                     ON dc.country_code = c.country_code AND dc.enabled = TRUE
                 LEFT JOIN dgip_continents dcont
                     ON dcont.continent_code = dc.continent_code"
            );
            client
                .query_opt(&query, &[&ip_param])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?
        } else {
            let ip_txt = v6_int.to_string();
            let query = format!(
                "SELECT
                     a.asn, a.asn_org, a.network_type, a.rpki_status,
                     a.start_ip AS asn_start, a.end_ip AS asn_end,
                     c.country_code, dc.country_name, dc.continent_code, dcont.continent_name,
                     c.region_code, c.city, c.geo_source,
                     c.start_ip AS country_start, c.end_ip AS country_end,
                     s.flags AS sec_flags, s.provider AS sec_provider, s.threat_feeds AS sec_threat_feeds,
                     s.start_ip AS sec_start, s.end_ip AS sec_end
                 FROM (SELECT 1) AS dummy
                 LEFT JOIN LATERAL (
                     SELECT asn, asn_org, network_type, rpki_status, start_ip, end_ip
                     FROM dgip_asn_v6_{slot}
                     WHERE ip_range @> ($1::text)::numeric
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) a ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT country_code, region_code, city, geo_source, start_ip, end_ip
                     FROM dgip_country_v6_{slot}
                     WHERE ip_range @> ($1::text)::numeric
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) c ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT flags, provider, threat_feeds, start_ip, end_ip
                     FROM dgip_security_v6_{slot}
                     WHERE ip_range @> ($1::text)::numeric
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) s ON TRUE
                 LEFT JOIN dgip_countries dc
                     ON dc.country_code = c.country_code AND dc.enabled = TRUE
                 LEFT JOIN dgip_continents dcont
                     ON dcont.continent_code = dc.continent_code"
            );
            client
                .query_opt(&query, &[&ip_txt])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?
        };

        match row_opt {
            Some(row) => row_to_raw_match(&row),
            None => Ok(RawDbMatch::default()),
        }
    }

    pub async fn lookup_batch(
        &self,
        slot: &str,
        v4_ints: &[u32],
        v6_ints: &[u128],
    ) -> DgipResult<(HashMap<u32, RawDbMatch>, HashMap<u128, RawDbMatch>)> {
        if slot != "a" && slot != "b" {
            return Err(DgipError::Database(format!(
                "Invalid active slot: {slot:?}"
            )));
        }

        let mut v4_results = HashMap::with_capacity(v4_ints.len());
        let mut v6_results = HashMap::with_capacity(v6_ints.len());
        if v4_ints.is_empty() && v6_ints.is_empty() {
            return Ok((v4_results, v6_results));
        }

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        if !v4_ints.is_empty() {
            let v4_i64: Vec<i64> = v4_ints.iter().map(|&v| i64::from(v)).collect();
            let query = format!(
                "SELECT
                     q.ip_val,
                     a.asn, a.asn_org, a.network_type, a.rpki_status,
                     a.start_ip AS asn_start, a.end_ip AS asn_end,
                     c.country_code, dc.country_name, dc.continent_code, dcont.continent_name,
                     c.region_code, c.city, c.geo_source,
                     c.start_ip AS country_start, c.end_ip AS country_end,
                     s.flags AS sec_flags, s.provider AS sec_provider, s.threat_feeds AS sec_threat_feeds,
                     s.start_ip AS sec_start, s.end_ip AS sec_end
                 FROM unnest($1::bigint[]) AS q(ip_val)
                 LEFT JOIN LATERAL (
                     SELECT asn, asn_org, network_type, rpki_status, start_ip, end_ip
                     FROM dgip_asn_v4_{slot}
                     WHERE ip_range @> q.ip_val
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) a ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT country_code, region_code, city, geo_source, start_ip, end_ip
                     FROM dgip_country_v4_{slot}
                     WHERE ip_range @> q.ip_val
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) c ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT flags, provider, threat_feeds, start_ip, end_ip
                     FROM dgip_security_v4_{slot}
                     WHERE ip_range @> q.ip_val
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) s ON TRUE
                 LEFT JOIN dgip_countries dc
                     ON dc.country_code = c.country_code AND dc.enabled = TRUE
                 LEFT JOIN dgip_continents dcont
                     ON dcont.continent_code = dc.continent_code"
            );
            let rows = client
                .query(&query, &[&v4_i64])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
            for row in rows {
                let ip_val: i64 = row
                    .try_get("ip_val")
                    .map_err(|e| DgipError::Database(e.to_string()))?;
                if let Ok(ip_u32) = u32::try_from(ip_val) {
                    v4_results.insert(ip_u32, row_to_raw_match(&row)?);
                }
            }
        }

        if !v6_ints.is_empty() {
            let v6_txts: Vec<String> = v6_ints.iter().map(u128::to_string).collect();
            let query = format!(
                "SELECT
                     q.ip_txt,
                     a.asn, a.asn_org, a.network_type, a.rpki_status,
                     a.start_ip AS asn_start, a.end_ip AS asn_end,
                     c.country_code, dc.country_name, dc.continent_code, dcont.continent_name,
                     c.region_code, c.city, c.geo_source,
                     c.start_ip AS country_start, c.end_ip AS country_end,
                     s.flags AS sec_flags, s.provider AS sec_provider, s.threat_feeds AS sec_threat_feeds,
                     s.start_ip AS sec_start, s.end_ip AS sec_end
                 FROM unnest($1::text[]) AS q(ip_txt)
                 LEFT JOIN LATERAL (
                     SELECT asn, asn_org, network_type, rpki_status, start_ip, end_ip
                     FROM dgip_asn_v6_{slot}
                     WHERE ip_range @> (q.ip_txt::numeric)
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) a ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT country_code, region_code, city, geo_source, start_ip, end_ip
                     FROM dgip_country_v6_{slot}
                     WHERE ip_range @> (q.ip_txt::numeric)
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) c ON TRUE
                 LEFT JOIN LATERAL (
                     SELECT flags, provider, threat_feeds, start_ip, end_ip
                     FROM dgip_security_v6_{slot}
                     WHERE ip_range @> (q.ip_txt::numeric)
                     ORDER BY (upper(ip_range) - lower(ip_range)) ASC
                     LIMIT 1
                 ) s ON TRUE
                 LEFT JOIN dgip_countries dc
                     ON dc.country_code = c.country_code AND dc.enabled = TRUE
                 LEFT JOIN dgip_continents dcont
                     ON dcont.continent_code = dc.continent_code"
            );
            let rows = client
                .query(&query, &[&v6_txts])
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?;
            for row in rows {
                let ip_txt: String = row
                    .try_get("ip_txt")
                    .map_err(|e| DgipError::Database(e.to_string()))?;
                if let Ok(ip_u128) = ip_txt.parse::<u128>() {
                    v6_results.insert(ip_u128, row_to_raw_match(&row)?);
                }
            }
        }

        Ok((v4_results, v6_results))
    }

    pub async fn list_releases(&self, limit: i64) -> DgipResult<Vec<ReleaseRow>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let rows = client
            .query(
                "SELECT build_number, version, release_title, released_at, previous_version,
                        combined_feed_sha256, bundle_sha256, bundle_size_bytes, manifest_json,
                        row_counts, diff_summary_json, release_notes_md,
                        operator_note, source_attribution, has_blobs
                 FROM dgip_releases
                 ORDER BY build_number DESC
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(row_to_release_row(&r)?);
        }
        Ok(out)
    }

    pub async fn get_release(&self, version: Option<&str>) -> DgipResult<Option<ReleaseRow>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let row_opt = match version {
            None => client
                .query_opt(
                    "SELECT r.build_number, r.version, r.release_title, r.released_at, r.previous_version,
                            r.combined_feed_sha256, r.bundle_sha256, r.bundle_size_bytes, r.manifest_json,
                            r.row_counts, r.diff_summary_json, r.release_notes_md,
                            r.operator_note, r.source_attribution, r.has_blobs
                     FROM dgip_state s
                     JOIN dgip_releases r ON r.version = s.active_version
                     WHERE s.id = 1",
                    &[],
                )
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?,
            Some(ver) => client
                .query_opt(
                    "SELECT r.build_number, r.version, r.release_title, r.released_at, r.previous_version,
                            r.combined_feed_sha256, r.bundle_sha256, r.bundle_size_bytes, r.manifest_json,
                            r.row_counts, r.diff_summary_json, r.release_notes_md,
                            r.operator_note, r.source_attribution, r.has_blobs
                     FROM dgip_releases r
                     WHERE r.version = $1",
                    &[&ver],
                )
                .await
                .map_err(|e| DgipError::Database(e.to_string()))?,
        };

        match row_opt {
            Some(row) => Ok(Some(row_to_release_row(&row)?)),
            None => Ok(None),
        }
    }

    pub async fn get_latest_release_for_diff(
        &self,
    ) -> DgipResult<(Option<ReleaseRow>, Option<HashMap<String, Vec<u8>>>)> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let row_opt = client
            .query_opt(
                "SELECT build_number, version, release_title, released_at, previous_version,
                        combined_feed_sha256, bundle_sha256, bundle_size_bytes, manifest_json,
                        row_counts, diff_summary_json, release_notes_md,
                        operator_note, source_attribution, has_blobs
                 FROM dgip_releases
                 ORDER BY build_number DESC
                 LIMIT 1",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let Some(row) = row_opt else {
            return Ok((None, None));
        };

        let rel = row_to_release_row(&row)?;
        if !rel.has_blobs {
            return Ok((Some(rel), None));
        }

        let file_rows = client
            .query(
                "SELECT filename, payload
                 FROM dgip_release_files
                 WHERE version = $1 AND filename LIKE 'dgip-%-ipv%.csv.gz'",
                &[&rel.version],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let mut files_gz = HashMap::with_capacity(file_rows.len());
        for frow in file_rows {
            let fname: String = frow
                .try_get(0)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            let payload: Vec<u8> = frow
                .try_get(1)
                .map_err(|e| DgipError::Database(e.to_string()))?;
            files_gz.insert(fname, payload);
        }

        let csv_opt = if files_gz.is_empty() {
            None
        } else {
            Some(files_gz)
        };
        Ok((Some(rel), csv_opt))
    }

    pub async fn list_versions_matching(&self, prefix: &str) -> DgipResult<Vec<String>> {
        let like_pat = format!("{prefix}.%");
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let rows = client
            .query(
                "SELECT version FROM dgip_releases WHERE version = $1 OR version LIKE $2",
                &[&prefix, &like_pat],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(
                r.try_get(0)
                    .map_err(|e| DgipError::Database(e.to_string()))?,
            );
        }
        Ok(out)
    }

    pub async fn count_stored_blob_versions(&self) -> DgipResult<i64> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM dgip_releases WHERE has_blobs = TRUE",
                &[],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        row.try_get::<_, i64>(0)
            .map_err(|e| DgipError::Database(e.to_string()))
    }

    pub fn list_local_cached_versions(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.cache_root) else {
            return Vec::new();
        };
        let mut versions = Vec::new();
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if !name.starts_with('.') {
                            versions.push(name.to_string());
                        }
                    }
                }
            }
        }
        versions.sort();
        versions
    }

    pub fn write_cache_file(
        &self,
        version: &str,
        filename: &str,
        payload: &[u8],
        content_type: Option<&str>,
        sha256_hex: Option<&str>,
    ) -> DgipResult<PathBuf> {
        let safe_ver = sanitize_segment(version)?;
        let safe_name = sanitize_segment(filename)?;
        let ver_dir = self.cache_root.join(safe_ver);
        std::fs::create_dir_all(&ver_dir)?;

        let final_path = ver_dir.join(safe_name);
        let rand_token: u32 = rand::random();
        let suffix = format!("{}.{:08x}", std::process::id(), rand_token);
        let tmp_path = ver_dir.join(format!(".{safe_name}.tmp.{suffix}"));

        std::fs::write(&tmp_path, payload)?;
        std::fs::rename(&tmp_path, &final_path)?;

        if let (Some(ctype), Some(sha)) = (content_type, sha256_hex) {
            if !ctype.is_empty() && !sha.is_empty() {
                let meta_path = ver_dir.join(format!("{safe_name}.meta.json"));
                let tmp_meta = ver_dir.join(format!(".{safe_name}.meta.tmp.{suffix}"));
                let meta_json = json!({
                    "content_type": ctype,
                    "sha256": sha,
                    "size_bytes": payload.len(),
                });
                std::fs::write(&tmp_meta, meta_json.to_string().as_bytes())?;
                std::fs::rename(&tmp_meta, &meta_path)?;
            }
        }

        Ok(final_path)
    }

    pub fn prune_local_cache(&self, keep_versions: &HashSet<String>) {
        let Ok(entries) = std::fs::read_dir(&self.cache_root) else {
            return;
        };
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if !keep_versions.contains(name) {
                            let _ = std::fs::remove_dir_all(entry.path());
                        }
                    }
                }
            }
        }
    }

    fn read_cached_artifact_fast(&self, safe_ver: &str, safe_name: &str) -> Option<CachedArtifact> {
        let ver_dir = self.cache_root.join(safe_ver);
        let local_path = ver_dir.join(safe_name);
        let meta_path = ver_dir.join(format!("{safe_name}.meta.json"));
        if !local_path.is_file() || !meta_path.is_file() {
            return None;
        }
        let meta_raw = std::fs::read_to_string(&meta_path).ok()?;
        let meta: Value = serde_json::from_str(&meta_raw).ok()?;
        let expected_size = meta.get("size_bytes")?.as_u64()?;
        let actual_size = std::fs::metadata(&local_path).ok()?.len();
        if actual_size != expected_size {
            return None;
        }
        let content_type = meta.get("content_type")?.as_str()?.to_string();
        let sha256 = meta.get("sha256")?.as_str()?.to_string();

        Some(CachedArtifact {
            path: local_path,
            filename: safe_name.to_string(),
            content_type,
            sha256,
            size_bytes: expected_size,
        })
    }

    pub async fn resolve_download_artifact(
        &self,
        version: &str,
        filename: &str,
    ) -> DgipResult<Option<CachedArtifact>> {
        let safe_ver = sanitize_segment(version)?.to_string();
        let safe_name = sanitize_segment(filename)?.to_string();

        if let Some(cached) = self.read_cached_artifact_fast(&safe_ver, &safe_name) {
            return Ok(Some(cached));
        }

        let key_lock = {
            let mut map = self
                .artifact_locks
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if map.len() > 512 {
                map.retain(|_, lk| Arc::strong_count(lk) > 1);
            }
            Arc::clone(
                map.entry((safe_ver.clone(), safe_name.clone()))
                    .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
            )
        };

        let _singleflight = key_lock.lock().await;

        if let Some(cached) = self.read_cached_artifact_fast(&safe_ver, &safe_name) {
            return Ok(Some(cached));
        }

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let row_opt = client
            .query_opt(
                "SELECT content_type, sha256, size_bytes, payload
                 FROM dgip_release_files
                 WHERE version = $1 AND filename = $2",
                &[&safe_ver, &safe_name],
            )
            .await
            .map_err(|e| DgipError::Database(e.to_string()))?;
        drop(client);

        let Some(row) = row_opt else {
            return Ok(None);
        };

        let ctype: String = row
            .try_get(0)
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let sha_hex: String = row
            .try_get(1)
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let size_b: i64 = row
            .try_get(2)
            .map_err(|e| DgipError::Database(e.to_string()))?;
        let payload_bytes: Vec<u8> = row
            .try_get(3)
            .map_err(|e| DgipError::Database(e.to_string()))?;

        let cache_root = self.cache_root.clone();
        let ver_clone = safe_ver.clone();
        let name_clone = safe_name.clone();
        let ctype_clone = ctype.clone();
        let sha_clone = sha_hex.clone();

        let written = tokio::task::spawn_blocking(move || -> DgipResult<PathBuf> {
            let ver_dir = cache_root.join(&ver_clone);
            std::fs::create_dir_all(&ver_dir)?;
            let final_path = ver_dir.join(&name_clone);
            let rand_token: u32 = rand::random();
            let suffix = format!("{}.{:08x}", std::process::id(), rand_token);
            let tmp_path = ver_dir.join(format!(".{name_clone}.tmp.{suffix}"));
            std::fs::write(&tmp_path, &payload_bytes)?;
            std::fs::rename(&tmp_path, &final_path)?;

            let meta_path = ver_dir.join(format!("{name_clone}.meta.json"));
            let tmp_meta = ver_dir.join(format!(".{name_clone}.meta.tmp.{suffix}"));
            let meta_json = json!({
                "content_type": ctype_clone,
                "sha256": sha_clone,
                "size_bytes": payload_bytes.len(),
            });
            std::fs::write(&tmp_meta, meta_json.to_string().as_bytes())?;
            std::fs::rename(&tmp_meta, &meta_path)?;
            Ok(final_path)
        })
        .await
        .map_err(|e| DgipError::Database(format!("Cache write task failed: {e}")))??;

        Ok(Some(CachedArtifact {
            path: written,
            filename: safe_name,
            content_type: ctype,
            sha256: sha_hex,
            size_bytes: size_b.max(0) as u64,
        }))
    }
}

fn sanitize_segment(segment: &str) -> DgipResult<&str> {
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.contains('\0')
    {
        return Err(DgipError::InvalidConfig(format!(
            "Unsafe path segment: {segment:?}"
        )));
    }
    Ok(segment)
}

fn json_to_row_counts(val: &Value) -> Option<HashMap<String, usize>> {
    let obj = val.as_object()?;
    let mut out = HashMap::with_capacity(obj.len());
    for (k, v) in obj {
        if let Some(n) = v.as_u64() {
            out.insert(k.clone(), n as usize);
        } else if let Some(i) = v.as_i64() {
            if i >= 0 {
                out.insert(k.clone(), i as usize);
            }
        }
    }
    Some(out)
}

fn non_empty_opt(val: Option<String>) -> Option<String> {
    val.filter(|s| !s.is_empty())
}

fn trimmed_non_empty_opt(val: Option<String>) -> Option<String> {
    val.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

fn row_to_raw_match(row: &Row) -> DgipResult<RawDbMatch> {
    let asn_i64: Option<i64> = row
        .try_get("asn")
        .map_err(|e| DgipError::Database(e.to_string()))?;
    let asn = asn_i64.and_then(|v| u32::try_from(v).ok());

    Ok(RawDbMatch {
        asn,
        asn_org: non_empty_opt(
            row.try_get("asn_org")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        network_type: non_empty_opt(
            row.try_get("network_type")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        rpki_status: non_empty_opt(
            row.try_get("rpki_status")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        asn_start_ip: row
            .try_get("asn_start")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        asn_end_ip: row
            .try_get("asn_end")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        country_code: trimmed_non_empty_opt(
            row.try_get("country_code")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        country_name: row
            .try_get("country_name")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        continent_code: trimmed_non_empty_opt(
            row.try_get("continent_code")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        continent_name: row
            .try_get("continent_name")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        region_code: non_empty_opt(
            row.try_get("region_code")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        city: non_empty_opt(
            row.try_get("city")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        geo_source: non_empty_opt(
            row.try_get("geo_source")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        country_start_ip: row
            .try_get("country_start")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        country_end_ip: row
            .try_get("country_end")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        sec_flags: row
            .try_get("sec_flags")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        sec_provider: non_empty_opt(
            row.try_get("sec_provider")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        sec_threat_feeds: non_empty_opt(
            row.try_get("sec_threat_feeds")
                .map_err(|e| DgipError::Database(e.to_string()))?,
        ),
        sec_start_ip: row
            .try_get("sec_start")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        sec_end_ip: row
            .try_get("sec_end")
            .map_err(|e| DgipError::Database(e.to_string()))?,
    })
}

fn row_to_release_row(row: &Row) -> DgipResult<ReleaseRow> {
    let counts_val: Value = row
        .try_get("row_counts")
        .map_err(|e| DgipError::Database(e.to_string()))?;
    let row_counts = json_to_row_counts(&counts_val).unwrap_or_default();

    Ok(ReleaseRow {
        build_number: row
            .try_get("build_number")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        version: row
            .try_get("version")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        release_title: row
            .try_get("release_title")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        released_at: row
            .try_get("released_at")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        previous_version: row
            .try_get("previous_version")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        combined_feed_sha256: row
            .try_get("combined_feed_sha256")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        bundle_sha256: row
            .try_get("bundle_sha256")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        bundle_size_bytes: row
            .try_get("bundle_size_bytes")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        manifest_json: row
            .try_get("manifest_json")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        row_counts,
        diff_summary_json: row
            .try_get("diff_summary_json")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        release_notes_md: row
            .try_get("release_notes_md")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        operator_note: row
            .try_get("operator_note")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        source_attribution: row
            .try_get("source_attribution")
            .map_err(|e| DgipError::Database(e.to_string()))?,
        has_blobs: row
            .try_get("has_blobs")
            .map_err(|e| DgipError::Database(e.to_string()))?,
    })
}

async fn copy_asn_rows<I, F>(
    tx: &tokio_postgres::Transaction<'_>,
    table_name: &str,
    rows: &[AsnRow<I>],
    fmt_ip: F,
) -> DgipResult<()>
where
    I: Copy + std::fmt::Display,
    F: Fn(I) -> String,
{
    let stmt = format!(
        "COPY {table_name} (ip_range, start_ip, end_ip, asn, asn_org, network_type, rpki_status) FROM STDIN"
    );
    let sink = tx
        .copy_in::<_, Bytes>(&stmt)
        .await
        .map_err(|e| DgipError::Database(format!("COPY start failed on {table_name}: {e}")))?;
    let mut sink = pin!(sink);

    let mut buf = String::with_capacity(COPY_CHUNK_BYTES + 512);
    for row in rows {
        use std::fmt::Write;
        let s_ip = fmt_ip(row.start);
        let e_ip = fmt_ip(row.end);
        let _ = write!(
            buf,
            "[{},{}]\t{}\t{}\t{}\t",
            row.start, row.end, s_ip, e_ip, row.asn
        );
        push_escaped_copy_text(&mut buf, &row.org);
        buf.push('\t');
        push_escaped_copy_text(&mut buf, &row.network_type);
        buf.push('\t');
        let rpki = if row.rpki_status.is_empty() {
            "unknown"
        } else {
            row.rpki_status.as_str()
        };
        push_escaped_copy_text(&mut buf, rpki);
        buf.push('\n');

        if buf.len() >= COPY_CHUNK_BYTES {
            let chunk = std::mem::replace(&mut buf, String::with_capacity(COPY_CHUNK_BYTES + 512));
            sink.send(Bytes::from(chunk)).await.map_err(|e| {
                DgipError::Database(format!("COPY write failed on {table_name}: {e}"))
            })?;
        }
    }
    if !buf.is_empty() {
        sink.send(Bytes::from(buf)).await.map_err(|e| {
            DgipError::Database(format!("COPY final write failed on {table_name}: {e}"))
        })?;
    }
    sink.close()
        .await
        .map_err(|e| DgipError::Database(format!("COPY finish failed on {table_name}: {e}")))?;
    Ok(())
}

async fn copy_country_rows<I, F>(
    tx: &tokio_postgres::Transaction<'_>,
    table_name: &str,
    rows: &[CountryRow<I>],
    fmt_ip: F,
) -> DgipResult<()>
where
    I: Copy + std::fmt::Display,
    F: Fn(I) -> String,
{
    let stmt = format!(
        "COPY {table_name} (ip_range, start_ip, end_ip, country_code, region_code, city, geo_source) FROM STDIN"
    );
    let sink = tx
        .copy_in::<_, Bytes>(&stmt)
        .await
        .map_err(|e| DgipError::Database(format!("COPY start failed on {table_name}: {e}")))?;
    let mut sink = pin!(sink);

    let mut buf = String::with_capacity(COPY_CHUNK_BYTES + 512);
    for row in rows {
        use std::fmt::Write;
        let s_ip = fmt_ip(row.start);
        let e_ip = fmt_ip(row.end);
        let _ = write!(buf, "[{},{}]\t{}\t{}\t", row.start, row.end, s_ip, e_ip);
        push_escaped_copy_text(&mut buf, &row.cc);
        buf.push('\t');
        push_escaped_copy_text(&mut buf, &row.region_code);
        buf.push('\t');
        push_escaped_copy_text(&mut buf, &row.city);
        buf.push('\t');
        let gsrc = if row.geo_source.is_empty() {
            "rir"
        } else {
            row.geo_source.as_str()
        };
        push_escaped_copy_text(&mut buf, gsrc);
        buf.push('\n');

        if buf.len() >= COPY_CHUNK_BYTES {
            let chunk = std::mem::replace(&mut buf, String::with_capacity(COPY_CHUNK_BYTES + 512));
            sink.send(Bytes::from(chunk)).await.map_err(|e| {
                DgipError::Database(format!("COPY write failed on {table_name}: {e}"))
            })?;
        }
    }
    if !buf.is_empty() {
        sink.send(Bytes::from(buf)).await.map_err(|e| {
            DgipError::Database(format!("COPY final write failed on {table_name}: {e}"))
        })?;
    }
    sink.close()
        .await
        .map_err(|e| DgipError::Database(format!("COPY finish failed on {table_name}: {e}")))?;
    Ok(())
}

async fn copy_security_rows<I, F>(
    tx: &tokio_postgres::Transaction<'_>,
    table_name: &str,
    rows: &[SecurityRow<I>],
    fmt_ip: F,
) -> DgipResult<()>
where
    I: Copy + std::fmt::Display,
    F: Fn(I) -> String,
{
    let stmt = format!(
        "COPY {table_name} (ip_range, start_ip, end_ip, flags, provider, threat_feeds) FROM STDIN"
    );
    let sink = tx
        .copy_in::<_, Bytes>(&stmt)
        .await
        .map_err(|e| DgipError::Database(format!("COPY start failed on {table_name}: {e}")))?;
    let mut sink = pin!(sink);

    let mut buf = String::with_capacity(COPY_CHUNK_BYTES + 512);
    for row in rows {
        use std::fmt::Write;
        let s_ip = fmt_ip(row.start);
        let e_ip = fmt_ip(row.end);
        let _ = write!(
            buf,
            "[{},{}]\t{}\t{}\t{}\t",
            row.start, row.end, s_ip, e_ip, row.flags
        );
        push_escaped_copy_text(&mut buf, &row.provider);
        buf.push('\t');
        push_escaped_copy_text(&mut buf, &row.threat_feeds);
        buf.push('\n');

        if buf.len() >= COPY_CHUNK_BYTES {
            let chunk = std::mem::replace(&mut buf, String::with_capacity(COPY_CHUNK_BYTES + 512));
            sink.send(Bytes::from(chunk)).await.map_err(|e| {
                DgipError::Database(format!("COPY write failed on {table_name}: {e}"))
            })?;
        }
    }
    if !buf.is_empty() {
        sink.send(Bytes::from(buf)).await.map_err(|e| {
            DgipError::Database(format!("COPY final write failed on {table_name}: {e}"))
        })?;
    }
    sink.close()
        .await
        .map_err(|e| DgipError::Database(format!("COPY finish failed on {table_name}: {e}")))?;
    Ok(())
}
