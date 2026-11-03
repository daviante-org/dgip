//! HTTP API and operational CLI serialization schemas for DGIP (`1:1` parity with `app/models.py` and `openapi.yaml`).

use crate::types::FeedSourceSpec;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;

pub mod rfc3339_utc {
    use super::*;

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Secs, true))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

pub mod opt_rfc3339_utc {
    use super::*;

    pub fn serialize<S>(dt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(d) => serializer.serialize_str(&d.to_rfc3339_opts(SecondsFormat::Secs, true)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => DateTime::parse_from_rfc3339(&s)
                .map(|dt| Some(dt.with_timezone(&Utc)))
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

fn default_problem_type() -> String {
    "about:blank".to_string()
}

fn default_status_ok() -> String {
    "ok".to_string()
}

fn default_status_ready() -> String {
    "ready".to_string()
}

/// RFC 9457 Problem Details (`application/problem+json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type", default = "default_problem_type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<Value>>,
}

impl ProblemDetails {
    pub fn new(
        status: u16,
        title: impl Into<String>,
        detail: impl Into<String>,
        instance: Option<String>,
    ) -> Self {
        Self {
            type_uri: default_problem_type(),
            title: title.into(),
            status,
            detail: detail.into(),
            instance,
            errors: None,
        }
    }
}

/// Container process liveness response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthLiveResponse {
    #[serde(default = "default_status_ok")]
    pub status: String,
    pub version: String,
}

/// PostgreSQL connectivity and active GiST lookup slot readiness response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReadyResponse {
    #[serde(default = "default_status_ready")]
    pub status: String,
    pub active_slot: String,
    pub active_version: Option<String>,
    pub initial_bootstrapped: bool,
}

/// Autonomous System ownership, network classification, RPKI status, and BGP prefix range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ASNInfo {
    pub number: u32,
    pub code: String,
    pub organization: Option<String>,
    pub network_type: Option<String>,
    pub rpki_status: Option<String>,
    pub range_start: String,
    pub range_end: String,
}

pub type AsnInfo = ASNInfo;

/// Country, continent, and physical operator geofeed geolocation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: Option<String>,
    pub continent_code: Option<String>,
    pub continent_name: Option<String>,
    pub region_code: Option<String>,
    pub city: Option<String>,
    pub source: Option<String>,
    pub range_start: String,
    pub range_end: String,
}

/// Cloud, CDN, privacy relay, Tor exit node, and threat intelligence classification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityInfo {
    #[serde(default)]
    pub is_cloud: bool,
    #[serde(default)]
    pub is_datacenter: bool,
    #[serde(default)]
    pub is_cdn: bool,
    #[serde(default)]
    pub is_tor_exit: bool,
    #[serde(default)]
    pub is_privacy_relay: bool,
    #[serde(default)]
    pub is_threat: bool,
    pub provider: Option<String>,
    #[serde(default)]
    pub threat_feeds: Vec<String>,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
}

/// Single IPv4 or IPv6 4-layer intelligence lookup result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IPLookupResponse {
    pub ip: String,
    pub ip_version: u8,
    #[serde(default)]
    pub is_ipv4_mapped: bool,
    pub is_bogon: bool,
    pub bogon_type: Option<String>,
    pub found: bool,
    pub asn: Option<ASNInfo>,
    pub geo: Option<GeoInfo>,
    pub security: Option<SecurityInfo>,
    pub snapshot_version: Option<String>,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub live_updated_at: Option<DateTime<Utc>>,
}

pub type IpLookupResponse = IPLookupResponse;

/// Bulk IPv4 and IPv6 lookup request payload (1 to `max_batch_size` addresses, default 1,000).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchIPRequest {
    pub ips: Vec<String>,
}

pub type BatchIpRequest = BatchIPRequest;

/// Per-item result within a bulk IP lookup response, preserving caller input order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchIPItemResult {
    pub input: String,
    pub ok: bool,
    pub data: Option<IPLookupResponse>,
    pub error: Option<String>,
}

pub type BatchIpItemResult = BatchIPItemResult;

/// Ordered bulk IPv4/IPv6 lookup response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchIPResponse {
    pub count: usize,
    pub snapshot_version: Option<String>,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub live_updated_at: Option<DateTime<Utc>>,
    pub results: Vec<BatchIPItemResult>,
}

pub type BatchIpResponse = BatchIPResponse;

/// Checksum, byte size, and row count metadata for an individual snapshot artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFileMetadata {
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub record_count: Option<u64>,
    pub download_path: String,
}

/// Weekly snapshot release descriptor served to clients and the `dgip-data` workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadataResponse {
    pub version: String,
    pub release_title: String,
    pub build_number: i64,
    #[serde(with = "rfc3339_utc")]
    pub released_at: DateTime<Utc>,
    pub previous_version: Option<String>,
    pub bundle_sha256: String,
    pub bundle_size_bytes: i64,
    pub bundle_download_path: String,
    pub sha256sums_download_path: String,
    pub has_blobs: bool,
    pub row_counts: HashMap<String, usize>,
    pub diff_summary: Value,
    pub release_notes_md: String,
    pub operator_note: Option<String>,
    pub files: Vec<SnapshotFileMetadata>,
    pub manifest: Value,
    pub source_attribution: String,
    pub installed_version: Option<String>,
    pub update_available: Option<bool>,
}

/// Paginated snapshot release history response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotListResponse {
    pub active_version: Option<String>,
    pub retention_limit: i32,
    pub snapshots: Vec<SnapshotMetadataResponse>,
}

/// Result of a live lookup table refresh from upstream RIR/RIPE feeds (`dgip sync`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncResponse {
    pub status: String,
    pub active_slot: Option<String>,
    pub live_row_counts: Option<HashMap<String, usize>>,
    pub duration_seconds: f64,
    pub detail: String,
}

/// Result of compiling and storing a multi-format dataset snapshot (`dgip release`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CutReleaseResponse {
    pub status: String,
    pub version: Option<String>,
    pub release_title: Option<String>,
    pub build_number: Option<i64>,
    pub previous_version: Option<String>,
    pub active_slot: Option<String>,
    pub row_counts: Option<HashMap<String, usize>>,
    pub duration_seconds: f64,
    pub detail: String,
}

/// Operational upstream feed entry reported by `dgip catalog` and `dgip feed list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSourceItem {
    pub feed_key: String,
    pub kind: String,
    pub ip_version: i16,
    pub source_url: String,
    pub min_records: i32,
    pub max_compressed_bytes: i64,
    pub max_uncompressed_bytes: i64,
    pub enabled: bool,
    pub display_order: i16,
}

impl From<&FeedSourceSpec> for FeedSourceItem {
    fn from(spec: &FeedSourceSpec) -> Self {
        Self {
            feed_key: spec.feed_key.clone(),
            kind: spec.kind.clone(),
            ip_version: spec.ip_version,
            source_url: spec.source_url.clone(),
            min_records: spec.min_records,
            max_compressed_bytes: spec.max_compressed_bytes,
            max_uncompressed_bytes: spec.max_uncompressed_bytes,
            enabled: spec.enabled,
            display_order: spec.display_order,
        }
    }
}

impl From<FeedSourceSpec> for FeedSourceItem {
    fn from(spec: FeedSourceSpec) -> Self {
        Self::from(&spec)
    }
}

/// Outbound HTTPS allowlist entry reported by `dgip catalog` and `dgip host list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedHostItem {
    pub hostname: String,
    pub enabled: bool,
    pub notes: Option<String>,
}

/// PostgreSQL runtime catalog summary reported by `dgip catalog`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationalCatalogResponse {
    pub catalog_version: i64,
    pub config: HashMap<String, Value>,
    pub feed_sources: Vec<FeedSourceItem>,
    pub allowed_hosts: Vec<AllowedHostItem>,
    pub active_continents_count: usize,
    pub active_countries_count: usize,
    pub active_special_ranges_count: usize,
}

/// Operational service state reported by `dgip status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalStatusResponse {
    pub service_version: String,
    pub initial_bootstrapped: bool,
    pub active_slot: String,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub live_updated_at: Option<DateTime<Utc>>,
    pub live_row_counts: Option<HashMap<String, usize>>,
    pub active_version: Option<String>,
    pub catalog_version: i64,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub last_sync_attempt_at: Option<DateTime<Utc>>,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub last_sync_success_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub last_release_attempt_at: Option<DateTime<Utc>>,
    #[serde(with = "opt_rfc3339_utc", default)]
    pub last_release_success_at: Option<DateTime<Utc>>,
    pub last_release_error: Option<String>,
    pub snapshot_retention: i32,
    pub stored_blob_versions: i64,
    pub local_cached_versions: Vec<String>,
}
