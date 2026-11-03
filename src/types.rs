//! Shared domain types, constants, bitmask flags, and error definitions for DGIP.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use thiserror::Error;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const ASN_IPV4_FILENAME: &str = "dgip-asn-ipv4.csv.gz";
pub const ASN_IPV6_FILENAME: &str = "dgip-asn-ipv6.csv.gz";
pub const COUNTRY_IPV4_FILENAME: &str = "dgip-country-ipv4.csv.gz";
pub const COUNTRY_IPV6_FILENAME: &str = "dgip-country-ipv6.csv.gz";
pub const SECURITY_IPV4_FILENAME: &str = "dgip-security-ipv4.csv.gz";
pub const SECURITY_IPV6_FILENAME: &str = "dgip-security-ipv6.csv.gz";
pub const GEOFEED_FILENAME: &str = "dgip-geofeed.csv.gz";
pub const ASN_MMDB_FILENAME: &str = "dgip-asn.mmdb";
pub const COUNTRY_MMDB_FILENAME: &str = "dgip-country.mmdb";
pub const SECURITY_MMDB_FILENAME: &str = "dgip-security.mmdb";

// Layer 4 Security bitmask flags
pub const SEC_CLOUD: u16 = 1 << 0; // 1
pub const SEC_DATACENTER: u16 = 1 << 1; // 2
pub const SEC_CDN: u16 = 1 << 2; // 4
pub const SEC_TOR_EXIT: u16 = 1 << 3; // 8
pub const SEC_PRIVACY_RELAY: u16 = 1 << 4; // 16
pub const SEC_THREAT: u16 = 1 << 5; // 32

pub const ADVISORY_LOCK_KEY: i64 = 5_063_961_992_970_600_449;

#[derive(Debug, Error)]
pub enum DgipError {
    #[error("{0}")]
    InvalidIp(String),

    #[error("{0}")]
    InvalidConfig(String),

    #[error("{0}")]
    Compilation(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type DgipResult<T> = Result<T, DgipError>;

/// Format a 32-bit unsigned integer as dotted-quad IPv4 (`a.b.c.d`).
#[inline]
pub fn format_ipv4(val: u32) -> String {
    Ipv4Addr::from(val).to_string()
}

/// Format a 128-bit unsigned integer strictly per RFC 5952 hex compression.
pub fn format_ipv6(val: u128) -> String {
    let mut groups = [0u16; 8];
    for (idx, slot) in groups.iter_mut().enumerate() {
        let shift = (7 - idx) * 16;
        *slot = ((val >> shift) & 0xFFFF) as u16;
    }

    // Find longest run of consecutive zero hextets (length >= 2, leftmost wins ties)
    let mut best_start: Option<usize> = None;
    let mut best_len: usize = 0;
    let mut i = 0;
    while i < 8 {
        if groups[i] == 0 {
            let mut j = i;
            while j < 8 && groups[j] == 0 {
                j += 1;
            }
            let len = j - i;
            if len >= 2 && len > best_len {
                best_start = Some(i);
                best_len = len;
            }
            i = j;
        } else {
            i += 1;
        }
    }

    let mut out = String::with_capacity(39);
    if let Some(start) = best_start {
        let end = start + best_len;
        if start == 0 && end == 8 {
            return "::".to_string();
        }
        for (idx, &g) in groups[..start].iter().enumerate() {
            if idx > 0 {
                out.push(':');
            }
            use std::fmt::Write;
            let _ = write!(out, "{:x}", g);
        }
        out.push_str("::");
        for (idx, &g) in groups[end..].iter().enumerate() {
            if idx > 0 {
                out.push(':');
            }
            use std::fmt::Write;
            let _ = write!(out, "{:x}", g);
        }
    } else {
        for (idx, &g) in groups.iter().enumerate() {
            if idx > 0 {
                out.push(':');
            }
            use std::fmt::Write;
            let _ = write!(out, "{:x}", g);
        }
    }
    out
}

/// Parsed CIDR network (`IPv4` or `IPv6`) supporting containment checks and canonical formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 {
        network: u32,
        broadcast: u32,
        prefix_len: u8,
    },
    V6 {
        network: u128,
        broadcast: u128,
        prefix_len: u8,
    },
}

impl IpNet {
    pub fn parse_non_strict(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        let (addr_part, plen_str) = s
            .split_once('/')
            .ok_or_else(|| format!("Missing '/' prefix length in CIDR: {raw:?}"))?;
        if addr_part.contains('%') {
            return Err(format!("Zone IDs not allowed in CIDR: {raw:?}"));
        }
        let plen: u8 = plen_str
            .parse()
            .map_err(|_| format!("Invalid prefix length in CIDR: {raw:?}"))?;
        let ip: IpAddr = addr_part
            .parse()
            .map_err(|_| format!("Invalid IP address in CIDR: {raw:?}"))?;
        match ip {
            IpAddr::V4(v4) => {
                if plen > 32 {
                    return Err(format!("IPv4 prefix length > 32 in CIDR: {raw:?}"));
                }
                let raw_u32 = u32::from(v4);
                let mask = if plen == 0 {
                    0u32
                } else {
                    !0u32 << (32 - plen)
                };
                let net = raw_u32 & mask;
                let bcast = net | !mask;
                Ok(IpNet::V4 {
                    network: net,
                    broadcast: bcast,
                    prefix_len: plen,
                })
            }
            IpAddr::V6(v6) => {
                if plen > 128 {
                    return Err(format!("IPv6 prefix length > 128 in CIDR: {raw:?}"));
                }
                let raw_u128 = u128::from(v6);
                let mask = if plen == 0 {
                    0u128
                } else {
                    !0u128 << (128 - plen)
                };
                let net = raw_u128 & mask;
                let bcast = net | !mask;
                Ok(IpNet::V6 {
                    network: net,
                    broadcast: bcast,
                    prefix_len: plen,
                })
            }
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            IpNet::V4 { .. } => 4,
            IpNet::V6 { .. } => 6,
        }
    }

    pub fn prefix_len(&self) -> u8 {
        match self {
            IpNet::V4 { prefix_len, .. } => *prefix_len,
            IpNet::V6 { prefix_len, .. } => *prefix_len,
        }
    }

    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (
                IpNet::V4 {
                    network, broadcast, ..
                },
                IpAddr::V4(v4),
            ) => {
                let v = u32::from(v4);
                v >= network && v <= broadcast
            }
            (
                IpNet::V6 {
                    network, broadcast, ..
                },
                IpAddr::V6(v6),
            ) => {
                let v = u128::from(v6);
                v >= network && v <= broadcast
            }
            _ => false,
        }
    }

    pub fn canonical_cidr(&self) -> String {
        match *self {
            IpNet::V4 {
                network,
                prefix_len,
                ..
            } => format!("{}/{}", format_ipv4(network), prefix_len),
            IpNet::V6 {
                network,
                prefix_len,
                ..
            } => format!("{}/{}", format_ipv6(network), prefix_len),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialRangeRuleV4 {
    pub start_int: u32,
    pub end_int: u32,
    pub category: String,
    pub priority: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecialRangeRuleV6 {
    pub start_int: u128,
    pub end_int: u128,
    pub category: String,
    pub priority: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedSourceSpec {
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

#[derive(Debug, Clone)]
pub struct RuntimeCatalog {
    pub catalog_version: i64,
    pub raw_config: HashMap<String, Value>,
    pub bootstrap_enabled: bool,
    pub bootstrap_bundle_url: String,
    pub live_sync_interval_seconds: i64,
    pub weekly_release_enabled: bool,
    pub weekly_release_weekday: i32,
    pub weekly_release_utc_hour: i32,
    pub version_prefix: String,
    pub release_title_template: String,
    pub snapshot_retention: i32,
    pub bgp_min_peers: i32,
    pub bgp_ipv4_min_prefixlen: u8,
    pub bgp_ipv6_min_prefixlen: u8,
    pub rpki_reject_invalid: bool,
    pub enrichment_strict: bool,
    pub http_timeout_seconds: f64,
    pub max_redirects: usize,
    pub upstream_user_agent: String,
    pub source_attribution: String,
    pub asn_min_valid: u32,
    pub asn_max_valid: u32,
    pub rate_limit_per_minute: usize,
    pub download_rate_limit_per_minute: usize,
    pub rate_limit_window_seconds: f64,
    pub rate_limit_max_keys: usize,
    pub max_batch_size: usize,
    pub max_request_body_bytes: usize,
    pub trusted_proxies: Vec<IpNet>,
    pub snapshot_latest_cache_max_age: i64,
    pub snapshot_immutable_cache_max_age: i64,
    pub swagger_enabled: bool,
    pub feed_sources: Vec<FeedSourceSpec>,
    pub allowed_hosts: HashSet<String>,
    pub allowed_host_rows: Vec<(String, bool, Option<String>)>,
    pub valid_country_codes: HashSet<String>,
    pub country_details: HashMap<String, (String, String, String)>,
    pub continents_count: usize,
    pub special_v4_rules: Vec<SpecialRangeRuleV4>,
    pub special_v6_rules: Vec<SpecialRangeRuleV6>,
}

#[derive(Debug, Clone, Default)]
pub struct RawDbMatch {
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub network_type: Option<String>,
    pub rpki_status: Option<String>,
    pub asn_start_ip: Option<String>,
    pub asn_end_ip: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub continent_code: Option<String>,
    pub continent_name: Option<String>,
    pub region_code: Option<String>,
    pub city: Option<String>,
    pub geo_source: Option<String>,
    pub country_start_ip: Option<String>,
    pub country_end_ip: Option<String>,
    pub sec_flags: Option<i16>,
    pub sec_provider: Option<String>,
    pub sec_threat_feeds: Option<String>,
    pub sec_start_ip: Option<String>,
    pub sec_end_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CachedArtifact {
    pub path: PathBuf,
    pub filename: String,
    pub content_type: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DbState {
    pub initial_bootstrapped: bool,
    pub active_slot: String,
    pub live_feed_sha256: Option<String>,
    pub live_row_counts: Option<HashMap<String, usize>>,
    pub live_updated_at: Option<DateTime<Utc>>,
    pub active_version: Option<String>,
    pub catalog_version: i64,
    pub last_sync_attempt_at: Option<DateTime<Utc>>,
    pub last_sync_success_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    pub last_release_attempt_at: Option<DateTime<Utc>>,
    pub last_release_success_at: Option<DateTime<Utc>>,
    pub last_release_error: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct ReleaseRow {
    pub build_number: i64,
    pub version: String,
    pub release_title: String,
    pub released_at: DateTime<Utc>,
    pub previous_version: Option<String>,
    pub combined_feed_sha256: Option<String>,
    pub bundle_sha256: String,
    pub bundle_size_bytes: i64,
    pub manifest_json: Value,
    pub row_counts: HashMap<String, usize>,
    pub diff_summary_json: Value,
    pub release_notes_md: String,
    pub operator_note: Option<String>,
    pub source_attribution: String,
    pub has_blobs: bool,
}

// Memory-compact compiled interval row types (`u32` for IPv4, `u128` for IPv6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnRow<I: Copy> {
    pub start: I,
    pub end: I,
    pub asn: u32,
    pub org: String,
    pub network_type: String,
    pub rpki_status: String,
}

pub type AsnV4Row = AsnRow<u32>;
pub type AsnV6Row = AsnRow<u128>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryRow<I: Copy> {
    pub start: I,
    pub end: I,
    pub cc: String,
    pub region_code: String,
    pub city: String,
    pub geo_source: String,
}

pub type CountryV4Row = CountryRow<u32>;
pub type CountryV6Row = CountryRow<u128>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRow<I: Copy> {
    pub start: I,
    pub end: I,
    pub flags: u16,
    pub provider: String,
    pub threat_feeds: String,
}

pub type SecurityV4Row = SecurityRow<u32>;
pub type SecurityV6Row = SecurityRow<u128>;

#[derive(Debug, Clone)]
pub struct CompiledTables {
    pub asn_v4: Vec<AsnV4Row>,
    pub asn_v6: Vec<AsnV6Row>,
    pub country_v4: Vec<CountryV4Row>,
    pub country_v6: Vec<CountryV6Row>,
    pub security_v4: Vec<SecurityV4Row>,
    pub security_v6: Vec<SecurityV6Row>,
    pub normalized_sha256: String,
}

impl CompiledTables {
    pub fn row_counts(&self) -> HashMap<String, usize> {
        let mut m = HashMap::with_capacity(6);
        m.insert(ASN_IPV4_FILENAME.to_string(), self.asn_v4.len());
        m.insert(ASN_IPV6_FILENAME.to_string(), self.asn_v6.len());
        m.insert(COUNTRY_IPV4_FILENAME.to_string(), self.country_v4.len());
        m.insert(COUNTRY_IPV6_FILENAME.to_string(), self.country_v6.len());
        m.insert(SECURITY_IPV4_FILENAME.to_string(), self.security_v4.len());
        m.insert(SECURITY_IPV6_FILENAME.to_string(), self.security_v6.len());
        m
    }
}

#[derive(Debug, Clone)]
pub struct BuiltArtifact {
    pub filename: String,
    pub content_type: String,
    pub payload: Vec<u8>,
    pub sha256: String,
    pub record_count: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PackagedSnapshot {
    pub version: String,
    pub release_title: String,
    pub released_iso: String,
    pub manifest: Value,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: String,
    pub bundle_bytes: Vec<u8>,
    pub bundle_sha256: String,
    pub sha256sums_bytes: Vec<u8>,
    pub sha256sums_sha256: String,
    pub dataset_artifacts: HashMap<String, BuiltArtifact>,
}
