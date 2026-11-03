//! Layers 2, 3, and 4 open IP intelligence parsers and interval algorithms.
//!
//! - Layer 2: Operator & Cloud Regional Geofeeds (RFC 8805 + GCP/OCI JSON) and priority overlay.
//! - Layer 3: RPKI Route Origin Validation (RFC 6811 / RFC 7607 `AS0`) & ASN Network Type.
//! - Layer 4: Cloud, CDN, Privacy Relay, Tor Exit & Threat Intelligence sweep-line merger.

use crate::compiler::decompress_bounded;
use crate::ip_utils::{classify_special_v4, classify_special_v6};
use crate::seed_data::is_valid_country_code;
use crate::types::{
    DgipError, DgipResult, SecurityV4Row, SecurityV6Row, SpecialRangeRuleV4, SpecialRangeRuleV6,
};
pub use crate::types::{
    SEC_CDN, SEC_CLOUD, SEC_DATACENTER, SEC_PRIVACY_RELAY, SEC_THREAT, SEC_TOR_EXIT,
};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

/// Layer 2 geolocation attributes (`geo_source` is `"rir"` or `"geofeed"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GeoAttr {
    pub cc: String,
    pub region_code: String,
    pub city: String,
    pub geo_source: String,
}

impl GeoAttr {
    pub fn new(
        cc: impl Into<String>,
        region_code: impl Into<String>,
        city: impl Into<String>,
        geo_source: impl Into<String>,
    ) -> Self {
        Self {
            cc: cc.into(),
            region_code: region_code.into(),
            city: city.into(),
            geo_source: geo_source.into(),
        }
    }
}

/// Raw unmerged Layer 4 security/infrastructure interval from a single upstream feed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawSecurityInterval<I: Copy> {
    pub start: I,
    pub end: I,
    pub flags: u16,
    pub provider: String,
    pub threat_feed: String,
}

pub type RawSecurityIntervalV4 = RawSecurityInterval<u32>;
pub type RawSecurityIntervalV6 = RawSecurityInterval<u128>;

pub type CloudGeoParseOutput = (
    Vec<(u32, u32, GeoAttr)>,
    Vec<(u128, u128, GeoAttr)>,
    Vec<RawSecurityIntervalV4>,
    Vec<RawSecurityIntervalV6>,
);

fn provider_priority(provider: &str) -> i32 {
    match provider {
        "apple_icloud_relay" => 100,
        "cloudflare" | "fastly" => 95,
        "github" => 90,
        "aws" | "gcp" | "oracle" | "digitalocean" | "linode" | "vultr" => 50,
        _ => 10,
    }
}

fn geofeed_security_profile(feed_key: &str) -> Option<(&'static str, u16)> {
    match feed_key {
        "geo-aws" => Some(("aws", SEC_CLOUD | SEC_DATACENTER)),
        "geo-digitalocean" => Some(("digitalocean", SEC_CLOUD | SEC_DATACENTER)),
        "geo-linode" => Some(("linode", SEC_CLOUD | SEC_DATACENTER)),
        "geo-vultr" => Some(("vultr", SEC_CLOUD | SEC_DATACENTER)),
        "geo-apple-relay" => Some(("apple_icloud_relay", SEC_PRIVACY_RELAY)),
        _ => None,
    }
}

fn gcp_scope_location(scope_norm: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match scope_norm {
        "africa-south1" => Some(("ZA", "ZA-GP", "Johannesburg")),
        "asia-east1" => Some(("TW", "TW-CHA", "Changhua County")),
        "asia-east2" => Some(("HK", "HK-HK", "Hong Kong")),
        "asia-northeast1" => Some(("JP", "JP-13", "Tokyo")),
        "asia-northeast2" => Some(("JP", "JP-27", "Osaka")),
        "asia-northeast3" => Some(("KR", "KR-11", "Seoul")),
        "asia-south1" => Some(("IN", "IN-MH", "Mumbai")),
        "asia-south2" => Some(("IN", "IN-DL", "Delhi")),
        "asia-southeast1" => Some(("SG", "SG-01", "Singapore")),
        "asia-southeast2" => Some(("ID", "ID-JK", "Jakarta")),
        "asia-southeast3" => Some(("TH", "TH-10", "Bangkok")),
        "australia-southeast1" => Some(("AU", "AU-NSW", "Sydney")),
        "australia-southeast2" => Some(("AU", "AU-VIC", "Melbourne")),
        "europe-central2" => Some(("PL", "PL-14", "Warsaw")),
        "europe-north1" => Some(("FI", "FI-09", "Hamina")),
        "europe-north2" => Some(("SE", "SE-AB", "Stockholm")),
        "europe-southwest1" => Some(("ES", "ES-MD", "Madrid")),
        "europe-west1" => Some(("BE", "BE-WHT", "St. Ghislain")),
        "europe-west2" => Some(("GB", "GB-LND", "London")),
        "europe-west3" => Some(("DE", "DE-HE", "Frankfurt")),
        "europe-west4" => Some(("NL", "NL-GR", "Eemshaven")),
        "europe-west6" => Some(("CH", "CH-ZH", "Zurich")),
        "europe-west8" => Some(("IT", "IT-25", "Milan")),
        "europe-west9" => Some(("FR", "FR-IDF", "Paris")),
        "europe-west10" => Some(("DE", "DE-BE", "Berlin")),
        "europe-west12" => Some(("IT", "IT-21", "Turin")),
        "me-central1" => Some(("QA", "QA-DA", "Doha")),
        "me-central2" => Some(("SA", "SA-04", "Dammam")),
        "me-west1" => Some(("IL", "IL-TA", "Tel Aviv")),
        "northamerica-northeast1" => Some(("CA", "CA-QC", "Montreal")),
        "northamerica-northeast2" => Some(("CA", "CA-ON", "Toronto")),
        "northamerica-south1" => Some(("MX", "MX-QUE", "Queretaro")),
        "southamerica-east1" => Some(("BR", "BR-SP", "Sao Paulo")),
        "southamerica-west1" => Some(("CL", "CL-RM", "Santiago")),
        "us-central1" => Some(("US", "US-IA", "Council Bluffs")),
        "us-central2" => Some(("US", "US-OK", "Pryor")),
        "us-east1" => Some(("US", "US-SC", "Moncks Corner")),
        "us-east4" => Some(("US", "US-VA", "Ashburn")),
        "us-east5" => Some(("US", "US-OH", "Columbus")),
        "us-east7" => Some(("US", "US-AL", "Bridgeport")),
        "us-south1" => Some(("US", "US-TX", "Dallas")),
        "us-west1" => Some(("US", "US-OR", "The Dalles")),
        "us-west2" => Some(("US", "US-CA", "Los Angeles")),
        "us-west3" => Some(("US", "US-UT", "Salt Lake City")),
        "us-west4" => Some(("US", "US-NV", "Las Vegas")),
        "us-west8" => Some(("US", "US-AZ", "Phoenix")),
        _ => None,
    }
}

fn resolve_gcp_scope(scope: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let norm = scope.trim().to_ascii_lowercase();
    if norm.is_empty() || norm == "global" {
        return None;
    }
    if let Some(exact) = gcp_scope_location(&norm) {
        return Some(exact);
    }
    if norm.starts_with("us-") {
        return Some(("US", "", ""));
    }
    if norm.starts_with("australia-") {
        return Some(("AU", "", ""));
    }
    None
}

fn oracle_region_location(region_norm: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match region_norm {
        "af-casablanca-1" => Some(("MA", "MA-06", "Casablanca")),
        "af-johannesburg-1" => Some(("ZA", "ZA-GP", "Johannesburg")),
        "ap-batam-1" => Some(("ID", "ID-KR", "Batam")),
        "ap-chuncheon-1" => Some(("KR", "KR-42", "Chuncheon")),
        "ap-delhi-1" => Some(("IN", "IN-DL", "Delhi")),
        "ap-hyderabad-1" => Some(("IN", "IN-TG", "Hyderabad")),
        "ap-kulai-1" | "ap-kulai-2" => Some(("MY", "MY-01", "Kulai")),
        "ap-melbourne-1" => Some(("AU", "AU-VIC", "Melbourne")),
        "ap-mumbai-1" => Some(("IN", "IN-MH", "Mumbai")),
        "ap-osaka-1" => Some(("JP", "JP-27", "Osaka")),
        "ap-seoul-1" => Some(("KR", "KR-11", "Seoul")),
        "ap-singapore-1" | "ap-singapore-2" => Some(("SG", "SG-01", "Singapore")),
        "ap-sydney-1" => Some(("AU", "AU-NSW", "Sydney")),
        "ap-tokyo-1" => Some(("JP", "JP-13", "Tokyo")),
        "ca-montreal-1" => Some(("CA", "CA-QC", "Montreal")),
        "ca-toronto-1" => Some(("CA", "CA-ON", "Toronto")),
        "eu-amsterdam-1" => Some(("NL", "NL-NH", "Amsterdam")),
        "eu-dublin-3" => Some(("IE", "IE-D", "Dublin")),
        "eu-frankfurt-1" => Some(("DE", "DE-HE", "Frankfurt")),
        "eu-jovanovac-1" => Some(("RS", "RS-12", "Jovanovac")),
        "eu-madrid-1" | "eu-madrid-3" => Some(("ES", "ES-MD", "Madrid")),
        "eu-marseille-1" => Some(("FR", "FR-PAC", "Marseille")),
        "eu-milan-1" => Some(("IT", "IT-25", "Milan")),
        "eu-paris-1" => Some(("FR", "FR-IDF", "Paris")),
        "eu-stockholm-1" => Some(("SE", "SE-AB", "Stockholm")),
        "eu-zurich-1" => Some(("CH", "CH-ZH", "Zurich")),
        "il-jerusalem-1" => Some(("IL", "IL-JM", "Jerusalem")),
        "me-abudhabi-1" => Some(("AE", "AE-AZ", "Abu Dhabi")),
        "me-dubai-1" => Some(("AE", "AE-DU", "Dubai")),
        "me-jeddah-1" => Some(("SA", "SA-02", "Jeddah")),
        "me-riyadh-1" => Some(("SA", "SA-01", "Riyadh")),
        "mx-monterrey-1" => Some(("MX", "MX-NLE", "Monterrey")),
        "mx-queretaro-1" => Some(("MX", "MX-QUE", "Queretaro")),
        "sa-bogota-1" => Some(("CO", "CO-DC", "Bogota")),
        "sa-riodejaneiro-2" => Some(("BR", "BR-RJ", "Rio de Janeiro")),
        "sa-santiago-1" => Some(("CL", "CL-RM", "Santiago")),
        "sa-saopaulo-1" => Some(("BR", "BR-SP", "Sao Paulo")),
        "sa-valparaiso-1" => Some(("CL", "CL-VS", "Valparaiso")),
        "sa-vinhedo-1" => Some(("BR", "BR-SP", "Vinhedo")),
        "uk-cardiff-1" => Some(("GB", "GB-CRF", "Newport")),
        "uk-london-1" => Some(("GB", "GB-LND", "London")),
        "us-abilene-1" => Some(("US", "US-TX", "Abilene")),
        "us-ashburn-1" => Some(("US", "US-VA", "Ashburn")),
        "us-boardman-1" => Some(("US", "US-OR", "Boardman")),
        "us-chicago-1" => Some(("US", "US-IL", "Chicago")),
        "us-dallas-1" => Some(("US", "US-TX", "Dallas")),
        "us-desmoines-1" => Some(("US", "US-IA", "Des Moines")),
        "us-lenexa-1" => Some(("US", "US-KS", "Lenexa")),
        "us-phoenix-1" => Some(("US", "US-AZ", "Phoenix")),
        "us-quincy-1" => Some(("US", "US-WA", "Quincy")),
        "us-saltlake-2" => Some(("US", "US-UT", "Salt Lake City")),
        "us-sanantonio-1" => Some(("US", "US-TX", "San Antonio")),
        "us-sanjose-1" => Some(("US", "US-CA", "San Jose")),
        "us-shawnee-1" => Some(("US", "US-KS", "Shawnee")),
        _ => None,
    }
}

fn resolve_oracle_region(region: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let norm = region.trim().to_ascii_lowercase();
    if norm.is_empty() {
        return None;
    }
    if let Some(exact) = oracle_region_location(&norm) {
        return Some(exact);
    }
    for (prefix, cc) in [
        ("us-", "US"),
        ("uk-", "GB"),
        ("ca-", "CA"),
        ("il-", "IL"),
        ("mx-", "MX"),
    ] {
        if norm.starts_with(prefix) {
            return Some((cc, "", ""));
        }
    }
    None
}

pub(crate) fn clean_geo_text(val: &str, max_len: usize) -> String {
    let filtered: String = val
        .chars()
        .filter(|&ch| ch >= ' ' && ch != '\x7f')
        .collect();
    filtered.trim().chars().take(max_len).collect()
}

pub(crate) fn parse_ipv4_fast(dotted: &str) -> Option<u32> {
    let mut parts = dotted.split('.');
    let a = parts.next()?.parse::<u16>().ok().filter(|&v| v <= 255)? as u32;
    let b = parts.next()?.parse::<u16>().ok().filter(|&v| v <= 255)? as u32;
    let c = parts.next()?.parse::<u16>().ok().filter(|&v| v <= 255)? as u32;
    let d = parts.next()?.parse::<u16>().ok().filter(|&v| v <= 255)? as u32;
    if parts.next().is_some() {
        return None;
    }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

#[derive(Debug, Clone, Copy)]
enum ParsedCidrBounds {
    V4 { start: u32, end: u32, plen: u8 },
    V6 { start: u128, end: u128, plen: u8 },
}

fn parse_cidr_bounds(
    raw_cidr: &str,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> Option<ParsedCidrBounds> {
    let text = raw_cidr.trim();
    let (addr_raw, plen_raw) = text.split_once('/')?;
    let addr_part = addr_raw.trim();
    if addr_part.is_empty() || addr_part.contains('%') {
        return None;
    }
    let plen: u8 = plen_raw.trim().parse().ok()?;

    if !addr_part.contains(':') {
        if !(1..=32).contains(&plen) {
            return None;
        }
        let ip_int = parse_ipv4_fast(addr_part)?;
        let host_bits = 32 - plen;
        let s_int = (ip_int >> host_bits) << host_bits;
        let e_int = s_int + ((1u32 << host_bits) - 1);
        if classify_special_v4(s_int, v4_special).is_some() {
            return None;
        }
        Some(ParsedCidrBounds::V4 {
            start: s_int,
            end: e_int,
            plen,
        })
    } else {
        if !(1..=128).contains(&plen) {
            return None;
        }
        let v6: Ipv6Addr = addr_part.parse().ok()?;
        let ip_int = u128::from(v6);
        let host_bits = 128 - plen;
        let s_int = (ip_int >> host_bits) << host_bits;
        let e_int = s_int + ((1u128 << host_bits) - 1);
        if classify_special_v6(s_int, v6_special).is_some() {
            return None;
        }
        Some(ParsedCidrBounds::V6 {
            start: s_int,
            end: e_int,
            plen,
        })
    }
}

/// Overlay sorted disjoint `override_intervals` onto sorted disjoint `base` IPv4 intervals in `O(N + M)` time.
///
/// Preserves country inheritance if an override entry omits `cc`, overrides `base` when `cc` is present,
/// and coalesces adjacent identical `GeoAttr` intervals safely at `u32::MAX`.
pub fn overlay_disjoint_intervals_v4(
    base: &[(u32, u32, GeoAttr)],
    override_intervals: &[(u32, u32, GeoAttr)],
) -> Vec<(u32, u32, GeoAttr)> {
    if override_intervals.is_empty() {
        return base.to_vec();
    }
    if base.is_empty() {
        return override_intervals
            .iter()
            .filter(|(_, _, a)| !a.cc.is_empty())
            .cloned()
            .collect();
    }

    let mut out: Vec<(u32, u32, GeoAttr)> =
        Vec::with_capacity(base.len() + override_intervals.len());
    let mut emit = |s: u32, e: u32, val: GeoAttr| {
        if s > e {
            return;
        }
        if let Some(last) = out.last_mut() {
            if last.1.checked_add(1) == Some(s) && last.2 == val {
                last.1 = e;
                return;
            }
        }
        out.push((s, e, val));
    };

    let mut i = 0usize;
    let n_base = base.len();
    let mut b_cur: Option<u32> = Some(base[0].0);

    for (o_s, o_e, o_val) in override_intervals {
        let (o_s, o_e) = (*o_s, *o_e);
        if o_s > o_e {
            continue;
        }

        while i < n_base {
            let Some(cur) = b_cur else {
                i = n_base;
                break;
            };
            let (b_s_orig, b_e, ref b_val) = base[i];
            let b_s = b_s_orig.max(cur);
            if b_s > b_e {
                i += 1;
                continue;
            }
            if b_e < o_s {
                emit(b_s, b_e, b_val.clone());
                i += 1;
            } else {
                if b_s < o_s {
                    emit(b_s, o_s - 1, b_val.clone());
                }
                break;
            }
        }

        if !o_val.cc.is_empty() {
            emit(o_s, o_e, o_val.clone());
            b_cur = o_e.checked_add(1);
            while i < n_base && base[i].1 <= o_e {
                i += 1;
            }
        } else {
            // Inherit country from underlying base intervals when override omits country
            while i < n_base {
                let Some(cur) = b_cur else {
                    i = n_base;
                    break;
                };
                let (b_s_orig, b_e, ref b_val) = base[i];
                let b_s = b_s_orig.max(cur).max(o_s);
                if b_s > o_e {
                    break;
                }
                let seg_e = b_e.min(o_e);
                if b_s <= seg_e {
                    let merged = GeoAttr {
                        cc: b_val.cc.clone(),
                        region_code: if o_val.region_code.is_empty() {
                            b_val.region_code.clone()
                        } else {
                            o_val.region_code.clone()
                        },
                        city: if o_val.city.is_empty() {
                            b_val.city.clone()
                        } else {
                            o_val.city.clone()
                        },
                        geo_source: o_val.geo_source.clone(),
                    };
                    emit(b_s, seg_e, merged);
                }
                if b_e <= o_e {
                    i += 1;
                } else {
                    break;
                }
            }
            b_cur = o_e.checked_add(1);
        }
    }

    if let Some(cur) = b_cur {
        while i < n_base {
            let (b_s_orig, b_e, ref b_val) = base[i];
            let b_s = b_s_orig.max(cur);
            if b_s <= b_e {
                emit(b_s, b_e, b_val.clone());
            }
            i += 1;
        }
    }

    out
}

/// Overlay sorted disjoint `override_intervals` onto sorted disjoint `base` IPv6 intervals in `O(N + M)` time.
pub fn overlay_disjoint_intervals_v6(
    base: &[(u128, u128, GeoAttr)],
    override_intervals: &[(u128, u128, GeoAttr)],
) -> Vec<(u128, u128, GeoAttr)> {
    if override_intervals.is_empty() {
        return base.to_vec();
    }
    if base.is_empty() {
        return override_intervals
            .iter()
            .filter(|(_, _, a)| !a.cc.is_empty())
            .cloned()
            .collect();
    }

    let mut out: Vec<(u128, u128, GeoAttr)> =
        Vec::with_capacity(base.len() + override_intervals.len());
    let mut emit = |s: u128, e: u128, val: GeoAttr| {
        if s > e {
            return;
        }
        if let Some(last) = out.last_mut() {
            if last.1.checked_add(1) == Some(s) && last.2 == val {
                last.1 = e;
                return;
            }
        }
        out.push((s, e, val));
    };

    let mut i = 0usize;
    let n_base = base.len();
    let mut b_cur: Option<u128> = Some(base[0].0);

    for (o_s, o_e, o_val) in override_intervals {
        let (o_s, o_e) = (*o_s, *o_e);
        if o_s > o_e {
            continue;
        }

        while i < n_base {
            let Some(cur) = b_cur else {
                i = n_base;
                break;
            };
            let (b_s_orig, b_e, ref b_val) = base[i];
            let b_s = b_s_orig.max(cur);
            if b_s > b_e {
                i += 1;
                continue;
            }
            if b_e < o_s {
                emit(b_s, b_e, b_val.clone());
                i += 1;
            } else {
                if b_s < o_s {
                    emit(b_s, o_s - 1, b_val.clone());
                }
                break;
            }
        }

        if !o_val.cc.is_empty() {
            emit(o_s, o_e, o_val.clone());
            b_cur = o_e.checked_add(1);
            while i < n_base && base[i].1 <= o_e {
                i += 1;
            }
        } else {
            while i < n_base {
                let Some(cur) = b_cur else {
                    i = n_base;
                    break;
                };
                let (b_s_orig, b_e, ref b_val) = base[i];
                let b_s = b_s_orig.max(cur).max(o_s);
                if b_s > o_e {
                    break;
                }
                let seg_e = b_e.min(o_e);
                if b_s <= seg_e {
                    let merged = GeoAttr {
                        cc: b_val.cc.clone(),
                        region_code: if o_val.region_code.is_empty() {
                            b_val.region_code.clone()
                        } else {
                            o_val.region_code.clone()
                        },
                        city: if o_val.city.is_empty() {
                            b_val.city.clone()
                        } else {
                            o_val.city.clone()
                        },
                        geo_source: o_val.geo_source.clone(),
                    };
                    emit(b_s, seg_e, merged);
                }
                if b_e <= o_e {
                    i += 1;
                } else {
                    break;
                }
            }
            b_cur = o_e.checked_add(1);
        }
    }

    if let Some(cur) = b_cur {
        while i < n_base {
            let (b_s_orig, b_e, ref b_val) = base[i];
            let b_s = b_s_orig.max(cur);
            if b_s <= b_e {
                emit(b_s, b_e, b_val.clone());
            }
            i += 1;
        }
    }

    out
}

fn coalesce_same_security_ranges_v4(
    mut ranges: Vec<(u32, u32)>,
    flags: u16,
    provider: &str,
    threat: &str,
) -> Vec<RawSecurityIntervalV4> {
    if ranges.is_empty() || flags == 0 {
        return Vec::new();
    }
    ranges.sort_unstable();
    let mut merged = Vec::new();
    let (mut cur_s, mut cur_e) = ranges[0];
    for &(s, e) in &ranges[1..] {
        if cur_e == u32::MAX || s <= cur_e + 1 {
            if e > cur_e {
                cur_e = e;
            }
        } else {
            merged.push(RawSecurityIntervalV4 {
                start: cur_s,
                end: cur_e,
                flags,
                provider: provider.to_string(),
                threat_feed: threat.to_string(),
            });
            cur_s = s;
            cur_e = e;
        }
    }
    merged.push(RawSecurityIntervalV4 {
        start: cur_s,
        end: cur_e,
        flags,
        provider: provider.to_string(),
        threat_feed: threat.to_string(),
    });
    merged
}

fn coalesce_same_security_ranges_v6(
    mut ranges: Vec<(u128, u128)>,
    flags: u16,
    provider: &str,
    threat: &str,
) -> Vec<RawSecurityIntervalV6> {
    if ranges.is_empty() || flags == 0 {
        return Vec::new();
    }
    ranges.sort_unstable();
    let mut merged = Vec::new();
    let (mut cur_s, mut cur_e) = ranges[0];
    for &(s, e) in &ranges[1..] {
        if cur_e == u128::MAX || s <= cur_e + 1 {
            if e > cur_e {
                cur_e = e;
            }
        } else {
            merged.push(RawSecurityIntervalV6 {
                start: cur_s,
                end: cur_e,
                flags,
                provider: provider.to_string(),
                threat_feed: threat.to_string(),
            });
            cur_s = s;
            cur_e = e;
        }
    }
    merged.push(RawSecurityIntervalV6 {
        start: cur_s,
        end: cur_e,
        flags,
        provider: provider.to_string(),
        threat_feed: threat.to_string(),
    });
    merged
}

/// Parse an IETF RFC 8805 CSV geofeed (`ip_prefix,alpha2code,region,city,postal_code`).
pub fn parse_rfc8805_geofeed(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    allowed_countries: &HashSet<String>,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<CloudGeoParseOutput> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut geo_v4: Vec<(u32, u32, GeoAttr)> = Vec::new();
    let mut geo_v6: Vec<(u128, u128, GeoAttr)> = Vec::new();
    let mut sec_v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut sec_v6_raw: Vec<(u128, u128)> = Vec::new();

    let (provider, sec_flags) = geofeed_security_profile(feed_key).unwrap_or(("", 0));
    let mut accepted = 0usize;

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(text.as_bytes());

    for rec_res in rdr.records() {
        let Ok(row) = rec_res else {
            continue;
        };
        let Some(first_raw) = row.get(0) else {
            continue;
        };
        let first = first_raw.trim();
        if first.is_empty() || first.starts_with('#') {
            continue;
        }
        let Some(parsed) = parse_cidr_bounds(first, v4_special, v6_special) else {
            continue;
        };
        accepted += 1;

        match parsed {
            ParsedCidrBounds::V4 { start, end, .. } => {
                if sec_flags != 0 {
                    sec_v4_raw.push((start, end));
                }
                let Some(cc_raw) = row.get(1) else {
                    continue;
                };
                let cc = cc_raw.trim().to_uppercase();
                if !is_valid_country_code(&cc, Some(allowed_countries)) {
                    continue;
                }
                let region = row
                    .get(2)
                    .map(|r| clean_geo_text(r, 32).to_uppercase())
                    .unwrap_or_default();
                let city = row
                    .get(3)
                    .map(|c| clean_geo_text(c, 96))
                    .unwrap_or_default();
                geo_v4.push((start, end, GeoAttr::new(cc, region, city, "geofeed")));
            }
            ParsedCidrBounds::V6 { start, end, .. } => {
                if sec_flags != 0 {
                    sec_v6_raw.push((start, end));
                }
                let Some(cc_raw) = row.get(1) else {
                    continue;
                };
                let cc = cc_raw.trim().to_uppercase();
                if !is_valid_country_code(&cc, Some(allowed_countries)) {
                    continue;
                }
                let region = row
                    .get(2)
                    .map(|r| clean_geo_text(r, 32).to_uppercase())
                    .unwrap_or_default();
                let city = row
                    .get(3)
                    .map(|c| clean_geo_text(c, 96))
                    .unwrap_or_default();
                geo_v6.push((start, end, GeoAttr::new(cc, region, city, "geofeed")));
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "RFC 8805 geofeed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    let sec_v4 = if sec_flags != 0 {
        coalesce_same_security_ranges_v4(sec_v4_raw, sec_flags, provider, "")
    } else {
        Vec::new()
    };
    let sec_v6 = if sec_flags != 0 {
        coalesce_same_security_ranges_v6(sec_v6_raw, sec_flags, provider, "")
    } else {
        Vec::new()
    };

    Ok((geo_v4, geo_v6, sec_v4, sec_v6))
}

/// Parse Google Cloud `cloud.json` (`prefixes: [{ipv4Prefix|ipv6Prefix, scope}]`).
pub fn parse_gcp_cloud_json(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    allowed_countries: &HashSet<String>,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<CloudGeoParseOutput> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let payload: Value = serde_json::from_slice(&decompressed).map_err(|e| {
        DgipError::Compilation(format!("Invalid JSON in GCP feed {feed_key:?}: {e}"))
    })?;
    let prefixes = payload
        .get("prefixes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DgipError::Compilation(format!("GCP feed {feed_key:?} missing 'prefixes' list."))
        })?;

    let mut geo_v4: Vec<(u32, u32, GeoAttr)> = Vec::new();
    let mut geo_v6: Vec<(u128, u128, GeoAttr)> = Vec::new();
    let mut sec_v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut sec_v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for item in prefixes {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let raw_cidr = obj
            .get("ipv4Prefix")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| obj.get("ipv6Prefix").and_then(Value::as_str))
            .unwrap_or("");
        let Some(parsed) = parse_cidr_bounds(raw_cidr, v4_special, v6_special) else {
            continue;
        };
        accepted += 1;

        let scope = obj.get("scope").and_then(Value::as_str).unwrap_or("");
        let loc = resolve_gcp_scope(scope);

        match parsed {
            ParsedCidrBounds::V4 { start, end, .. } => {
                sec_v4_raw.push((start, end));
                if let Some((cc, reg, city)) = loc {
                    if is_valid_country_code(cc, Some(allowed_countries)) {
                        geo_v4.push((start, end, GeoAttr::new(cc, reg, city, "geofeed")));
                    }
                }
            }
            ParsedCidrBounds::V6 { start, end, .. } => {
                sec_v6_raw.push((start, end));
                if let Some((cc, reg, city)) = loc {
                    if is_valid_country_code(cc, Some(allowed_countries)) {
                        geo_v6.push((start, end, GeoAttr::new(cc, reg, city, "geofeed")));
                    }
                }
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "GCP feed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    let flags = SEC_CLOUD | SEC_DATACENTER;
    Ok((
        geo_v4,
        geo_v6,
        coalesce_same_security_ranges_v4(sec_v4_raw, flags, "gcp", ""),
        coalesce_same_security_ranges_v6(sec_v6_raw, flags, "gcp", ""),
    ))
}

/// Parse Oracle Cloud `public_ip_ranges.json` (`regions: [{region, cidrs: [{cidr}]}]`).
pub fn parse_oracle_cloud_json(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    allowed_countries: &HashSet<String>,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<CloudGeoParseOutput> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let payload: Value = serde_json::from_slice(&decompressed).map_err(|e| {
        DgipError::Compilation(format!("Invalid JSON in Oracle feed {feed_key:?}: {e}"))
    })?;
    let regions = payload
        .get("regions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            DgipError::Compilation(format!("Oracle feed {feed_key:?} missing 'regions' list."))
        })?;

    let mut geo_v4: Vec<(u32, u32, GeoAttr)> = Vec::new();
    let mut geo_v6: Vec<(u128, u128, GeoAttr)> = Vec::new();
    let mut sec_v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut sec_v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for reg_val in regions {
        let Some(reg_obj) = reg_val.as_object() else {
            continue;
        };
        let region_name = reg_obj.get("region").and_then(Value::as_str).unwrap_or("");
        let loc = resolve_oracle_region(region_name);
        let Some(cidrs) = reg_obj.get("cidrs").and_then(Value::as_array) else {
            continue;
        };

        for c_item in cidrs {
            let raw_cidr = c_item
                .as_object()
                .and_then(|o| o.get("cidr"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(parsed) = parse_cidr_bounds(raw_cidr, v4_special, v6_special) else {
                continue;
            };
            accepted += 1;

            match parsed {
                ParsedCidrBounds::V4 { start, end, .. } => {
                    sec_v4_raw.push((start, end));
                    if let Some((cc, reg, city)) = loc {
                        if is_valid_country_code(cc, Some(allowed_countries)) {
                            geo_v4.push((start, end, GeoAttr::new(cc, reg, city, "geofeed")));
                        }
                    }
                }
                ParsedCidrBounds::V6 { start, end, .. } => {
                    sec_v6_raw.push((start, end));
                    if let Some((cc, reg, city)) = loc {
                        if is_valid_country_code(cc, Some(allowed_countries)) {
                            geo_v6.push((start, end, GeoAttr::new(cc, reg, city, "geofeed")));
                        }
                    }
                }
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "Oracle feed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    let flags = SEC_CLOUD | SEC_DATACENTER;
    Ok((
        geo_v4,
        geo_v6,
        coalesce_same_security_ranges_v4(sec_v4_raw, flags, "oracle", ""),
        coalesce_same_security_ranges_v6(sec_v6_raw, flags, "oracle", ""),
    ))
}

// ---------------------------------------------------------------------------
// Layer 3: RPKI Route Origin Validation (RFC 6811 / RFC 7607) & ASN Types
// ---------------------------------------------------------------------------

/// In-memory index of cryptographically validated RPKI ROA payloads (VRPs).
#[derive(Debug, Clone, Default)]
pub struct RpkiTable {
    pub v4: HashMap<(u32, u8), Vec<(u32, u8)>>,
    pub v6: HashMap<(u128, u8), Vec<(u32, u8)>>,
    pub v4_plens: Vec<u8>,
    pub v6_plens: Vec<u8>,
}

pub type RPKITable = RpkiTable;

impl RpkiTable {
    /// Evaluate RFC 6811 Section 2 + RFC 7607 (`AS0`) Route Origin Validation for IPv4.
    pub fn validate_v4(&self, net: u32, plen: u8, origin_asn: u32) -> &'static str {
        if self.v4.is_empty() {
            return "unknown";
        }
        let mut has_covering_vrp = false;
        for &p in &self.v4_plens {
            if p > plen {
                break;
            }
            let anc_net = if p == 0 {
                0
            } else {
                let shift = 32 - p;
                (net >> shift) << shift
            };
            if let Some(entries) = self.v4.get(&(anc_net, p)) {
                has_covering_vrp = true;
                for &(vrp_asn, vrp_maxlen) in entries {
                    if vrp_asn != 0 && vrp_asn == origin_asn && plen <= vrp_maxlen {
                        return "valid";
                    }
                }
            }
        }
        if has_covering_vrp {
            "invalid"
        } else {
            "unknown"
        }
    }

    /// Evaluate RFC 6811 Section 2 + RFC 7607 (`AS0`) Route Origin Validation for IPv6.
    pub fn validate_v6(&self, net: u128, plen: u8, origin_asn: u32) -> &'static str {
        if self.v6.is_empty() {
            return "unknown";
        }
        let mut has_covering_vrp = false;
        for &p in &self.v6_plens {
            if p > plen {
                break;
            }
            let anc_net = if p == 0 {
                0
            } else {
                let shift = 128 - p;
                (net >> shift) << shift
            };
            if let Some(entries) = self.v6.get(&(anc_net, p)) {
                has_covering_vrp = true;
                for &(vrp_asn, vrp_maxlen) in entries {
                    if vrp_asn != 0 && vrp_asn == origin_asn && plen <= vrp_maxlen {
                        return "valid";
                    }
                }
            }
        }
        if has_covering_vrp {
            "invalid"
        } else {
            "unknown"
        }
    }
}

/// Parse OpenBSD `rpki-client` `vrps.csv` (`ASN,IP Prefix,Max Length,Trust Anchor,Expires`).
pub fn parse_rpki_vrps_csv(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<RpkiTable> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut v4_sets: HashMap<(u32, u8), BTreeSet<(u32, u8)>> = HashMap::new();
    let mut v6_sets: HashMap<(u128, u8), BTreeSet<(u32, u8)>> = HashMap::new();
    let mut accepted = 0usize;

    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with("ASN,") {
            continue;
        }
        let mut parts = line.splitn(4, ',');
        let Some(p0) = parts.next() else {
            continue;
        };
        let Some(p1) = parts.next() else {
            continue;
        };
        let Some(p2) = parts.next() else {
            continue;
        };

        let raw_asn_trim = p0.trim();
        let asn_digits = if raw_asn_trim.len() >= 2
            && raw_asn_trim.as_bytes()[..2].eq_ignore_ascii_case(b"AS")
        {
            &raw_asn_trim[2..]
        } else {
            raw_asn_trim
        };
        let Ok(asn) = asn_digits.parse::<u32>() else {
            continue;
        };
        let Ok(max_len_raw) = p2.trim().parse::<u16>() else {
            continue;
        };

        let Some(parsed) = parse_cidr_bounds(p1, v4_special, v6_special) else {
            continue;
        };
        accepted += 1;

        match parsed {
            ParsedCidrBounds::V4 { start, plen, .. } => {
                let max_len = max_len_raw.clamp(u16::from(plen), 32) as u8;
                v4_sets
                    .entry((start, plen))
                    .or_default()
                    .insert((asn, max_len));
            }
            ParsedCidrBounds::V6 { start, plen, .. } => {
                let max_len = max_len_raw.clamp(u16::from(plen), 128) as u8;
                v6_sets
                    .entry((start, plen))
                    .or_default()
                    .insert((asn, max_len));
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "RPKI VRP feed {feed_key:?} yielded {accepted} VRPs, below minimum {min_records}."
        )));
    }

    let mut v4_plens_set = BTreeSet::new();
    let mut v4 = HashMap::with_capacity(v4_sets.len());
    for (k, vals) in v4_sets {
        v4_plens_set.insert(k.1);
        v4.insert(k, vals.into_iter().collect());
    }

    let mut v6_plens_set = BTreeSet::new();
    let mut v6 = HashMap::with_capacity(v6_sets.len());
    for (k, vals) in v6_sets {
        v6_plens_set.insert(k.1);
        v6.insert(k, vals.into_iter().collect());
    }

    Ok(RpkiTable {
        v4,
        v6,
        v4_plens: v4_plens_set.into_iter().collect(),
        v6_plens: v6_plens_set.into_iter().collect(),
    })
}

/// Parse `bgp.tools/asns.csv` (`asn,name,class,cc`), returning `(asn_classes, fallback_orgs)`.
pub fn parse_asn_classes_csv(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
) -> DgipResult<(HashMap<u32, String>, HashMap<u32, String>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut classes: HashMap<u32, String> = HashMap::new();
    let mut fallback_orgs: HashMap<u32, String> = HashMap::new();

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());

    for (idx, rec_res) in rdr.records().enumerate() {
        let Ok(row) = rec_res else {
            continue;
        };
        if idx == 0
            && row
                .get(0)
                .map(|s| s.trim().eq_ignore_ascii_case("asn"))
                .unwrap_or(false)
        {
            continue;
        }
        if row.len() < 3 {
            continue;
        }
        let raw_asn = row[0].trim();
        let asn_digits =
            if raw_asn.len() >= 2 && raw_asn.as_bytes()[..2].eq_ignore_ascii_case(b"AS") {
                &raw_asn[2..]
            } else {
                raw_asn
            };
        let Ok(asn) = asn_digits.parse::<u32>() else {
            continue;
        };
        if asn == 0 {
            continue;
        }
        let cls_raw = row[2].trim();
        if !cls_raw.is_empty() {
            classes.insert(asn, cls_raw.to_string());
        }
        let org_name = clean_geo_text(&row[1], 512);
        if !org_name.is_empty() && org_name != "Unknown" {
            fallback_orgs.insert(asn, org_name);
        }
    }

    if classes.len() < min_records {
        return Err(DgipError::Compilation(format!(
            "ASN classification feed {feed_key:?} yielded {} ASNs, below minimum {min_records}.",
            classes.len()
        )));
    }

    Ok((classes, fallback_orgs))
}

fn is_known_cdn_asn(asn: u32) -> bool {
    matches!(
        asn,
        13335 | 20940 | 16625 | 54113 | 15133 | 22822 | 60068 | 19551 | 30148 | 202623
    )
}

fn is_known_hosting_asn(asn: u32) -> bool {
    matches!(
        asn,
        16509
            | 14618
            | 8075
            | 396982
            | 15169
            | 31898
            | 14061
            | 63949
            | 20473
            | 24940
            | 16276
            | 12876
            | 51167
            | 36352
            | 46606
            | 26496
            | 136907
            | 45102
            | 37963
            | 45090
            | 132203
            | 36459
    )
}

/// Classify an ASN into `cdn`, `hosting`, `isp`, `transit`, `content`, `education`, `government`, or `business`.
pub fn classify_asn_network_type(
    asn: u32,
    org: &str,
    asn_classes: &HashMap<u32, String>,
) -> String {
    if is_known_cdn_asn(asn) {
        return "cdn".to_string();
    }
    if is_known_hosting_asn(asn) {
        return "hosting".to_string();
    }

    let low_org = org.to_lowercase();
    if [
        "university",
        "universitaet",
        "universidad",
        "universite",
        "college",
        "academic",
        "research network",
        "school district",
        "edu.",
    ]
    .iter()
    .any(|kw| low_org.contains(kw))
    {
        return "education".to_string();
    }

    if [
        "ministry of",
        "department of",
        "government",
        "municipal",
        "armed forces",
        "parliament",
        "federal ",
    ]
    .iter()
    .any(|kw| low_org.contains(kw))
    {
        return "government".to_string();
    }

    if ["cdn", "cloudflare", "fastly", "akamai", "edgecast"]
        .iter()
        .any(|kw| low_org.contains(kw))
    {
        return "cdn".to_string();
    }

    if [
        "hosting",
        "datacenter",
        "data center",
        "cloud",
        "vps",
        "server",
        "colocation",
        "dedibox",
        "digitalocean",
        "hetzner",
        "ovh",
        "linode",
        "vultr",
        "contabo",
        "leaseweb",
        "choopa",
    ]
    .iter()
    .any(|kw| low_org.contains(kw))
    {
        return "hosting".to_string();
    }

    let bt = asn_classes
        .get(&asn)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if bt == "eyeball" {
        return "isp".to_string();
    }
    if matches!(bt.as_str(), "carrier" | "t1" | "transit") {
        return "transit".to_string();
    }
    if bt == "content" {
        return "content".to_string();
    }

    if [
        "telecom",
        "telekom",
        "telefonica",
        "broadband",
        "wireless",
        "mobile",
        "fiber",
        "fibre",
        "cable",
        "comcast",
        "charter",
        "verizon",
        "vodafone",
        "airtel",
        "jio",
    ]
    .iter()
    .any(|kw| low_org.contains(kw))
    {
        return "isp".to_string();
    }

    "business".to_string()
}

// ---------------------------------------------------------------------------
// Layer 4: CDN, Cloud, Tor Exit & Threat Parsers + Sweep-Line Merger
// ---------------------------------------------------------------------------

/// Parse newline-delimited IPv4/IPv6 CIDRs (such as Cloudflare `ips-v4` / `ips-v6`).
#[allow(clippy::too_many_arguments)]
pub fn parse_cidr_text_list(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    flags: u16,
    provider: &str,
    threat: &str,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<(Vec<RawSecurityIntervalV4>, Vec<RawSecurityIntervalV6>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for raw_line in text.lines() {
        let without_hash = raw_line.split('#').next().unwrap_or("");
        let line = without_hash.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some(parsed) = parse_cidr_bounds(line, v4_special, v6_special) else {
            continue;
        };
        accepted += 1;
        match parsed {
            ParsedCidrBounds::V4 { start, end, .. } => v4_raw.push((start, end)),
            ParsedCidrBounds::V6 { start, end, .. } => v6_raw.push((start, end)),
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "CIDR feed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    Ok((
        coalesce_same_security_ranges_v4(v4_raw, flags, provider, threat),
        coalesce_same_security_ranges_v6(v6_raw, flags, provider, threat),
    ))
}

/// Parse Fastly `public-ip-list` JSON (`{"addresses": [...], "ipv6_addresses": [...]}`).
pub fn parse_fastly_json(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<(Vec<RawSecurityIntervalV4>, Vec<RawSecurityIntervalV6>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let payload: Value = serde_json::from_slice(&decompressed).map_err(|e| {
        DgipError::Compilation(format!("Invalid JSON in Fastly feed {feed_key:?}: {e}"))
    })?;

    let mut v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for arr_key in ["addresses", "ipv6_addresses"] {
        let Some(items) = payload.get(arr_key).and_then(Value::as_array) else {
            continue;
        };
        for item in items {
            let Some(raw_cidr) = item.as_str() else {
                continue;
            };
            let Some(parsed) = parse_cidr_bounds(raw_cidr, v4_special, v6_special) else {
                continue;
            };
            accepted += 1;
            match parsed {
                ParsedCidrBounds::V4 { start, end, .. } => v4_raw.push((start, end)),
                ParsedCidrBounds::V6 { start, end, .. } => v6_raw.push((start, end)),
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "Fastly feed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    let flags = SEC_CDN | SEC_CLOUD;
    Ok((
        coalesce_same_security_ranges_v4(v4_raw, flags, "fastly", ""),
        coalesce_same_security_ranges_v6(v6_raw, flags, "fastly", ""),
    ))
}

/// Parse GitHub `api.github.com/meta` CIDR arrays (`web`, `api`, `git`, `hooks`, `actions`, `pages`, `packages`).
pub fn parse_github_meta_json(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<(Vec<RawSecurityIntervalV4>, Vec<RawSecurityIntervalV6>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let payload: Value = serde_json::from_slice(&decompressed).map_err(|e| {
        DgipError::Compilation(format!(
            "Invalid JSON in GitHub meta feed {feed_key:?}: {e}"
        ))
    })?;
    let obj = payload.as_object().ok_or_else(|| {
        DgipError::Compilation(format!(
            "GitHub meta feed {feed_key:?} did not return a JSON object."
        ))
    })?;

    let mut v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for (key, val) in obj {
        if matches!(
            key.as_str(),
            "verifiable_password_authentication" | "ssh_key_fingerprints" | "ssh_keys" | "domains"
        ) {
            continue;
        }
        let Some(arr) = val.as_array() else {
            continue;
        };
        for item in arr {
            let Some(s) = item.as_str() else {
                continue;
            };
            if !s.contains('/') {
                continue;
            }
            let Some(parsed) = parse_cidr_bounds(s, v4_special, v6_special) else {
                continue;
            };
            accepted += 1;
            match parsed {
                ParsedCidrBounds::V4 { start, end, .. } => v4_raw.push((start, end)),
                ParsedCidrBounds::V6 { start, end, .. } => v6_raw.push((start, end)),
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "GitHub meta feed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    let flags = SEC_CLOUD | SEC_DATACENTER;
    Ok((
        coalesce_same_security_ranges_v4(v4_raw, flags, "github", ""),
        coalesce_same_security_ranges_v6(v6_raw, flags, "github", ""),
    ))
}

/// Parse newline-delimited IPv4/IPv6 literals or CIDRs (Tor `torbulkexitlist`, Abuse.ch Feodo C2).
#[allow(clippy::too_many_arguments)]
pub fn parse_ip_literal_list(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    flags: u16,
    provider: &str,
    threat: &str,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<(Vec<RawSecurityIntervalV4>, Vec<RawSecurityIntervalV6>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for raw_line in text.lines() {
        let without_hash = raw_line.split('#').next().unwrap_or("");
        let line = without_hash.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.contains('/') {
            let Some(parsed) = parse_cidr_bounds(line, v4_special, v6_special) else {
                continue;
            };
            accepted += 1;
            match parsed {
                ParsedCidrBounds::V4 { start, end, .. } => v4_raw.push((start, end)),
                ParsedCidrBounds::V6 { start, end, .. } => v6_raw.push((start, end)),
            }
        } else {
            if line.contains('%') {
                continue;
            }
            let Ok(addr) = line.parse::<IpAddr>() else {
                continue;
            };
            match addr {
                IpAddr::V4(v4) => {
                    let ip_int = u32::from(v4);
                    if classify_special_v4(ip_int, v4_special).is_some() {
                        continue;
                    }
                    accepted += 1;
                    v4_raw.push((ip_int, ip_int));
                }
                IpAddr::V6(v6) => {
                    let ip_int = u128::from(v6);
                    if classify_special_v6(ip_int, v6_special).is_some() {
                        continue;
                    }
                    accepted += 1;
                    v6_raw.push((ip_int, ip_int));
                }
            }
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "IP feed {feed_key:?} yielded {accepted} entries, below minimum {min_records}."
        )));
    }

    Ok((
        coalesce_same_security_ranges_v4(v4_raw, flags, provider, threat),
        coalesce_same_security_ranges_v6(v6_raw, flags, provider, threat),
    ))
}

/// Parse Spamhaus DROP v4/v6 JSONL (`{"cidr": "1.10.16.0/20", "sblid": "SBL..."}`).
pub fn parse_spamhaus_drop_jsonl(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<(Vec<RawSecurityIntervalV4>, Vec<RawSecurityIntervalV6>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut v4_raw: Vec<(u32, u32)> = Vec::new();
    let mut v6_raw: Vec<(u128, u128)> = Vec::new();
    let mut accepted = 0usize;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(cidr_str) = obj
            .as_object()
            .and_then(|o| o.get("cidr"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(parsed) = parse_cidr_bounds(cidr_str, v4_special, v6_special) else {
            continue;
        };
        accepted += 1;
        match parsed {
            ParsedCidrBounds::V4 { start, end, .. } => v4_raw.push((start, end)),
            ParsedCidrBounds::V6 { start, end, .. } => v6_raw.push((start, end)),
        }
    }

    if accepted < min_records {
        return Err(DgipError::Compilation(format!(
            "Spamhaus DROP feed {feed_key:?} yielded {accepted} prefixes, below minimum {min_records}."
        )));
    }

    Ok((
        coalesce_same_security_ranges_v4(v4_raw, SEC_THREAT, "", "spamhaus_drop"),
        coalesce_same_security_ranges_v6(v6_raw, SEC_THREAT, "", "spamhaus_drop"),
    ))
}

/// Combine overlapping IPv4 security/cloud/threat intervals via an event-point sweep-line.
///
/// Uses `u64` exclusive upper bounds (`e as u64 + 1`) so intervals touching `u32::MAX` never overflow.
pub fn merge_security_intervals_v4(intervals: &[RawSecurityIntervalV4]) -> Vec<SecurityV4Row> {
    if intervals.is_empty() {
        return Vec::new();
    }

    let mut grouped: HashMap<(u16, String, String), Vec<(u32, u32)>> = HashMap::new();
    for iv in intervals {
        if iv.start > iv.end || iv.flags == 0 {
            continue;
        }
        grouped
            .entry((iv.flags, iv.provider.clone(), iv.threat_feed.clone()))
            .or_default()
            .push((iv.start, iv.end));
    }
    if grouped.is_empty() {
        return Vec::new();
    }

    // Store unique metadata labels in a compact vector to avoid cloning Strings inside the heap
    let mut meta_pool: Vec<(u16, String, String)> = Vec::with_capacity(grouped.len());
    let mut starts_at: HashMap<u64, Vec<(u64, usize)>> = HashMap::new();
    let mut coords_set: BTreeSet<u64> = BTreeSet::new();

    for ((flags, prov, threat), rngs) in grouped {
        let coalesced = coalesce_same_security_ranges_v4(rngs, flags, &prov, &threat);
        let meta_idx = meta_pool.len();
        meta_pool.push((flags, prov, threat));
        for c in coalesced {
            let s64 = u64::from(c.start);
            let end_excl = u64::from(c.end) + 1;
            coords_set.insert(s64);
            coords_set.insert(end_excl);
            starts_at.entry(s64).or_default().push((end_excl, meta_idx));
        }
    }

    let xs: Vec<u64> = coords_set.into_iter().collect();
    let mut active_heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
    let mut out: Vec<SecurityV4Row> = Vec::new();

    for win in xs.windows(2) {
        let x = win[0];
        let nxt = win[1];

        while let Some(&Reverse((end_excl, _))) = active_heap.peek() {
            if end_excl <= x {
                active_heap.pop();
            } else {
                break;
            }
        }

        if let Some(new_items) = starts_at.get(&x) {
            for &item in new_items {
                active_heap.push(Reverse(item));
            }
        }

        if active_heap.is_empty() {
            continue;
        }

        let mut comb_flags: u16 = 0;
        let mut best_prov = "";
        let mut best_prio = -1i32;
        let mut threats_set: BTreeSet<&str> = BTreeSet::new();

        for &Reverse((_, meta_idx)) in active_heap.iter() {
            let (f, ref p, ref t) = meta_pool[meta_idx];
            comb_flags |= f;
            if !p.is_empty() {
                let prio = provider_priority(p);
                if prio > best_prio || (prio == best_prio && p.as_str() < best_prov) {
                    best_prio = prio;
                    best_prov = p.as_str();
                }
            }
            if !t.is_empty() {
                for sub_t in t.split([',', '|']) {
                    if !sub_t.is_empty() {
                        threats_set.insert(sub_t);
                    }
                }
            }
        }

        let threats_str = if threats_set.is_empty() {
            String::new()
        } else {
            threats_set.into_iter().collect::<Vec<&str>>().join(",")
        };
        let seg_start = x as u32;
        let seg_end = (nxt - 1) as u32;

        if let Some(last) = out.last_mut() {
            if u64::from(last.end) + 1 == x
                && last.flags == comb_flags
                && last.provider == best_prov
                && last.threat_feeds == threats_str
            {
                last.end = seg_end;
                continue;
            }
        }
        out.push(SecurityV4Row {
            start: seg_start,
            end: seg_end,
            flags: comb_flags,
            provider: best_prov.to_string(),
            threat_feeds: threats_str,
        });
    }

    out
}

/// 129-bit coordinate `(overflow_bit, low_128)` representing `0 ..= u128::MAX + 1` in lexicographic order.
type Coord129 = (bool, u128);

/// Combine overlapping IPv6 security/cloud/threat intervals via an event-point sweep-line.
///
/// Uses 129-bit `(bool, u128)` coordinates so intervals touching `u128::MAX` never overflow.
pub fn merge_security_intervals_v6(intervals: &[RawSecurityIntervalV6]) -> Vec<SecurityV6Row> {
    if intervals.is_empty() {
        return Vec::new();
    }

    let mut grouped: HashMap<(u16, String, String), Vec<(u128, u128)>> = HashMap::new();
    for iv in intervals {
        if iv.start > iv.end || iv.flags == 0 {
            continue;
        }
        grouped
            .entry((iv.flags, iv.provider.clone(), iv.threat_feed.clone()))
            .or_default()
            .push((iv.start, iv.end));
    }
    if grouped.is_empty() {
        return Vec::new();
    }

    let mut meta_pool: Vec<(u16, String, String)> = Vec::with_capacity(grouped.len());
    let mut starts_at: HashMap<Coord129, Vec<(Coord129, usize)>> = HashMap::new();
    let mut coords_set: BTreeSet<Coord129> = BTreeSet::new();

    for ((flags, prov, threat), rngs) in grouped {
        let coalesced = coalesce_same_security_ranges_v6(rngs, flags, &prov, &threat);
        let meta_idx = meta_pool.len();
        meta_pool.push((flags, prov, threat));
        for c in coalesced {
            let s_coord: Coord129 = (false, c.start);
            let end_excl: Coord129 = if c.end == u128::MAX {
                (true, 0)
            } else {
                (false, c.end + 1)
            };
            coords_set.insert(s_coord);
            coords_set.insert(end_excl);
            starts_at
                .entry(s_coord)
                .or_default()
                .push((end_excl, meta_idx));
        }
    }

    let xs: Vec<Coord129> = coords_set.into_iter().collect();
    let mut active_heap: BinaryHeap<Reverse<(Coord129, usize)>> = BinaryHeap::new();
    let mut out: Vec<SecurityV6Row> = Vec::new();

    for win in xs.windows(2) {
        let x = win[0];
        let nxt = win[1];

        while let Some(&Reverse((end_excl, _))) = active_heap.peek() {
            if end_excl <= x {
                active_heap.pop();
            } else {
                break;
            }
        }

        if let Some(new_items) = starts_at.get(&x) {
            for &item in new_items {
                active_heap.push(Reverse(item));
            }
        }

        if active_heap.is_empty() {
            continue;
        }

        let mut comb_flags: u16 = 0;
        let mut best_prov = "";
        let mut best_prio = -1i32;
        let mut threats_set: BTreeSet<&str> = BTreeSet::new();

        for &Reverse((_, meta_idx)) in active_heap.iter() {
            let (f, ref p, ref t) = meta_pool[meta_idx];
            comb_flags |= f;
            if !p.is_empty() {
                let prio = provider_priority(p);
                if prio > best_prio || (prio == best_prio && p.as_str() < best_prov) {
                    best_prio = prio;
                    best_prov = p.as_str();
                }
            }
            if !t.is_empty() {
                for sub_t in t.split([',', '|']) {
                    if !sub_t.is_empty() {
                        threats_set.insert(sub_t);
                    }
                }
            }
        }

        let threats_str = if threats_set.is_empty() {
            String::new()
        } else {
            threats_set.into_iter().collect::<Vec<&str>>().join(",")
        };
        let seg_start = x.1;
        let seg_end = if nxt.0 { u128::MAX } else { nxt.1 - 1 };

        if let Some(last) = out.last_mut() {
            if last.end.checked_add(1) == Some(seg_start)
                && last.flags == comb_flags
                && last.provider == best_prov
                && last.threat_feeds == threats_str
            {
                last.end = seg_end;
                continue;
            }
        }
        out.push(SecurityV6Row {
            start: seg_start,
            end: seg_end,
            flags: comb_flags,
            provider: best_prov.to_string(),
            threat_feeds: threats_str,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_utils::FALLBACK_SPECIAL_RANGES;
    use crate::seed_data::DEFAULT_COUNTRIES;
    use std::net::Ipv4Addr;

    #[test]
    fn test_layers_2_3_4_parsers_rpki_and_security_sweep() {
        let allowed_cc: HashSet<String> = DEFAULT_COUNTRIES
            .iter()
            .map(|(cc, _, _)| (*cc).to_string())
            .collect();
        let (ref v4_sp, ref v6_sp) = *FALLBACK_SPECIAL_RANGES;

        let aws_geofeed = b"# AWS RFC 8805 Geofeed\n3.6.0.0/16,IN,IN-MH,Mumbai,\n2600:1f10::/35,US,US-VA,Ashburn,\n";
        let (gv4, gv6, sv4, _sv6) = parse_rfc8805_geofeed(
            "geo-aws",
            aws_geofeed,
            1024 * 1024,
            2,
            &allowed_cc,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        assert_eq!(gv4.len(), 1);
        assert_eq!(gv4[0].2, GeoAttr::new("IN", "IN-MH", "Mumbai", "geofeed"));
        assert_eq!(gv6.len(), 1);
        assert_eq!(gv6[0].2, GeoAttr::new("US", "US-VA", "Ashburn", "geofeed"));
        assert_eq!(sv4.len(), 1);
        assert_eq!(sv4[0].flags, SEC_CLOUD | SEC_DATACENTER);
        assert_eq!(sv4[0].provider, "aws");

        let gcp_json = br#"{"prefixes":[
            {"ipv4Prefix":"34.84.0.0/16","scope":"asia-northeast1"},
            {"ipv4Prefix":"34.120.0.0/16","scope":"global"},
            {"ipv6Prefix":"2600:1900:4000::/44","scope":"europe-west3"}
        ]}"#;
        let (gcp_gv4, gcp_gv6, gcp_sv4, _) = parse_gcp_cloud_json(
            "cloud-gcp",
            gcp_json,
            1024 * 1024,
            3,
            &allowed_cc,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        assert_eq!(gcp_gv4.len(), 1);
        assert_eq!(
            gcp_gv4[0].2,
            GeoAttr::new("JP", "JP-13", "Tokyo", "geofeed")
        );
        assert_eq!(gcp_gv6.len(), 1);
        assert_eq!(
            gcp_gv6[0].2,
            GeoAttr::new("DE", "DE-HE", "Frankfurt", "geofeed")
        );
        assert!(!gcp_sv4.is_empty());
        assert_eq!(gcp_sv4[0].provider, "gcp");

        let oci_json =
            br#"{"regions":[{"region":"ap-mumbai-1","cidrs":[{"cidr":"129.154.32.0/20"}]}]}"#;
        let (oci_gv4, _, oci_sv4, _) = parse_oracle_cloud_json(
            "cloud-oracle",
            oci_json,
            1024 * 1024,
            1,
            &allowed_cc,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        assert_eq!(oci_gv4.len(), 1);
        assert_eq!(
            oci_gv4[0].2,
            GeoAttr::new("IN", "IN-MH", "Mumbai", "geofeed")
        );
        assert_eq!(oci_sv4[0].provider, "oracle");

        // Overlay splitting ARIN US /8 cleanly around AWS Mumbai /16 + u32::MAX safety
        let s_3_0 = u32::from(Ipv4Addr::new(3, 0, 0, 0));
        let e_3_255 = u32::from(Ipv4Addr::new(3, 255, 255, 255));
        let overlaid = overlay_disjoint_intervals_v4(
            &[(s_3_0, e_3_255, GeoAttr::new("US", "", "", "rir"))],
            &gv4,
        );
        assert_eq!(overlaid.len(), 3);
        assert_eq!(overlaid[0].2.cc, "US");
        assert_eq!(
            overlaid[1].2,
            GeoAttr::new("IN", "IN-MH", "Mumbai", "geofeed")
        );
        assert_eq!(overlaid[2].2.cc, "US");

        // RPKI RFC 6811 + RFC 7607 AS0
        let vrps_csv = concat!(
            "ASN,IP Prefix,Max Length,Trust Anchor,Expires\n",
            "AS13335,1.1.1.0/24,24,apnic,1999999999\n",
            "AS15169,8.8.0.0/16,24,arin,1999999999\n",
            "AS0,203.0.114.0/24,24,apnic,1999999999\n",
        );
        let rpki_tbl = parse_rpki_vrps_csv(
            "rpki-vrps",
            vrps_csv.as_bytes(),
            1024 * 1024,
            3,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        assert_eq!(
            rpki_tbl.validate_v4(u32::from(Ipv4Addr::new(1, 1, 1, 0)), 24, 13335),
            "valid"
        );
        assert_eq!(
            rpki_tbl.validate_v4(u32::from(Ipv4Addr::new(1, 1, 1, 0)), 24, 64496),
            "invalid"
        );
        assert_eq!(
            rpki_tbl.validate_v4(u32::from(Ipv4Addr::new(8, 8, 8, 0)), 25, 15169),
            "invalid"
        );
        assert_eq!(
            rpki_tbl.validate_v4(u32::from(Ipv4Addr::new(203, 0, 114, 0)), 24, 174),
            "invalid"
        );
        assert_eq!(
            rpki_tbl.validate_v4(u32::from(Ipv4Addr::new(9, 9, 9, 0)), 24, 19281),
            "unknown"
        );

        // ASN classes + network_type heuristics
        let asns_csv = b"asn,name,class\nAS7922,Comcast Cable Communications,Eyeball\nAS174,Cogent Communications,Carrier\nAS13335,Cloudflare Inc,Content\n";
        let (cls_map, fb_orgs) =
            parse_asn_classes_csv("asn-classes", asns_csv, 1024 * 1024, 3).unwrap();
        assert_eq!(
            classify_asn_network_type(7922, &fb_orgs[&7922], &cls_map),
            "isp"
        );
        assert_eq!(
            classify_asn_network_type(174, &fb_orgs[&174], &cls_map),
            "transit"
        );
        assert_eq!(
            classify_asn_network_type(13335, &fb_orgs[&13335], &cls_map),
            "cdn"
        );
        assert_eq!(
            classify_asn_network_type(16509, "Amazon.com, Inc.", &cls_map),
            "hosting"
        );

        // Layer 4 sweep-line merge + max-bound guard
        let (gh_v4, _) = parse_github_meta_json(
            "cloud-github",
            br#"{"hooks":["192.30.252.0/22"],"actions":["3.6.10.0/24"]}"#,
            1024 * 1024,
            2,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        let (drop_v4, _) = parse_spamhaus_drop_jsonl(
            "spamhaus-drop",
            b"{\"cidr\":\"3.6.10.128/25\",\"sblid\":\"SBL123\"}\n{\"type\":\"metadata\"}\n",
            1024 * 1024,
            1,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        let (tor_v4, _) = parse_ip_literal_list(
            "tor-exit",
            b"# Tor Exit Node\n3.6.10.200\n",
            1024 * 1024,
            1,
            SEC_TOR_EXIT,
            "",
            "",
            v4_sp,
            v6_sp,
        )
        .unwrap();

        let mut all_sec = Vec::new();
        all_sec.extend(sv4);
        all_sec.extend(gh_v4);
        all_sec.extend(drop_v4);
        all_sec.extend(tor_v4);
        let merged = merge_security_intervals_v4(&all_sec);
        let target_ip = u32::from(Ipv4Addr::new(3, 6, 10, 200));
        let hit: Vec<&SecurityV4Row> = merged
            .iter()
            .filter(|r| r.start <= target_ip && target_ip <= r.end)
            .collect();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].provider, "github");
        assert_ne!(hit[0].flags & SEC_CLOUD, 0);
        assert_ne!(hit[0].flags & SEC_DATACENTER, 0);
        assert_ne!(hit[0].flags & SEC_TOR_EXIT, 0);
        assert_ne!(hit[0].flags & SEC_THREAT, 0);
        assert_eq!(hit[0].threat_feeds, "spamhaus_drop");

        // Verify u128::MAX boundary safety on v6 security merge
        let max_v6 = merge_security_intervals_v6(&[RawSecurityIntervalV6 {
            start: u128::MAX - 10,
            end: u128::MAX,
            flags: SEC_THREAT,
            provider: String::new(),
            threat_feed: "test_max".to_string(),
        }]);
        assert_eq!(max_v6.len(), 1);
        assert_eq!(max_v6[0].end, u128::MAX);
    }
}
