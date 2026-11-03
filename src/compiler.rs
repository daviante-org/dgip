//! Multi-layer compiler for authoritative RIRs, RIPE RIS BGP, Geofeeds, RPKI, and Threat Intelligence.

use crate::enrichment::{
    classify_asn_network_type, clean_geo_text, merge_security_intervals_v4,
    merge_security_intervals_v6, overlay_disjoint_intervals_v4, overlay_disjoint_intervals_v6,
    parse_asn_classes_csv, parse_cidr_text_list, parse_fastly_json, parse_gcp_cloud_json,
    parse_github_meta_json, parse_ip_literal_list, parse_ipv4_fast, parse_oracle_cloud_json,
    parse_rfc8805_geofeed, parse_rpki_vrps_csv, parse_spamhaus_drop_jsonl, GeoAttr,
    RawSecurityIntervalV4, RawSecurityIntervalV6, RpkiTable, SEC_CDN, SEC_CLOUD, SEC_DATACENTER,
    SEC_PRIVACY_RELAY, SEC_THREAT, SEC_TOR_EXIT,
};
use crate::ip_utils::{classify_special_v4, classify_special_v6};
use crate::mmdb::{build_dual_stack_mmdb, iter_range_cidrs_v4, iter_range_cidrs_v6, MmdbValue};
use crate::seed_data::is_valid_country_code;
use crate::types::{
    format_ipv4, format_ipv6, AsnV4Row, AsnV6Row, CountryV4Row, CountryV6Row, DgipError,
    DgipResult, FeedSourceSpec, SecurityV4Row, SecurityV6Row, SpecialRangeRuleV4,
    SpecialRangeRuleV6,
};
pub use crate::types::{
    BuiltArtifact, CompiledTables, PackagedSnapshot, ASN_IPV4_FILENAME, ASN_IPV6_FILENAME,
    ASN_MMDB_FILENAME, COUNTRY_IPV4_FILENAME, COUNTRY_IPV6_FILENAME, COUNTRY_MMDB_FILENAME,
    GEOFEED_FILENAME, SECURITY_IPV4_FILENAME, SECURITY_IPV6_FILENAME, SECURITY_MMDB_FILENAME,
};
use chrono::{DateTime, Utc};
use flate2::bufread::MultiGzDecoder;
use flate2::{Compression, GzBuilder};
use serde_json::{json, Map as JsonMap, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::Ipv6Addr;

pub const CORE_FEED_KINDS: &[&str] = &["rir_delegated", "ris_bgp", "asn_names"];

/// Unpacked and SHA-256-verified one-time bootstrap bundle (`bundle.tar.gz`).
#[derive(Debug, Clone)]
pub struct UnpackedBootstrap {
    pub version: String,
    pub release_title: String,
    pub released_at: DateTime<Utc>,
    pub previous_version: Option<String>,
    pub manifest: Value,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: String,
    pub sha256sums_bytes: Vec<u8>,
    pub sha256sums_sha256: String,
    pub bundle_sha256: String,
    pub source_attribution: String,
    pub dataset_artifacts: HashMap<String, BuiltArtifact>,
    pub tables: CompiledTables,
}

fn rpki_rank(status: &str) -> u8 {
    match status {
        "valid" => 2,
        "unknown" => 1,
        _ => 0,
    }
}

/// Compute lowercase hexadecimal SHA-256 digest of `data`.
pub fn sha256_bytes(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Decompress a gzip stream (if `0x1F 0x8B` magic header is present) in 64 KB chunks while
/// enforcing `max_uncompressed_bytes`. For uncompressed payloads, enforces `raw_bytes.len() <= max_uncompressed_bytes`.
pub fn decompress_bounded(raw_bytes: &[u8], max_uncompressed_bytes: usize) -> DgipResult<Vec<u8>> {
    if raw_bytes.len() >= 2 && raw_bytes[0] == 0x1F && raw_bytes[1] == 0x8B {
        let mut decoder = MultiGzDecoder::new(raw_bytes);
        let mut out = Vec::new();
        let mut chunk = [0u8; 65_536];
        let mut total = 0usize;

        loop {
            let n = decoder.read(&mut chunk).map_err(|e| {
                DgipError::Compilation(format!("Failed decompressing gzip payload: {e}"))
            })?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n);
            if total > max_uncompressed_bytes {
                return Err(DgipError::Compilation(format!(
                    "Decompressed payload exceeded limit of {max_uncompressed_bytes} bytes."
                )));
            }
            out.extend_from_slice(&chunk[..n]);
        }
        return Ok(out);
    }

    if raw_bytes.len() > max_uncompressed_bytes {
        return Err(DgipError::Compilation(format!(
            "Payload size {} exceeded limit of {max_uncompressed_bytes} bytes.",
            raw_bytes.len()
        )));
    }
    Ok(raw_bytes.to_vec())
}

/// Deterministically gzip-compress `data` with `mtime = 0` at compression `level`.
pub fn deterministic_gzip(data: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::new(level));
    encoder
        .write_all(data)
        .expect("in-memory gzip compression write cannot fail");
    encoder
        .finish()
        .expect("in-memory gzip compression finish cannot fail")
}

/// Validate that `asn` is a globally routable public Autonomous System Number, excluding
/// RFC 6996 / RFC 5398 / RFC 7300 private, documentation, and reserved ASNs.
pub fn is_public_asn(asn: u32, min_asn: u32, max_asn: u32) -> bool {
    if asn == 0 || asn < min_asn || asn > max_asn {
        return false;
    }
    if asn == 23_456 {
        return false;
    }
    if (64_496..=65_551).contains(&asn) {
        return false;
    }
    if asn >= 4_200_000_000 {
        return false;
    }
    true
}

fn sanitize_org(raw_org: &str) -> String {
    clean_geo_text(raw_org, 512)
}

/// Strip trailing `, <CC>` country suffix (e.g. `, US`).
fn strip_trailing_cc(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 3
        && bytes[bytes.len() - 2].is_ascii_uppercase()
        && bytes[bytes.len() - 1].is_ascii_uppercase()
    {
        let before_cc = s[..s.len() - 2].trim_end();
        if let Some(stripped) = before_cc.strip_suffix(',') {
            return stripped;
        }
    }
    s
}

/// Flatten IPv4 binary CIDRs `(net_int, prefix_len, value)` via Longest-Prefix Match,
/// subtract `special_rules`, and coalesce adjacent identical values safely at `u32::MAX`.
pub fn flatten_binary_cidrs_v4<V: Eq + Clone>(
    cidrs: &[(u32, u8, V)],
    special_rules: &[SpecialRangeRuleV4],
) -> Vec<(u32, u32, V)> {
    if cidrs.is_empty() {
        return Vec::new();
    }

    let mut items: Vec<(u32, u32, V)> = Vec::with_capacity(cidrs.len());
    for (raw_net, plen, val) in cidrs {
        if *plen > 32 {
            continue;
        }
        let (s, e) = if *plen == 0 {
            (0u32, u32::MAX)
        } else {
            let hb = 32 - *plen;
            let net = (*raw_net >> hb) << hb;
            (net, net | ((1u32 << hb) - 1))
        };
        items.push((s, e, val.clone()));
    }
    if items.is_empty() {
        return Vec::new();
    }

    items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));

    let mut lpm_out: Vec<(u32, u32, V)> = Vec::with_capacity(items.len());
    let mut emit_lpm = |s: u32, e: u32, val: V| {
        if s > e {
            return;
        }
        if let Some(last) = lpm_out.last_mut() {
            if last.1.checked_add(1) == Some(s) && last.2 == val {
                last.1 = e;
                return;
            }
        }
        lpm_out.push((s, e, val));
    };

    let mut stack: Vec<(u32, V)> = Vec::new();
    let mut cursor: Option<u32> = Some(0);

    for (s, e, val) in items {
        while let Some(&(p_end, _)) = stack.last() {
            if p_end < s {
                let (p_end, p_val) = stack.pop().unwrap();
                if let Some(cur) = cursor {
                    if cur <= p_end {
                        emit_lpm(cur, p_end, p_val);
                        cursor = p_end.checked_add(1);
                    }
                }
            } else {
                break;
            }
        }

        if let (Some((_, top_val)), Some(cur)) = (stack.last(), cursor) {
            if cur < s {
                emit_lpm(cur, s - 1, top_val.clone());
                cursor = Some(s);
            }
        }

        if let Some(last) = stack.last_mut() {
            if last.0 == e {
                last.1 = val;
                if let Some(cur) = cursor {
                    cursor = Some(cur.max(s));
                }
                continue;
            }
        }
        if let Some(cur) = cursor {
            cursor = Some(cur.max(s));
        }
        stack.push((e, val));
    }

    while let Some((p_end, p_val)) = stack.pop() {
        if let Some(cur) = cursor {
            if cur <= p_end {
                emit_lpm(cur, p_end, p_val);
                cursor = p_end.checked_add(1);
            }
        }
    }

    if special_rules.is_empty() || lpm_out.is_empty() {
        return lpm_out;
    }

    let mut raw_sp: Vec<(u32, u32)> = special_rules
        .iter()
        .filter(|r| r.start_int <= r.end_int)
        .map(|r| (r.start_int, r.end_int))
        .collect();
    if raw_sp.is_empty() {
        return lpm_out;
    }
    raw_sp.sort_unstable();
    let mut spec_merged: Vec<(u32, u32)> = Vec::with_capacity(raw_sp.len());
    let (mut sp_s, mut sp_e) = raw_sp[0];
    for &(s, e) in &raw_sp[1..] {
        if sp_e == u32::MAX || s <= sp_e + 1 {
            if e > sp_e {
                sp_e = e;
            }
        } else {
            spec_merged.push((sp_s, sp_e));
            sp_s = s;
            sp_e = e;
        }
    }
    spec_merged.push((sp_s, sp_e));

    let mut final_out: Vec<(u32, u32, V)> = Vec::with_capacity(lpm_out.len());
    let mut emit_final = |s: u32, e: u32, val: V| {
        if s > e {
            return;
        }
        if let Some(last) = final_out.last_mut() {
            if last.1.checked_add(1) == Some(s) && last.2 == val {
                last.1 = e;
                return;
            }
        }
        final_out.push((s, e, val));
    };

    let mut sp_idx = 0usize;
    for (s, e, val) in lpm_out {
        let mut cur_opt: Option<u32> = Some(s);
        while let Some(cur) = cur_opt {
            if cur > e {
                break;
            }
            while sp_idx < spec_merged.len() && spec_merged[sp_idx].1 < cur {
                sp_idx += 1;
            }
            if sp_idx >= spec_merged.len() || spec_merged[sp_idx].0 > e {
                emit_final(cur, e, val.clone());
                break;
            }
            let (hole_s, hole_e) = spec_merged[sp_idx];
            if cur < hole_s {
                emit_final(cur, hole_s - 1, val.clone());
            }
            cur_opt = hole_e.checked_add(1);
        }
    }

    final_out
}

/// Flatten IPv6 binary CIDRs `(net_int, prefix_len, value)` via Longest-Prefix Match,
/// subtract `special_rules`, and coalesce adjacent identical values safely at `u128::MAX`.
pub fn flatten_binary_cidrs_v6<V: Eq + Clone>(
    cidrs: &[(u128, u8, V)],
    special_rules: &[SpecialRangeRuleV6],
) -> Vec<(u128, u128, V)> {
    if cidrs.is_empty() {
        return Vec::new();
    }

    let mut items: Vec<(u128, u128, V)> = Vec::with_capacity(cidrs.len());
    for (raw_net, plen, val) in cidrs {
        if *plen > 128 {
            continue;
        }
        let (s, e) = if *plen == 0 {
            (0u128, u128::MAX)
        } else {
            let hb = 128 - *plen;
            let net = (*raw_net >> hb) << hb;
            (net, net | ((1u128 << hb) - 1))
        };
        items.push((s, e, val.clone()));
    }
    if items.is_empty() {
        return Vec::new();
    }

    items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));

    let mut lpm_out: Vec<(u128, u128, V)> = Vec::with_capacity(items.len());
    let mut emit_lpm = |s: u128, e: u128, val: V| {
        if s > e {
            return;
        }
        if let Some(last) = lpm_out.last_mut() {
            if last.1.checked_add(1) == Some(s) && last.2 == val {
                last.1 = e;
                return;
            }
        }
        lpm_out.push((s, e, val));
    };

    let mut stack: Vec<(u128, V)> = Vec::new();
    let mut cursor: Option<u128> = Some(0);

    for (s, e, val) in items {
        while let Some(&(p_end, _)) = stack.last() {
            if p_end < s {
                let (p_end, p_val) = stack.pop().unwrap();
                if let Some(cur) = cursor {
                    if cur <= p_end {
                        emit_lpm(cur, p_end, p_val);
                        cursor = p_end.checked_add(1);
                    }
                }
            } else {
                break;
            }
        }

        if let (Some((_, top_val)), Some(cur)) = (stack.last(), cursor) {
            if cur < s {
                emit_lpm(cur, s - 1, top_val.clone());
                cursor = Some(s);
            }
        }

        if let Some(last) = stack.last_mut() {
            if last.0 == e {
                last.1 = val;
                if let Some(cur) = cursor {
                    cursor = Some(cur.max(s));
                }
                continue;
            }
        }
        if let Some(cur) = cursor {
            cursor = Some(cur.max(s));
        }
        stack.push((e, val));
    }

    while let Some((p_end, p_val)) = stack.pop() {
        if let Some(cur) = cursor {
            if cur <= p_end {
                emit_lpm(cur, p_end, p_val);
                cursor = p_end.checked_add(1);
            }
        }
    }

    if special_rules.is_empty() || lpm_out.is_empty() {
        return lpm_out;
    }

    let mut raw_sp: Vec<(u128, u128)> = special_rules
        .iter()
        .filter(|r| r.start_int <= r.end_int)
        .map(|r| (r.start_int, r.end_int))
        .collect();
    if raw_sp.is_empty() {
        return lpm_out;
    }
    raw_sp.sort_unstable();
    let mut spec_merged: Vec<(u128, u128)> = Vec::with_capacity(raw_sp.len());
    let (mut sp_s, mut sp_e) = raw_sp[0];
    for &(s, e) in &raw_sp[1..] {
        if sp_e == u128::MAX || s <= sp_e + 1 {
            if e > sp_e {
                sp_e = e;
            }
        } else {
            spec_merged.push((sp_s, sp_e));
            sp_s = s;
            sp_e = e;
        }
    }
    spec_merged.push((sp_s, sp_e));

    let mut final_out: Vec<(u128, u128, V)> = Vec::with_capacity(lpm_out.len());
    let mut emit_final = |s: u128, e: u128, val: V| {
        if s > e {
            return;
        }
        if let Some(last) = final_out.last_mut() {
            if last.1.checked_add(1) == Some(s) && last.2 == val {
                last.1 = e;
                return;
            }
        }
        final_out.push((s, e, val));
    };

    let mut sp_idx = 0usize;
    for (s, e, val) in lpm_out {
        let mut cur_opt: Option<u128> = Some(s);
        while let Some(cur) = cur_opt {
            if cur > e {
                break;
            }
            while sp_idx < spec_merged.len() && spec_merged[sp_idx].1 < cur {
                sp_idx += 1;
            }
            if sp_idx >= spec_merged.len() || spec_merged[sp_idx].0 > e {
                emit_final(cur, e, val.clone());
                break;
            }
            let (hole_s, hole_e) = spec_merged[sp_idx];
            if cur < hole_s {
                emit_final(cur, hole_s - 1, val.clone());
            }
            cur_opt = hole_e.checked_add(1);
        }
    }

    final_out
}

/// Parse RIPE NCC `asn.txt` (`<asn> <HANDLE - Organization Name>, <CC>`).
pub fn parse_ripe_asnames(
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
) -> DgipResult<HashMap<u32, String>> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);
    let mut orgs: HashMap<u32, String> = HashMap::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let Some(asn_part) = it.next() else {
            continue;
        };
        let Some(rest_raw) = it.next() else {
            continue;
        };
        let rest = rest_raw.trim_start();
        if rest.is_empty() {
            continue;
        }
        let Ok(asn) = asn_part.parse::<u32>() else {
            continue;
        };
        let desc = strip_trailing_cc(rest).trim();
        let clean_org = if let Some((_handle, org_part)) = desc.split_once(" - ") {
            let primary = sanitize_org(org_part);
            if primary.is_empty() {
                sanitize_org(desc)
            } else {
                primary
            }
        } else {
            sanitize_org(desc)
        };
        if !clean_org.is_empty() && clean_org != "--" {
            orgs.insert(asn, clean_org);
        }
    }

    if orgs.len() < min_records {
        return Err(DgipError::Compilation(format!(
            "ASN names feed yielded {} entries, below minimum threshold {min_records}.",
            orgs.len()
        )));
    }

    Ok(orgs)
}

/// Parse an NRO Extended Delegation Statistics file (`delegated-*-extended-latest`)
/// into binary CIDR tuples `(net_int, prefix_len, country_code)` for IPv4 and IPv6.
#[allow(clippy::type_complexity)]
pub fn parse_rir_delegated_feed(
    feed_key: &str,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    allowed_countries: &HashSet<String>,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
) -> DgipResult<(Vec<(u32, u8, String)>, Vec<(u128, u8, String)>)> {
    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    let mut v4_cidrs: Vec<(u32, u8, String)> = Vec::new();
    let mut v6_cidrs: Vec<(u128, u8, String)> = Vec::new();
    let mut accepted_records = 0usize;

    for raw_line in text.lines() {
        if raw_line.is_empty() || raw_line.starts_with('#') || raw_line.starts_with('%') {
            continue;
        }
        let cols: Vec<&str> = raw_line.split('|').collect();
        if cols.len() < 7 {
            continue;
        }
        let status = cols[6].trim();
        if !status.eq_ignore_ascii_case("allocated") && !status.eq_ignore_ascii_case("assigned") {
            continue;
        }
        let rec_type = cols[2].trim();
        if rec_type.eq_ignore_ascii_case("asn") {
            accepted_records += 1;
            continue;
        }
        let cc = cols[1].trim().to_uppercase();
        if !is_valid_country_code(&cc, Some(allowed_countries)) {
            continue;
        }

        let raw_start = cols[3].trim();
        let raw_val = cols[4].trim();

        if rec_type.eq_ignore_ascii_case("ipv4") {
            let Some(s_int) = parse_ipv4_fast(raw_start) else {
                continue;
            };
            let Ok(host_count) = raw_val.parse::<u64>() else {
                continue;
            };
            if host_count == 0 {
                continue;
            }
            let e_int = (u64::from(s_int).saturating_add(host_count - 1)).min(0xFFFF_FFFF) as u32;
            if classify_special_v4(s_int, v4_special).is_some() {
                continue;
            }
            accepted_records += 1;
            for (net_int, plen) in iter_range_cidrs_v4(s_int, e_int) {
                v4_cidrs.push((net_int, plen, cc.clone()));
            }
        } else if rec_type.eq_ignore_ascii_case("ipv6") {
            if raw_start.contains('%') {
                continue;
            }
            let Ok(v6_addr) = raw_start.parse::<Ipv6Addr>() else {
                continue;
            };
            let Ok(plen) = raw_val.parse::<u8>() else {
                continue;
            };
            if !(1..=128).contains(&plen) {
                continue;
            }
            let s_int = u128::from(v6_addr);
            let mask_bits = 128 - plen;
            let net_int = (s_int >> mask_bits) << mask_bits;
            if classify_special_v6(net_int, v6_special).is_some() {
                continue;
            }
            accepted_records += 1;
            v6_cidrs.push((net_int, plen, cc));
        }
    }

    if accepted_records < min_records {
        return Err(DgipError::Compilation(format!(
            "RIR feed {feed_key:?} yielded {accepted_records} active delegations, below minimum threshold {min_records}."
        )));
    }

    Ok((v4_cidrs, v6_cidrs))
}

/// Parse RIPE NCC RIS `riswhoisdump.IPv4/IPv6.gz` (`origin_asn \t prefix \t peers`)
/// into deduplicated binary CIDR tuples `(net_int, prefix_len, asn, rpki_status)`.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn parse_ris_bgp_feed(
    feed_key: &str,
    ip_version: i16,
    raw_bytes: &[u8],
    max_uncompressed_bytes: usize,
    min_records: usize,
    min_peers: i32,
    min_prefixlen: u8,
    min_asn: u32,
    max_asn: u32,
    v4_special: &[SpecialRangeRuleV4],
    v6_special: &[SpecialRangeRuleV6],
    rpki_table: Option<&RpkiTable>,
    rpki_reject_invalid: bool,
) -> DgipResult<(Vec<(u32, u8, u32, String)>, Vec<(u128, u8, u32, String)>)> {
    if ip_version != 4 && ip_version != 6 {
        return Err(DgipError::Compilation(format!(
            "Unsupported BGP feed ip_version {ip_version} for {feed_key:?}."
        )));
    }

    let decompressed = decompress_bounded(raw_bytes, max_uncompressed_bytes)?;
    let text = String::from_utf8_lossy(&decompressed);

    if ip_version == 4 {
        let mut best_by_prefix: HashMap<(u32, u8), (u8, i32, u32, &'static str)> = HashMap::new();

        for raw_line in text.lines() {
            if raw_line.is_empty() || raw_line.starts_with('%') || raw_line.starts_with('#') {
                continue;
            }
            let (p0, p1, p2) = if let Some((a, rest)) = raw_line.split_once('\t') {
                if let Some((b, c)) = rest.split_once('\t') {
                    (a, b, c.split('\t').next().unwrap_or(c))
                } else {
                    let mut ws = raw_line.split_whitespace();
                    let (Some(a), Some(b), Some(c)) = (ws.next(), ws.next(), ws.next()) else {
                        continue;
                    };
                    (a, b, c)
                }
            } else {
                let mut ws = raw_line.split_whitespace();
                let (Some(a), Some(b), Some(c)) = (ws.next(), ws.next(), ws.next()) else {
                    continue;
                };
                (a, b, c)
            };

            let mut raw_asn = p0.trim();
            if raw_asn.starts_with('{') && raw_asn.ends_with('}') && raw_asn.len() >= 2 {
                raw_asn = raw_asn[1..raw_asn.len() - 1]
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim();
            }
            let Ok(asn) = raw_asn.parse::<u32>() else {
                continue;
            };
            let Ok(peers) = p2.trim().parse::<i32>() else {
                continue;
            };
            if peers < min_peers || !is_public_asn(asn, min_asn, max_asn) {
                continue;
            }

            let raw_prefix = p1.trim();
            let Some((addr_part, plen_str)) = raw_prefix.split_once('/') else {
                continue;
            };
            if addr_part.is_empty() {
                continue;
            }
            let Ok(plen) = plen_str.parse::<u8>() else {
                continue;
            };
            if plen < min_prefixlen || plen > 32 {
                continue;
            }
            let Some(ip_int) = parse_ipv4_fast(addr_part) else {
                continue;
            };
            let s_int = if plen == 0 {
                0
            } else {
                let hb = 32 - plen;
                (ip_int >> hb) << hb
            };
            if classify_special_v4(s_int, v4_special).is_some() {
                continue;
            }

            let rpki_st = rpki_table
                .map(|t| t.validate_v4(s_int, plen, asn))
                .unwrap_or("unknown");
            if rpki_st == "invalid" && rpki_reject_invalid {
                continue;
            }

            let rank = rpki_rank(rpki_st);
            let key = (s_int, plen);
            let replace = match best_by_prefix.get(&key) {
                None => true,
                Some(&(prev_rank, prev_peers, prev_asn, _)) => {
                    rank > prev_rank
                        || (rank == prev_rank && peers > prev_peers)
                        || (rank == prev_rank && peers == prev_peers && asn < prev_asn)
                }
            };
            if replace {
                best_by_prefix.insert(key, (rank, peers, asn, rpki_st));
            }
        }

        if best_by_prefix.len() < min_records {
            return Err(DgipError::Compilation(format!(
                "BGP feed {feed_key:?} yielded {} valid prefixes, below minimum threshold {min_records}.",
                best_by_prefix.len()
            )));
        }

        let out_v4 = best_by_prefix
            .into_iter()
            .map(|((s, plen), (_, _, asn, rpki_st))| (s, plen, asn, rpki_st.to_string()))
            .collect();
        Ok((out_v4, Vec::new()))
    } else {
        let mut best_by_prefix: HashMap<(u128, u8), (u8, i32, u32, &'static str)> = HashMap::new();

        for raw_line in text.lines() {
            if raw_line.is_empty() || raw_line.starts_with('%') || raw_line.starts_with('#') {
                continue;
            }
            let (p0, p1, p2) = if let Some((a, rest)) = raw_line.split_once('\t') {
                if let Some((b, c)) = rest.split_once('\t') {
                    (a, b, c.split('\t').next().unwrap_or(c))
                } else {
                    let mut ws = raw_line.split_whitespace();
                    let (Some(a), Some(b), Some(c)) = (ws.next(), ws.next(), ws.next()) else {
                        continue;
                    };
                    (a, b, c)
                }
            } else {
                let mut ws = raw_line.split_whitespace();
                let (Some(a), Some(b), Some(c)) = (ws.next(), ws.next(), ws.next()) else {
                    continue;
                };
                (a, b, c)
            };

            let mut raw_asn = p0.trim();
            if raw_asn.starts_with('{') && raw_asn.ends_with('}') && raw_asn.len() >= 2 {
                raw_asn = raw_asn[1..raw_asn.len() - 1]
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim();
            }
            let Ok(asn) = raw_asn.parse::<u32>() else {
                continue;
            };
            let Ok(peers) = p2.trim().parse::<i32>() else {
                continue;
            };
            if peers < min_peers || !is_public_asn(asn, min_asn, max_asn) {
                continue;
            }

            let raw_prefix = p1.trim();
            let Some((addr_part, plen_str)) = raw_prefix.split_once('/') else {
                continue;
            };
            if addr_part.is_empty() || addr_part.contains('%') {
                continue;
            }
            let Ok(plen) = plen_str.parse::<u8>() else {
                continue;
            };
            if plen < min_prefixlen || plen > 128 {
                continue;
            }
            let Ok(v6_addr) = addr_part.parse::<Ipv6Addr>() else {
                continue;
            };
            let ip_int = u128::from(v6_addr);
            let s_int = if plen == 0 {
                0
            } else {
                let hb = 128 - plen;
                (ip_int >> hb) << hb
            };
            if classify_special_v6(s_int, v6_special).is_some() {
                continue;
            }

            let rpki_st = rpki_table
                .map(|t| t.validate_v6(s_int, plen, asn))
                .unwrap_or("unknown");
            if rpki_st == "invalid" && rpki_reject_invalid {
                continue;
            }

            let rank = rpki_rank(rpki_st);
            let key = (s_int, plen);
            let replace = match best_by_prefix.get(&key) {
                None => true,
                Some(&(prev_rank, prev_peers, prev_asn, _)) => {
                    rank > prev_rank
                        || (rank == prev_rank && peers > prev_peers)
                        || (rank == prev_rank && peers == prev_peers && asn < prev_asn)
                }
            };
            if replace {
                best_by_prefix.insert(key, (rank, peers, asn, rpki_st));
            }
        }

        if best_by_prefix.len() < min_records {
            return Err(DgipError::Compilation(format!(
                "BGP feed {feed_key:?} yielded {} valid prefixes, below minimum threshold {min_records}.",
                best_by_prefix.len()
            )));
        }

        let out_v6 = best_by_prefix
            .into_iter()
            .map(|((s, plen), (_, _, asn, rpki_st))| (s, plen, asn, rpki_st.to_string()))
            .collect();
        Ok((Vec::new(), out_v6))
    }
}

/// Compute canonical SHA-256 digest across all 6 normalized interval tables.
pub fn hash_compiled_tables(
    asn_v4: &[AsnV4Row],
    asn_v6: &[AsnV6Row],
    cc_v4: &[CountryV4Row],
    cc_v6: &[CountryV6Row],
    sec_v4: &[SecurityV4Row],
    sec_v6: &[SecurityV6Row],
) -> String {
    let mut hasher = Sha256::new();
    let mut line = String::with_capacity(256);

    for r in asn_v4 {
        line.clear();
        let _ = writeln!(
            line,
            "a4:{}-{}:{}:{}:{}:{}",
            r.start, r.end, r.asn, r.org, r.network_type, r.rpki_status
        );
        hasher.update(line.as_bytes());
    }
    for r in asn_v6 {
        line.clear();
        let _ = writeln!(
            line,
            "a6:{}-{}:{}:{}:{}:{}",
            r.start, r.end, r.asn, r.org, r.network_type, r.rpki_status
        );
        hasher.update(line.as_bytes());
    }
    for r in cc_v4 {
        line.clear();
        let _ = writeln!(
            line,
            "c4:{}-{}:{}:{}:{}:{}",
            r.start, r.end, r.cc, r.region_code, r.city, r.geo_source
        );
        hasher.update(line.as_bytes());
    }
    for r in cc_v6 {
        line.clear();
        let _ = writeln!(
            line,
            "c6:{}-{}:{}:{}:{}:{}",
            r.start, r.end, r.cc, r.region_code, r.city, r.geo_source
        );
        hasher.update(line.as_bytes());
    }
    for r in sec_v4 {
        line.clear();
        let _ = writeln!(
            line,
            "s4:{}-{}:{}:{}:{}",
            r.start, r.end, r.flags, r.provider, r.threat_feeds
        );
        hasher.update(line.as_bytes());
    }
    for r in sec_v6 {
        line.clear();
        let _ = writeln!(
            line,
            "s6:{}-{}:{}:{}:{}",
            r.start, r.end, r.flags, r.provider, r.threat_feeds
        );
        hasher.update(line.as_bytes());
    }

    hex::encode(hasher.finalize())
}

/// Flatten, overlay, classify, coalesce, and hash all 6 IPv4/IPv6 ASN, Country & Security tables.
#[allow(clippy::too_many_arguments)]
pub fn compile_from_registry_inputs(
    rir_v4_cidrs: &[(u32, u8, String)],
    rir_v6_cidrs: &[(u128, u8, String)],
    bgp_v4_cidrs: &[(u32, u8, u32, String)],
    bgp_v6_cidrs: &[(u128, u8, u32, String)],
    asn_orgs: &HashMap<u32, String>,
    asn_classes: &HashMap<u32, String>,
    geofeed_v4_cidrs: &[(u32, u32, GeoAttr)],
    geofeed_v6_cidrs: &[(u128, u128, GeoAttr)],
    security_v4_raw: &[RawSecurityIntervalV4],
    security_v6_raw: &[RawSecurityIntervalV6],
    special_v4_rules: &[SpecialRangeRuleV4],
    special_v6_rules: &[SpecialRangeRuleV6],
) -> DgipResult<CompiledTables> {
    let rir_v4_geo: Vec<(u32, u8, GeoAttr)> = rir_v4_cidrs
        .iter()
        .map(|(net, plen, cc)| {
            (
                *net,
                *plen,
                GeoAttr::new(cc.clone(), String::new(), String::new(), "rir"),
            )
        })
        .collect();
    let rir_v6_geo: Vec<(u128, u8, GeoAttr)> = rir_v6_cidrs
        .iter()
        .map(|(net, plen, cc)| {
            (
                *net,
                *plen,
                GeoAttr::new(cc.clone(), String::new(), String::new(), "rir"),
            )
        })
        .collect();

    let base_cc_v4 = flatten_binary_cidrs_v4(&rir_v4_geo, special_v4_rules);
    let base_cc_v6 = flatten_binary_cidrs_v6(&rir_v6_geo, special_v6_rules);

    let mut geo_v4_expanded: Vec<(u32, u8, GeoAttr)> = Vec::with_capacity(geofeed_v4_cidrs.len());
    for (s, e, attr) in geofeed_v4_cidrs {
        for (net, plen) in iter_range_cidrs_v4(*s, *e) {
            geo_v4_expanded.push((net, plen, attr.clone()));
        }
    }
    let mut geo_v6_expanded: Vec<(u128, u8, GeoAttr)> = Vec::with_capacity(geofeed_v6_cidrs.len());
    for (s, e, attr) in geofeed_v6_cidrs {
        for (net, plen) in iter_range_cidrs_v6(*s, *e) {
            geo_v6_expanded.push((net, plen, attr.clone()));
        }
    }

    let override_v4 = flatten_binary_cidrs_v4(&geo_v4_expanded, special_v4_rules);
    let override_v6 = flatten_binary_cidrs_v6(&geo_v6_expanded, special_v6_rules);

    let final_cc_v4 = overlay_disjoint_intervals_v4(&base_cc_v4, &override_v4);
    let final_cc_v6 = overlay_disjoint_intervals_v6(&base_cc_v6, &override_v6);

    let mut asn_meta_cache: HashMap<u32, (String, String)> = HashMap::new();
    let mut lookup_asn_meta = |asn: u32| -> (String, String) {
        if let Some(cached) = asn_meta_cache.get(&asn) {
            return cached.clone();
        }
        let org = asn_orgs.get(&asn).cloned().unwrap_or_default();
        let ntype = classify_asn_network_type(asn, &org, asn_classes);
        let pair = (org, ntype);
        asn_meta_cache.insert(asn, pair.clone());
        pair
    };

    type BgpMeta = (u32, String, String, String);
    let mut bgp_v4_tagged: Vec<(u32, u8, BgpMeta)> = Vec::with_capacity(bgp_v4_cidrs.len());
    for (net, plen, asn, rpki_st) in bgp_v4_cidrs {
        let (org, ntype) = lookup_asn_meta(*asn);
        bgp_v4_tagged.push((*net, *plen, (*asn, org, ntype, rpki_st.clone())));
    }

    let mut bgp_v6_tagged: Vec<(u128, u8, BgpMeta)> = Vec::with_capacity(bgp_v6_cidrs.len());
    for (net, plen, asn, rpki_st) in bgp_v6_cidrs {
        let (org, ntype) = lookup_asn_meta(*asn);
        bgp_v6_tagged.push((*net, *plen, (*asn, org, ntype, rpki_st.clone())));
    }

    let flat_asn_v4 = flatten_binary_cidrs_v4(&bgp_v4_tagged, special_v4_rules);
    let flat_asn_v6 = flatten_binary_cidrs_v6(&bgp_v6_tagged, special_v6_rules);

    let security_v4 = merge_security_intervals_v4(security_v4_raw);
    let security_v6 = merge_security_intervals_v6(security_v6_raw);

    let asn_v4: Vec<AsnV4Row> = flat_asn_v4
        .into_iter()
        .map(
            |(start, end, (asn, org, network_type, rpki_status))| AsnV4Row {
                start,
                end,
                asn,
                org,
                network_type,
                rpki_status,
            },
        )
        .collect();

    let asn_v6: Vec<AsnV6Row> = flat_asn_v6
        .into_iter()
        .map(
            |(start, end, (asn, org, network_type, rpki_status))| AsnV6Row {
                start,
                end,
                asn,
                org,
                network_type,
                rpki_status,
            },
        )
        .collect();

    let country_v4: Vec<CountryV4Row> = final_cc_v4
        .into_iter()
        .map(|(start, end, g)| CountryV4Row {
            start,
            end,
            cc: g.cc,
            region_code: g.region_code,
            city: g.city,
            geo_source: g.geo_source,
        })
        .collect();

    let country_v6: Vec<CountryV6Row> = final_cc_v6
        .into_iter()
        .map(|(start, end, g)| CountryV6Row {
            start,
            end,
            cc: g.cc,
            region_code: g.region_code,
            city: g.city,
            geo_source: g.geo_source,
        })
        .collect();

    let normalized_sha256 = hash_compiled_tables(
        &asn_v4,
        &asn_v6,
        &country_v4,
        &country_v6,
        &security_v4,
        &security_v6,
    );

    Ok(CompiledTables {
        asn_v4,
        asn_v6,
        country_v4,
        country_v6,
        security_v4,
        security_v6,
        normalized_sha256,
    })
}

/// Parse all downloaded Layer 1–4 feed payloads and compile unified `CompiledTables`.
#[allow(clippy::too_many_arguments)]
pub fn compile_feed_payloads(
    downloaded: &[(FeedSourceSpec, Vec<u8>)],
    valid_country_codes: &HashSet<String>,
    special_v4_rules: &[SpecialRangeRuleV4],
    special_v6_rules: &[SpecialRangeRuleV6],
    bgp_min_peers: i32,
    bgp_ipv4_min_prefixlen: u8,
    bgp_ipv6_min_prefixlen: u8,
    asn_min_valid: u32,
    asn_max_valid: u32,
    rpki_reject_invalid: bool,
    enrichment_strict: bool,
) -> DgipResult<CompiledTables> {
    let mut rir_v4: Vec<(u32, u8, String)> = Vec::new();
    let mut rir_v6: Vec<(u128, u8, String)> = Vec::new();
    let mut geo_v4: Vec<(u32, u32, GeoAttr)> = Vec::new();
    let mut geo_v6: Vec<(u128, u128, GeoAttr)> = Vec::new();
    let mut sec_v4: Vec<RawSecurityIntervalV4> = Vec::new();
    let mut sec_v6: Vec<RawSecurityIntervalV6> = Vec::new();
    let mut asn_orgs: HashMap<u32, String> = HashMap::new();
    let mut asn_fallback_orgs: HashMap<u32, String> = HashMap::new();
    let mut asn_classes: HashMap<u32, String> = HashMap::new();
    let mut rpki_table: Option<RpkiTable> = None;
    let mut bgp_deferred: Vec<(&FeedSourceSpec, &[u8])> = Vec::new();

    // Pass 1: Parse RIRs, AS names, RPKI VRPs (needed before BGP), Layer 2 Geofeeds & Layer 4 Security
    for (spec, raw) in downloaded {
        let kind = spec.kind.as_str();
        if kind == "ris_bgp" {
            bgp_deferred.push((spec, raw.as_slice()));
            continue;
        }

        let max_uncomp = spec.max_uncompressed_bytes.max(0) as usize;
        let min_rec = spec.min_records.max(0) as usize;

        let parse_res: DgipResult<()> = (|| {
            match kind {
                "rir_delegated" => {
                    let (v4_c, v6_c) = parse_rir_delegated_feed(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        valid_country_codes,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    rir_v4.extend(v4_c);
                    rir_v6.extend(v6_c);
                }
                "asn_names" => {
                    let parsed_orgs = parse_ripe_asnames(raw, max_uncomp, min_rec)?;
                    asn_orgs.extend(parsed_orgs);
                }
                "rpki_vrps_csv" => {
                    let tbl = parse_rpki_vrps_csv(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    rpki_table = Some(tbl);
                }
                "asn_classes_csv" => {
                    let (cls_parsed, fb_orgs) =
                        parse_asn_classes_csv(&spec.feed_key, raw, max_uncomp, min_rec)?;
                    asn_classes.extend(cls_parsed);
                    asn_fallback_orgs.extend(fb_orgs);
                }
                "geofeed_rfc8805" => {
                    let (gv4, gv6, sv4, sv6) = parse_rfc8805_geofeed(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        valid_country_codes,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    geo_v4.extend(gv4);
                    geo_v6.extend(gv6);
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "cloud_gcp_json" => {
                    let (gv4, gv6, sv4, sv6) = parse_gcp_cloud_json(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        valid_country_codes,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    geo_v4.extend(gv4);
                    geo_v6.extend(gv6);
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "cloud_oracle_json" => {
                    let (gv4, gv6, sv4, sv6) = parse_oracle_cloud_json(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        valid_country_codes,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    geo_v4.extend(gv4);
                    geo_v6.extend(gv6);
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "cdn_cidr_list" => {
                    let prov = if spec.feed_key.contains("cloudflare") {
                        "cloudflare"
                    } else {
                        spec.feed_key.as_str()
                    };
                    let (sv4, sv6) = parse_cidr_text_list(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        SEC_CDN | SEC_CLOUD,
                        prov,
                        "",
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "cdn_fastly_json" => {
                    let (sv4, sv6) = parse_fastly_json(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "cloud_github_json" => {
                    let (sv4, sv6) = parse_github_meta_json(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "tor_exit_list" => {
                    let (sv4, sv6) = parse_ip_literal_list(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        SEC_TOR_EXIT,
                        "",
                        "",
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "spamhaus_drop_json" => {
                    let (sv4, sv6) = parse_spamhaus_drop_jsonl(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                "threat_ip_list" => {
                    let threat_id = if spec.feed_key.contains("feodo") {
                        "feodo_c2"
                    } else {
                        spec.feed_key.as_str()
                    };
                    let (sv4, sv6) = parse_ip_literal_list(
                        &spec.feed_key,
                        raw,
                        max_uncomp,
                        min_rec,
                        SEC_THREAT,
                        "",
                        threat_id,
                        special_v4_rules,
                        special_v6_rules,
                    )?;
                    sec_v4.extend(sv4);
                    sec_v6.extend(sv6);
                }
                _ => {}
            }
            Ok(())
        })();

        if let Err(err) = parse_res {
            if CORE_FEED_KINDS.contains(&kind) || enrichment_strict {
                return Err(err);
            }
            tracing::warn!(
                "Skipping degraded enrichment feed {} ({}): {}",
                spec.feed_key,
                kind,
                err
            );
        }
    }

    for (asn_num, fb_name) in asn_fallback_orgs {
        asn_orgs.entry(asn_num).or_insert(fb_name);
    }

    // Pass 2: Parse RIPE RIS BGP feeds against validated RPKI VRPs
    let mut bgp_v4: Vec<(u32, u8, u32, String)> = Vec::new();
    let mut bgp_v6: Vec<(u128, u8, u32, String)> = Vec::new();

    for (spec, raw) in bgp_deferred {
        let min_plen = if spec.ip_version == 4 {
            bgp_ipv4_min_prefixlen
        } else {
            bgp_ipv6_min_prefixlen
        };
        let (v4_b, v6_b) = parse_ris_bgp_feed(
            &spec.feed_key,
            spec.ip_version,
            raw,
            spec.max_uncompressed_bytes.max(0) as usize,
            spec.min_records.max(0) as usize,
            bgp_min_peers,
            min_plen,
            asn_min_valid,
            asn_max_valid,
            special_v4_rules,
            special_v6_rules,
            rpki_table.as_ref(),
            rpki_reject_invalid,
        )?;
        bgp_v4.extend(v4_b);
        bgp_v6.extend(v6_b);
    }

    compile_from_registry_inputs(
        &rir_v4,
        &rir_v6,
        &bgp_v4,
        &bgp_v6,
        &asn_orgs,
        &asn_classes,
        &geo_v4,
        &geo_v6,
        &sec_v4,
        &sec_v6,
        special_v4_rules,
        special_v6_rules,
    )
}

fn format_released_iso(dt: DateTime<Utc>) -> String {
    let subsec_micros = dt.timestamp_subsec_micros();
    if subsec_micros == 0 {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S.%6fZ").to_string()
    }
}

fn encode_asn_csv_gz_v4(rows: &[AsnV4Row]) -> DgipResult<Vec<u8>> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(Vec::with_capacity(rows.len() * 48));
    for r in rows {
        let s_ip = format_ipv4(r.start);
        let e_ip = format_ipv4(r.end);
        let asn_str = r.asn.to_string();
        wtr.write_record([
            s_ip.as_str(),
            e_ip.as_str(),
            asn_str.as_str(),
            r.org.as_str(),
            r.network_type.as_str(),
            r.rpki_status.as_str(),
        ])
        .map_err(|e| DgipError::Compilation(format!("CSV encode error: {e}")))?;
    }
    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("CSV flush error: {e}")))?;
    Ok(deterministic_gzip(&raw, 6))
}

fn encode_asn_csv_gz_v6(rows: &[AsnV6Row]) -> DgipResult<Vec<u8>> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(Vec::with_capacity(rows.len() * 64));
    for r in rows {
        let s_ip = format_ipv6(r.start);
        let e_ip = format_ipv6(r.end);
        let asn_str = r.asn.to_string();
        wtr.write_record([
            s_ip.as_str(),
            e_ip.as_str(),
            asn_str.as_str(),
            r.org.as_str(),
            r.network_type.as_str(),
            r.rpki_status.as_str(),
        ])
        .map_err(|e| DgipError::Compilation(format!("CSV encode error: {e}")))?;
    }
    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("CSV flush error: {e}")))?;
    Ok(deterministic_gzip(&raw, 6))
}

fn encode_country_csv_gz_v4(rows: &[CountryV4Row]) -> DgipResult<Vec<u8>> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(Vec::with_capacity(rows.len() * 40));
    for r in rows {
        let s_ip = format_ipv4(r.start);
        let e_ip = format_ipv4(r.end);
        wtr.write_record([
            s_ip.as_str(),
            e_ip.as_str(),
            r.cc.as_str(),
            r.region_code.as_str(),
            r.city.as_str(),
            r.geo_source.as_str(),
        ])
        .map_err(|e| DgipError::Compilation(format!("CSV encode error: {e}")))?;
    }
    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("CSV flush error: {e}")))?;
    Ok(deterministic_gzip(&raw, 6))
}

fn encode_country_csv_gz_v6(rows: &[CountryV6Row]) -> DgipResult<Vec<u8>> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(Vec::with_capacity(rows.len() * 56));
    for r in rows {
        let s_ip = format_ipv6(r.start);
        let e_ip = format_ipv6(r.end);
        wtr.write_record([
            s_ip.as_str(),
            e_ip.as_str(),
            r.cc.as_str(),
            r.region_code.as_str(),
            r.city.as_str(),
            r.geo_source.as_str(),
        ])
        .map_err(|e| DgipError::Compilation(format!("CSV encode error: {e}")))?;
    }
    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("CSV flush error: {e}")))?;
    Ok(deterministic_gzip(&raw, 6))
}

fn flag_bit_str(flags: u16, mask: u16) -> &'static str {
    if (flags & mask) != 0 {
        "1"
    } else {
        "0"
    }
}

fn encode_security_csv_gz_v4(rows: &[SecurityV4Row]) -> DgipResult<Vec<u8>> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(Vec::with_capacity(rows.len() * 48));
    for r in rows {
        let s_ip = format_ipv4(r.start);
        let e_ip = format_ipv4(r.end);
        wtr.write_record([
            s_ip.as_str(),
            e_ip.as_str(),
            flag_bit_str(r.flags, SEC_CLOUD),
            flag_bit_str(r.flags, SEC_DATACENTER),
            flag_bit_str(r.flags, SEC_CDN),
            flag_bit_str(r.flags, SEC_TOR_EXIT),
            flag_bit_str(r.flags, SEC_PRIVACY_RELAY),
            flag_bit_str(r.flags, SEC_THREAT),
            r.provider.as_str(),
            r.threat_feeds.as_str(),
        ])
        .map_err(|e| DgipError::Compilation(format!("CSV encode error: {e}")))?;
    }
    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("CSV flush error: {e}")))?;
    Ok(deterministic_gzip(&raw, 6))
}

fn encode_security_csv_gz_v6(rows: &[SecurityV6Row]) -> DgipResult<Vec<u8>> {
    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(Vec::with_capacity(rows.len() * 64));
    for r in rows {
        let s_ip = format_ipv6(r.start);
        let e_ip = format_ipv6(r.end);
        wtr.write_record([
            s_ip.as_str(),
            e_ip.as_str(),
            flag_bit_str(r.flags, SEC_CLOUD),
            flag_bit_str(r.flags, SEC_DATACENTER),
            flag_bit_str(r.flags, SEC_CDN),
            flag_bit_str(r.flags, SEC_TOR_EXIT),
            flag_bit_str(r.flags, SEC_PRIVACY_RELAY),
            flag_bit_str(r.flags, SEC_THREAT),
            r.provider.as_str(),
            r.threat_feeds.as_str(),
        ])
        .map_err(|e| DgipError::Compilation(format!("CSV encode error: {e}")))?;
    }
    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("CSV flush error: {e}")))?;
    Ok(deterministic_gzip(&raw, 6))
}

fn encode_rfc8805_geofeed_gz(
    v4_rows: &[CountryV4Row],
    v6_rows: &[CountryV6Row],
) -> DgipResult<(Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity((v4_rows.len() + v6_rows.len()) * 36 + 80);
    buf.extend_from_slice(
        b"# DGIP Geofeed (RFC 8805) - https://github.com/daviante-org/dgip-data\n",
    );

    let mut wtr = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary)
        .from_writer(buf);

    let mut prefix_count = 0usize;
    for r in v4_rows {
        for (net_int, plen) in iter_range_cidrs_v4(r.start, r.end) {
            let cidr = format!("{}/{}", format_ipv4(net_int), plen);
            wtr.write_record([
                cidr.as_str(),
                r.cc.as_str(),
                r.region_code.as_str(),
                r.city.as_str(),
                "",
            ])
            .map_err(|e| DgipError::Compilation(format!("Geofeed CSV encode error: {e}")))?;
            prefix_count += 1;
        }
    }
    for r in v6_rows {
        for (net_int, plen) in iter_range_cidrs_v6(r.start, r.end) {
            let cidr = format!("{}/{}", format_ipv6(net_int), plen);
            wtr.write_record([
                cidr.as_str(),
                r.cc.as_str(),
                r.region_code.as_str(),
                r.city.as_str(),
                "",
            ])
            .map_err(|e| DgipError::Compilation(format!("Geofeed CSV encode error: {e}")))?;
            prefix_count += 1;
        }
    }

    let raw = wtr
        .into_inner()
        .map_err(|e| DgipError::Compilation(format!("Geofeed CSV flush error: {e}")))?;
    Ok((deterministic_gzip(&raw, 6), prefix_count))
}

fn build_asn_mmdb_record(asn: u32, org: &str, ntype: &str, rpki: &str) -> MmdbValue {
    let mut map = BTreeMap::new();
    map.insert(
        "autonomous_system_number".to_string(),
        MmdbValue::Uint32(asn),
    );
    if !org.is_empty() {
        map.insert(
            "autonomous_system_organization".to_string(),
            MmdbValue::Str(org.to_string()),
        );
    }
    map.insert(
        "network_type".to_string(),
        MmdbValue::Str(ntype.to_string()),
    );
    map.insert("rpki_status".to_string(), MmdbValue::Str(rpki.to_string()));
    MmdbValue::Map(map)
}

fn build_country_mmdb_record(
    cc: &str,
    reg: &str,
    city: &str,
    gsrc: &str,
    country_details: &HashMap<String, (String, String, String)>,
) -> MmdbValue {
    let mut map = BTreeMap::new();

    if let Some((c_name, cont_code, cont_name)) = country_details.get(cc) {
        let mut cont_names = BTreeMap::new();
        cont_names.insert("en".to_string(), MmdbValue::Str(cont_name.clone()));
        let mut cont_map = BTreeMap::new();
        cont_map.insert("code".to_string(), MmdbValue::Str(cont_code.clone()));
        cont_map.insert("names".to_string(), MmdbValue::Map(cont_names));
        map.insert("continent".to_string(), MmdbValue::Map(cont_map));

        let mut c_names = BTreeMap::new();
        c_names.insert("en".to_string(), MmdbValue::Str(c_name.clone()));
        let mut c_map = BTreeMap::new();
        c_map.insert("iso_code".to_string(), MmdbValue::Str(cc.to_string()));
        c_map.insert("names".to_string(), MmdbValue::Map(c_names));
        map.insert("country".to_string(), MmdbValue::Map(c_map));
    } else {
        let mut c_names = BTreeMap::new();
        c_names.insert("en".to_string(), MmdbValue::Str(cc.to_string()));
        let mut c_map = BTreeMap::new();
        c_map.insert("iso_code".to_string(), MmdbValue::Str(cc.to_string()));
        c_map.insert("names".to_string(), MmdbValue::Map(c_names));
        map.insert("country".to_string(), MmdbValue::Map(c_map));
    }

    let mut traits_map = BTreeMap::new();
    traits_map.insert("geo_source".to_string(), MmdbValue::Str(gsrc.to_string()));
    if !reg.is_empty() {
        let sub_iso = reg.split_once('-').map(|(_, rhs)| rhs).unwrap_or(reg);
        let mut sub_map = BTreeMap::new();
        sub_map.insert("iso_code".to_string(), MmdbValue::Str(sub_iso.to_string()));
        map.insert(
            "subdivisions".to_string(),
            MmdbValue::Array(vec![MmdbValue::Map(sub_map)]),
        );
        traits_map.insert("region_code".to_string(), MmdbValue::Str(reg.to_string()));
    }
    map.insert("traits".to_string(), MmdbValue::Map(traits_map));

    if !city.is_empty() {
        let mut city_names = BTreeMap::new();
        city_names.insert("en".to_string(), MmdbValue::Str(city.to_string()));
        let mut city_map = BTreeMap::new();
        city_map.insert("names".to_string(), MmdbValue::Map(city_names));
        map.insert("city".to_string(), MmdbValue::Map(city_map));
    }

    MmdbValue::Map(map)
}

fn build_security_mmdb_record(flags: u16, prov: &str, threats: &str) -> MmdbValue {
    let mut map = BTreeMap::new();
    map.insert(
        "is_cdn".to_string(),
        MmdbValue::Bool((flags & SEC_CDN) != 0),
    );
    map.insert(
        "is_cloud".to_string(),
        MmdbValue::Bool((flags & SEC_CLOUD) != 0),
    );
    map.insert(
        "is_datacenter".to_string(),
        MmdbValue::Bool((flags & SEC_DATACENTER) != 0),
    );
    map.insert(
        "is_privacy_relay".to_string(),
        MmdbValue::Bool((flags & SEC_PRIVACY_RELAY) != 0),
    );
    map.insert(
        "is_threat".to_string(),
        MmdbValue::Bool((flags & SEC_THREAT) != 0),
    );
    map.insert(
        "is_tor_exit".to_string(),
        MmdbValue::Bool((flags & SEC_TOR_EXIT) != 0),
    );
    if !prov.is_empty() {
        map.insert("provider".to_string(), MmdbValue::Str(prov.to_string()));
    }
    let threat_arr = if threats.is_empty() {
        Vec::new()
    } else {
        threats
            .split([',', '|'])
            .filter(|t| !t.is_empty())
            .map(|t| MmdbValue::Str(t.to_string()))
            .collect()
    };
    map.insert("threat_feeds".to_string(), MmdbValue::Array(threat_arr));
    MmdbValue::Map(map)
}

/// Build all 10 global-standard dataset artifacts (`6x .csv.gz`, `dgip-geofeed.csv.gz`,
/// `dgip-asn.mmdb`, `dgip-country.mmdb`, `dgip-security.mmdb`), `manifest.json`,
/// `bundle.tar.gz`, and `SHA256SUMS.txt`.
pub fn package_standard_snapshot(
    tables: &CompiledTables,
    version: &str,
    release_title: &str,
    released_dt: DateTime<Utc>,
    previous_version: Option<&str>,
    source_attribution: &str,
    country_details: &HashMap<String, (String, String, String)>,
) -> DgipResult<PackagedSnapshot> {
    let released_iso = format_released_iso(released_dt);
    let build_epoch = released_dt.timestamp().max(0) as u64;

    let asn_v4_gz = encode_asn_csv_gz_v4(&tables.asn_v4)?;
    let asn_v6_gz = encode_asn_csv_gz_v6(&tables.asn_v6)?;
    let cc_v4_gz = encode_country_csv_gz_v4(&tables.country_v4)?;
    let cc_v6_gz = encode_country_csv_gz_v6(&tables.country_v6)?;
    let sec_v4_gz = encode_security_csv_gz_v4(&tables.security_v4)?;
    let sec_v6_gz = encode_security_csv_gz_v6(&tables.security_v6)?;
    let (geofeed_gz, geofeed_prefixes) =
        encode_rfc8805_geofeed_gz(&tables.country_v4, &tables.country_v6)?;

    // 1. Build dgip-asn.mmdb using compact u32 record IDs in insertion order
    let mut asn_key_ids: HashMap<(u32, &str, &str, &str), u32> = HashMap::new();
    let mut asn_ordered_records: Vec<(u32, MmdbValue)> = Vec::new();
    let mut asn_v4_mmdb_in: Vec<(u32, u32, u32)> = Vec::with_capacity(tables.asn_v4.len());
    let mut asn_v6_mmdb_in: Vec<(u128, u128, u32)> = Vec::with_capacity(tables.asn_v6.len());

    for r in &tables.asn_v4 {
        let k = (
            r.asn,
            r.org.as_str(),
            r.network_type.as_str(),
            r.rpki_status.as_str(),
        );
        let id = if let Some(&existing) = asn_key_ids.get(&k) {
            existing
        } else {
            let new_id = asn_ordered_records.len() as u32;
            asn_key_ids.insert(k, new_id);
            asn_ordered_records.push((
                new_id,
                build_asn_mmdb_record(r.asn, &r.org, &r.network_type, &r.rpki_status),
            ));
            new_id
        };
        asn_v4_mmdb_in.push((r.start, r.end, id));
    }
    for r in &tables.asn_v6 {
        let k = (
            r.asn,
            r.org.as_str(),
            r.network_type.as_str(),
            r.rpki_status.as_str(),
        );
        let id = if let Some(&existing) = asn_key_ids.get(&k) {
            existing
        } else {
            let new_id = asn_ordered_records.len() as u32;
            asn_key_ids.insert(k, new_id);
            asn_ordered_records.push((
                new_id,
                build_asn_mmdb_record(r.asn, &r.org, &r.network_type, &r.rpki_status),
            ));
            new_id
        };
        asn_v6_mmdb_in.push((r.start, r.end, id));
    }

    let asn_mmdb_bytes = build_dual_stack_mmdb(
        "GeoLite2-ASN",
        &format!(
            "DGIP Autonomous System Database {version} (https://github.com/daviante-org/dgip-data)"
        ),
        &asn_v4_mmdb_in,
        &asn_v6_mmdb_in,
        &asn_ordered_records,
        Some(build_epoch),
        None,
    );

    // 2. Build dgip-country.mmdb
    let mut cc_key_ids: HashMap<(&str, &str, &str, &str), u32> = HashMap::new();
    let mut cc_ordered_records: Vec<(u32, MmdbValue)> = Vec::new();
    let mut cc_v4_mmdb_in: Vec<(u32, u32, u32)> = Vec::with_capacity(tables.country_v4.len());
    let mut cc_v6_mmdb_in: Vec<(u128, u128, u32)> = Vec::with_capacity(tables.country_v6.len());

    for r in &tables.country_v4 {
        let k = (
            r.cc.as_str(),
            r.region_code.as_str(),
            r.city.as_str(),
            r.geo_source.as_str(),
        );
        let id = if let Some(&existing) = cc_key_ids.get(&k) {
            existing
        } else {
            let new_id = cc_ordered_records.len() as u32;
            cc_key_ids.insert(k, new_id);
            cc_ordered_records.push((
                new_id,
                build_country_mmdb_record(
                    &r.cc,
                    &r.region_code,
                    &r.city,
                    &r.geo_source,
                    country_details,
                ),
            ));
            new_id
        };
        cc_v4_mmdb_in.push((r.start, r.end, id));
    }
    for r in &tables.country_v6 {
        let k = (
            r.cc.as_str(),
            r.region_code.as_str(),
            r.city.as_str(),
            r.geo_source.as_str(),
        );
        let id = if let Some(&existing) = cc_key_ids.get(&k) {
            existing
        } else {
            let new_id = cc_ordered_records.len() as u32;
            cc_key_ids.insert(k, new_id);
            cc_ordered_records.push((
                new_id,
                build_country_mmdb_record(
                    &r.cc,
                    &r.region_code,
                    &r.city,
                    &r.geo_source,
                    country_details,
                ),
            ));
            new_id
        };
        cc_v6_mmdb_in.push((r.start, r.end, id));
    }

    let country_mmdb_bytes = build_dual_stack_mmdb(
        "GeoLite2-Country",
        &format!(
            "DGIP Country & Regional Geolocation Database {version} (https://github.com/daviante-org/dgip-data)"
        ),
        &cc_v4_mmdb_in,
        &cc_v6_mmdb_in,
        &cc_ordered_records,
        Some(build_epoch),
        None,
    );

    // 3. Build dgip-security.mmdb
    let mut sec_key_ids: HashMap<(u16, &str, &str), u32> = HashMap::new();
    let mut sec_ordered_records: Vec<(u32, MmdbValue)> = Vec::new();
    let mut sec_v4_mmdb_in: Vec<(u32, u32, u32)> = Vec::with_capacity(tables.security_v4.len());
    let mut sec_v6_mmdb_in: Vec<(u128, u128, u32)> = Vec::with_capacity(tables.security_v6.len());

    for r in &tables.security_v4 {
        let k = (r.flags, r.provider.as_str(), r.threat_feeds.as_str());
        let id = if let Some(&existing) = sec_key_ids.get(&k) {
            existing
        } else {
            let new_id = sec_ordered_records.len() as u32;
            sec_key_ids.insert(k, new_id);
            sec_ordered_records.push((
                new_id,
                build_security_mmdb_record(r.flags, &r.provider, &r.threat_feeds),
            ));
            new_id
        };
        sec_v4_mmdb_in.push((r.start, r.end, id));
    }
    for r in &tables.security_v6 {
        let k = (r.flags, r.provider.as_str(), r.threat_feeds.as_str());
        let id = if let Some(&existing) = sec_key_ids.get(&k) {
            existing
        } else {
            let new_id = sec_ordered_records.len() as u32;
            sec_key_ids.insert(k, new_id);
            sec_ordered_records.push((
                new_id,
                build_security_mmdb_record(r.flags, &r.provider, &r.threat_feeds),
            ));
            new_id
        };
        sec_v6_mmdb_in.push((r.start, r.end, id));
    }

    let security_mmdb_bytes = build_dual_stack_mmdb(
        "DGIP-Security",
        &format!(
            "DGIP Cloud, CDN, Anonymizer & Threat Intelligence Database {version} (https://github.com/daviante-org/dgip-data)"
        ),
        &sec_v4_mmdb_in,
        &sec_v6_mmdb_in,
        &sec_ordered_records,
        Some(build_epoch),
        None,
    );

    let raw_items: Vec<(&str, &str, Vec<u8>, usize)> = vec![
        (
            ASN_IPV4_FILENAME,
            "application/gzip",
            asn_v4_gz,
            tables.asn_v4.len(),
        ),
        (
            ASN_IPV6_FILENAME,
            "application/gzip",
            asn_v6_gz,
            tables.asn_v6.len(),
        ),
        (
            COUNTRY_IPV4_FILENAME,
            "application/gzip",
            cc_v4_gz,
            tables.country_v4.len(),
        ),
        (
            COUNTRY_IPV6_FILENAME,
            "application/gzip",
            cc_v6_gz,
            tables.country_v6.len(),
        ),
        (
            SECURITY_IPV4_FILENAME,
            "application/gzip",
            sec_v4_gz,
            tables.security_v4.len(),
        ),
        (
            SECURITY_IPV6_FILENAME,
            "application/gzip",
            sec_v6_gz,
            tables.security_v6.len(),
        ),
        (
            GEOFEED_FILENAME,
            "application/gzip",
            geofeed_gz,
            geofeed_prefixes,
        ),
        (
            ASN_MMDB_FILENAME,
            "application/octet-stream",
            asn_mmdb_bytes,
            tables.asn_v4.len() + tables.asn_v6.len(),
        ),
        (
            COUNTRY_MMDB_FILENAME,
            "application/octet-stream",
            country_mmdb_bytes,
            tables.country_v4.len() + tables.country_v6.len(),
        ),
        (
            SECURITY_MMDB_FILENAME,
            "application/octet-stream",
            security_mmdb_bytes,
            tables.security_v4.len() + tables.security_v6.len(),
        ),
    ];

    let mut dataset_artifacts: HashMap<String, BuiltArtifact> =
        HashMap::with_capacity(raw_items.len());
    for (fname, ctype, payload, rec_cnt) in raw_items {
        let sha256 = sha256_bytes(&payload);
        dataset_artifacts.insert(
            fname.to_string(),
            BuiltArtifact {
                filename: fname.to_string(),
                content_type: ctype.to_string(),
                payload,
                sha256,
                record_count: Some(rec_cnt),
            },
        );
    }

    // Build manifest.json with deterministic sorted keys
    let mut sorted_fnames: Vec<&String> = dataset_artifacts.keys().collect();
    sorted_fnames.sort();

    let mut files_json = JsonMap::with_capacity(sorted_fnames.len());
    for fname in &sorted_fnames {
        let art = &dataset_artifacts[*fname];
        let mut f_obj = JsonMap::with_capacity(3);
        f_obj.insert("record_count".to_string(), json!(art.record_count));
        f_obj.insert("sha256".to_string(), json!(art.sha256));
        f_obj.insert("size_bytes".to_string(), json!(art.payload.len()));
        files_json.insert((*fname).clone(), Value::Object(f_obj));
    }

    let mut manifest_obj = JsonMap::with_capacity(8);
    manifest_obj.insert("files".to_string(), Value::Object(files_json));
    manifest_obj.insert(
        "normalized_sha256".to_string(),
        json!(tables.normalized_sha256),
    );
    manifest_obj.insert("previous_version".to_string(), json!(previous_version));
    manifest_obj.insert("release_title".to_string(), json!(release_title));
    manifest_obj.insert("released_at".to_string(), json!(released_iso));
    manifest_obj.insert("schema_version".to_string(), json!(1));
    manifest_obj.insert("source_attribution".to_string(), json!(source_attribution));
    manifest_obj.insert("version".to_string(), json!(version));

    let manifest = Value::Object(manifest_obj);
    let mut manifest_str = serde_json::to_string_pretty(&manifest)
        .map_err(|e| DgipError::Compilation(format!("Manifest JSON encode error: {e}")))?;
    manifest_str.push('\n');
    let manifest_bytes = manifest_str.into_bytes();
    let manifest_sha256 = sha256_bytes(&manifest_bytes);

    // Deterministic bundle.tar.gz (mtime=0, uid=0, gid=0, mode=0o644)
    let mut tar_raw = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_raw);
        let mut members: Vec<(&str, &[u8])> = Vec::with_capacity(1 + sorted_fnames.len());
        members.push(("manifest.json", &manifest_bytes));
        for fname in &sorted_fnames {
            members.push((fname.as_str(), &dataset_artifacts[*fname].payload));
        }

        for (arcname, payload) in members {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(payload.len() as u64);
            header.set_mtime(0);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            let _ = header.set_username("dgip");
            let _ = header.set_groupname("dgip");
            header.set_cksum();
            builder
                .append_data(&mut header, arcname, payload)
                .map_err(|e| DgipError::Compilation(format!("Tar archive write error: {e}")))?;
        }
        builder
            .finish()
            .map_err(|e| DgipError::Compilation(format!("Tar archive finish error: {e}")))?;
    }
    let bundle_bytes = deterministic_gzip(&tar_raw, 6);
    let bundle_sha256 = sha256_bytes(&bundle_bytes);

    let sha256sums_bytes =
        build_sha256sums_bytes(&bundle_sha256, &manifest_sha256, &dataset_artifacts);
    let sha256sums_sha256 = sha256_bytes(&sha256sums_bytes);

    Ok(PackagedSnapshot {
        version: version.to_string(),
        release_title: release_title.to_string(),
        released_iso,
        manifest,
        manifest_bytes,
        manifest_sha256,
        bundle_bytes,
        bundle_sha256,
        sha256sums_bytes,
        sha256sums_sha256,
        dataset_artifacts,
    })
}

fn build_sha256sums_bytes(
    bundle_sha: &str,
    manifest_sha: &str,
    artifacts: &HashMap<String, BuiltArtifact>,
) -> Vec<u8> {
    let mut entries: Vec<(&str, &str)> = Vec::with_capacity(2 + artifacts.len());
    entries.push(("bundle.tar.gz", bundle_sha));
    entries.push(("manifest.json", manifest_sha));
    for (fname, art) in artifacts {
        entries.push((fname.as_str(), art.sha256.as_str()));
    }
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut out = String::new();
    for (fname, sha) in entries {
        let _ = writeln!(out, "{sha}  {fname}");
    }
    out.into_bytes()
}

/// Validate and unpack a `bundle.tar.gz` archive downloaded during one-time initial bootstrap,
/// strictly enforcing path safety, cumulative `max_archive_bytes` tarbomb limits across both
/// archive entries and decompressed CSV streams, and SHA-256 verification against `manifest.json`.
pub fn unpack_bootstrap_bundle(
    bundle_bytes: &[u8],
    max_archive_bytes: usize,
) -> DgipResult<UnpackedBootstrap> {
    if bundle_bytes.len() < 2 || bundle_bytes[0] != 0x1F || bundle_bytes[1] != 0x8B {
        return Err(DgipError::Compilation(
            "Invalid bootstrap tar.gz archive: missing gzip header.".to_string(),
        ));
    }

    // Bound outer tar stream to prevent header-only / sparse gzip bombs while keeping entry checks exact
    let outer_limit = max_archive_bytes.saturating_add(4 * 1024 * 1024);
    let gz_decoder = MultiGzDecoder::new(bundle_bytes).take((outer_limit as u64).saturating_add(1));
    let mut archive = tar::Archive::new(gz_decoder);

    let mut members_raw: HashMap<String, Vec<u8>> = HashMap::new();
    let mut total_bytes_used = 0usize;

    let entries = archive
        .entries()
        .map_err(|e| DgipError::Compilation(format!("Invalid bootstrap tar.gz archive: {e}")))?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| {
            DgipError::Compilation(format!("Invalid bootstrap tar.gz archive entry: {e}"))
        })?;
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() {
            continue;
        }

        let raw_path_bytes = entry.path_bytes();
        let member_name = std::str::from_utf8(&raw_path_bytes)
            .map_err(|_| DgipError::Compilation("Non-UTF-8 path in bootstrap bundle.".to_string()))?
            .to_string();

        if member_name.is_empty()
            || member_name.contains('/')
            || member_name.contains('\\')
            || member_name.contains("..")
            || member_name.contains('\0')
        {
            return Err(DgipError::Compilation(format!(
                "Unsafe archive path in bootstrap bundle: {member_name:?}"
            )));
        }

        let declared_size = entry.header().size().map_err(|e| {
            DgipError::Compilation(format!("Invalid tar header size for {member_name:?}: {e}"))
        })? as usize;

        if total_bytes_used.saturating_add(declared_size) > max_archive_bytes {
            return Err(DgipError::Compilation(format!(
                "Bootstrap archive member {member_name:?} exceeds {max_archive_bytes} B archive limit."
            )));
        }

        let remaining_budget = max_archive_bytes - total_bytes_used;
        let mut data = Vec::with_capacity(declared_size.min(remaining_budget));
        entry
            .by_ref()
            .take((remaining_budget as u64).saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|e| {
                DgipError::Compilation(format!(
                    "Invalid bootstrap tar.gz stream while reading {member_name:?}: {e}"
                ))
            })?;

        if data.len() > remaining_budget {
            return Err(DgipError::Compilation(format!(
                "Bootstrap archive stream exceeded {max_archive_bytes} B archive limit."
            )));
        }

        total_bytes_used += data.len();
        members_raw.insert(member_name, data);
    }

    let manifest_bytes = members_raw.remove("manifest.json").ok_or_else(|| {
        DgipError::Compilation("Bootstrap bundle.tar.gz is missing manifest.json.".to_string())
    })?;

    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        DgipError::Compilation(format!("Invalid JSON in bootstrap manifest.json: {e}"))
    })?;

    let files_meta = manifest
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DgipError::Compilation(
                "Bootstrap manifest.json is missing 'files' dictionary.".to_string(),
            )
        })?;

    let mut dataset_artifacts: HashMap<String, BuiltArtifact> =
        HashMap::with_capacity(files_meta.len());

    for (fname, meta_val) in files_meta {
        let payload = members_raw.remove(fname).ok_or_else(|| {
            DgipError::Compilation(format!(
                "Bootstrap bundle is missing declared artifact {fname:?}."
            ))
        })?;
        let meta = meta_val.as_object().ok_or_else(|| {
            DgipError::Compilation(format!(
                "Invalid metadata object for bootstrap member {fname:?}."
            ))
        })?;

        let expected_sha = meta
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DgipError::Compilation(format!("Missing sha256 in manifest for {fname:?}."))
            })?
            .to_ascii_lowercase();
        let actual_sha = sha256_bytes(&payload);
        if actual_sha != expected_sha {
            return Err(DgipError::Compilation(format!(
                "SHA-256 verification failed for bootstrap member {fname}: expected {expected_sha}, got {actual_sha}"
            )));
        }

        let expected_size = meta
            .get("size_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                DgipError::Compilation(format!("Missing size_bytes in manifest for {fname:?}."))
            })? as usize;
        if payload.len() != expected_size {
            return Err(DgipError::Compilation(format!(
                "Byte size mismatch for bootstrap member {fname}."
            )));
        }

        let record_count = meta
            .get("record_count")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        let content_type = if fname.ends_with(".gz") {
            "application/gzip"
        } else {
            "application/octet-stream"
        };

        dataset_artifacts.insert(
            fname.clone(),
            BuiltArtifact {
                filename: fname.clone(),
                content_type: content_type.to_string(),
                payload,
                sha256: actual_sha,
                record_count,
            },
        );
    }

    for req_file in [
        ASN_IPV4_FILENAME,
        ASN_IPV6_FILENAME,
        COUNTRY_IPV4_FILENAME,
        COUNTRY_IPV6_FILENAME,
        SECURITY_IPV4_FILENAME,
        SECURITY_IPV6_FILENAME,
    ] {
        if !dataset_artifacts.contains_key(req_file) {
            return Err(DgipError::Compilation(format!(
                "Bootstrap bundle missing required range CSV {req_file:?}."
            )));
        }
    }

    let mut decompress_csv_checked = |fname: &str| -> DgipResult<Vec<u8>> {
        let remaining = max_archive_bytes.saturating_sub(total_bytes_used);
        if remaining == 0 {
            return Err(DgipError::Compilation(format!(
                "Bootstrap CSV decompression for {fname:?} exceeded {max_archive_bytes} B archive limit."
            )));
        }
        let raw_csv = decompress_bounded(&dataset_artifacts[fname].payload, remaining).map_err(|_| {
            DgipError::Compilation(format!(
                "Bootstrap CSV decompression for {fname:?} exceeded {max_archive_bytes} B archive limit."
            ))
        })?;
        total_bytes_used = total_bytes_used.saturating_add(raw_csv.len());
        Ok(raw_csv)
    };

    let asn_v4 = parse_asn_csv_v4(&decompress_csv_checked(ASN_IPV4_FILENAME)?)?;
    let asn_v6 = parse_asn_csv_v6(&decompress_csv_checked(ASN_IPV6_FILENAME)?)?;
    let country_v4 = parse_country_csv_v4(&decompress_csv_checked(COUNTRY_IPV4_FILENAME)?)?;
    let country_v6 = parse_country_csv_v6(&decompress_csv_checked(COUNTRY_IPV6_FILENAME)?)?;
    let security_v4 = parse_security_csv_v4(&decompress_csv_checked(SECURITY_IPV4_FILENAME)?)?;
    let security_v6 = parse_security_csv_v6(&decompress_csv_checked(SECURITY_IPV6_FILENAME)?)?;

    let normalized_sha256 = manifest
        .get("normalized_sha256")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            hash_compiled_tables(
                &asn_v4,
                &asn_v6,
                &country_v4,
                &country_v6,
                &security_v4,
                &security_v6,
            )
        });

    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            DgipError::Compilation("Bootstrap manifest.json is missing 'version'.".to_string())
        })?
        .to_string();

    let release_title = manifest
        .get("release_title")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(&version)
        .to_string();

    let released_at = manifest
        .get("released_at")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let previous_version = manifest
        .get("previous_version")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let source_attribution = manifest
        .get("source_attribution")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    let bundle_sha256 = sha256_bytes(bundle_bytes);
    let sha256sums_bytes =
        build_sha256sums_bytes(&bundle_sha256, &manifest_sha256, &dataset_artifacts);
    let sha256sums_sha256 = sha256_bytes(&sha256sums_bytes);

    let tables = CompiledTables {
        asn_v4,
        asn_v6,
        country_v4,
        country_v6,
        security_v4,
        security_v6,
        normalized_sha256,
    };

    Ok(UnpackedBootstrap {
        version,
        release_title,
        released_at,
        previous_version,
        manifest,
        manifest_bytes,
        manifest_sha256,
        sha256sums_bytes,
        sha256sums_sha256,
        bundle_sha256,
        source_attribution,
        dataset_artifacts,
        tables,
    })
}

fn parse_asn_csv_v4(csv_bytes: &[u8]) -> DgipResult<Vec<AsnV4Row>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_bytes);
    let mut rows = Vec::new();
    for rec_res in rdr.records() {
        let rec = rec_res
            .map_err(|e| DgipError::Compilation(format!("Invalid ASN IPv4 CSV row: {e}")))?;
        if rec.len() < 6 {
            continue;
        }
        let s_int = parse_ipv4_fast(rec[0].trim()).ok_or_else(|| {
            DgipError::Compilation(format!("Invalid IPv4 in ASN CSV: {:?}", &rec[0]))
        })?;
        let e_int = parse_ipv4_fast(rec[1].trim()).ok_or_else(|| {
            DgipError::Compilation(format!("Invalid IPv4 in ASN CSV: {:?}", &rec[1]))
        })?;
        let asn: u32 = rec[2].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid ASN number in ASN CSV: {:?}", &rec[2]))
        })?;
        rows.push(AsnV4Row {
            start: s_int,
            end: e_int,
            asn,
            org: rec[3].to_string(),
            network_type: rec[4].trim().to_string(),
            rpki_status: rec[5].trim().to_string(),
        });
    }
    Ok(rows)
}

fn parse_asn_csv_v6(csv_bytes: &[u8]) -> DgipResult<Vec<AsnV6Row>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_bytes);
    let mut rows = Vec::new();
    for rec_res in rdr.records() {
        let rec = rec_res
            .map_err(|e| DgipError::Compilation(format!("Invalid ASN IPv6 CSV row: {e}")))?;
        if rec.len() < 6 {
            continue;
        }
        let s_v6: Ipv6Addr = rec[0].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid IPv6 in ASN CSV: {:?}", &rec[0]))
        })?;
        let e_v6: Ipv6Addr = rec[1].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid IPv6 in ASN CSV: {:?}", &rec[1]))
        })?;
        let asn: u32 = rec[2].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid ASN number in ASN CSV: {:?}", &rec[2]))
        })?;
        rows.push(AsnV6Row {
            start: u128::from(s_v6),
            end: u128::from(e_v6),
            asn,
            org: rec[3].to_string(),
            network_type: rec[4].trim().to_string(),
            rpki_status: rec[5].trim().to_string(),
        });
    }
    Ok(rows)
}

fn parse_country_csv_v4(csv_bytes: &[u8]) -> DgipResult<Vec<CountryV4Row>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_bytes);
    let mut rows = Vec::new();
    for rec_res in rdr.records() {
        let rec = rec_res
            .map_err(|e| DgipError::Compilation(format!("Invalid Country IPv4 CSV row: {e}")))?;
        if rec.len() < 6 {
            continue;
        }
        let s_int = parse_ipv4_fast(rec[0].trim()).ok_or_else(|| {
            DgipError::Compilation(format!("Invalid IPv4 in Country CSV: {:?}", &rec[0]))
        })?;
        let e_int = parse_ipv4_fast(rec[1].trim()).ok_or_else(|| {
            DgipError::Compilation(format!("Invalid IPv4 in Country CSV: {:?}", &rec[1]))
        })?;
        rows.push(CountryV4Row {
            start: s_int,
            end: e_int,
            cc: rec[2].trim().to_uppercase(),
            region_code: rec[3].trim().to_string(),
            city: rec[4].trim().to_string(),
            geo_source: rec[5].trim().to_string(),
        });
    }
    Ok(rows)
}

fn parse_country_csv_v6(csv_bytes: &[u8]) -> DgipResult<Vec<CountryV6Row>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_bytes);
    let mut rows = Vec::new();
    for rec_res in rdr.records() {
        let rec = rec_res
            .map_err(|e| DgipError::Compilation(format!("Invalid Country IPv6 CSV row: {e}")))?;
        if rec.len() < 6 {
            continue;
        }
        let s_v6: Ipv6Addr = rec[0].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid IPv6 in Country CSV: {:?}", &rec[0]))
        })?;
        let e_v6: Ipv6Addr = rec[1].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid IPv6 in Country CSV: {:?}", &rec[1]))
        })?;
        rows.push(CountryV6Row {
            start: u128::from(s_v6),
            end: u128::from(e_v6),
            cc: rec[2].trim().to_uppercase(),
            region_code: rec[3].trim().to_string(),
            city: rec[4].trim().to_string(),
            geo_source: rec[5].trim().to_string(),
        });
    }
    Ok(rows)
}

fn parse_security_flags_cols(rec: &csv::StringRecord) -> u16 {
    (if rec[2].trim() == "1" { SEC_CLOUD } else { 0 })
        | (if rec[3].trim() == "1" {
            SEC_DATACENTER
        } else {
            0
        })
        | (if rec[4].trim() == "1" { SEC_CDN } else { 0 })
        | (if rec[5].trim() == "1" {
            SEC_TOR_EXIT
        } else {
            0
        })
        | (if rec[6].trim() == "1" {
            SEC_PRIVACY_RELAY
        } else {
            0
        })
        | (if rec[7].trim() == "1" { SEC_THREAT } else { 0 })
}

fn parse_security_csv_v4(csv_bytes: &[u8]) -> DgipResult<Vec<SecurityV4Row>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_bytes);
    let mut rows = Vec::new();
    for rec_res in rdr.records() {
        let rec = rec_res
            .map_err(|e| DgipError::Compilation(format!("Invalid Security IPv4 CSV row: {e}")))?;
        if rec.len() < 10 {
            continue;
        }
        let s_int = parse_ipv4_fast(rec[0].trim()).ok_or_else(|| {
            DgipError::Compilation(format!("Invalid IPv4 in Security CSV: {:?}", &rec[0]))
        })?;
        let e_int = parse_ipv4_fast(rec[1].trim()).ok_or_else(|| {
            DgipError::Compilation(format!("Invalid IPv4 in Security CSV: {:?}", &rec[1]))
        })?;
        rows.push(SecurityV4Row {
            start: s_int,
            end: e_int,
            flags: parse_security_flags_cols(&rec),
            provider: rec[8].trim().to_string(),
            threat_feeds: rec[9].trim().to_string(),
        });
    }
    Ok(rows)
}

fn parse_security_csv_v6(csv_bytes: &[u8]) -> DgipResult<Vec<SecurityV6Row>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(csv_bytes);
    let mut rows = Vec::new();
    for rec_res in rdr.records() {
        let rec = rec_res
            .map_err(|e| DgipError::Compilation(format!("Invalid Security IPv6 CSV row: {e}")))?;
        if rec.len() < 10 {
            continue;
        }
        let s_v6: Ipv6Addr = rec[0].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid IPv6 in Security CSV: {:?}", &rec[0]))
        })?;
        let e_v6: Ipv6Addr = rec[1].trim().parse().map_err(|_| {
            DgipError::Compilation(format!("Invalid IPv6 in Security CSV: {:?}", &rec[1]))
        })?;
        rows.push(SecurityV6Row {
            start: u128::from(s_v6),
            end: u128::from(e_v6),
            flags: parse_security_flags_cols(&rec),
            provider: rec[8].trim().to_string(),
            threat_feeds: rec[9].trim().to_string(),
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_utils::FALLBACK_SPECIAL_RANGES;
    use crate::seed_data::{DEFAULT_COUNTRIES, DEFAULT_SOURCE_ATTRIBUTION};
    use chrono::TimeZone;
    use std::net::Ipv4Addr;

    #[test]
    fn test_flatten_lpm_special_subtraction_and_coalescing() {
        let (ref v4_sp, _) = *FALLBACK_SPECIAL_RANGES;
        let flattened = flatten_binary_cidrs_v4(
            &[
                (u32::from(Ipv4Addr::new(1, 0, 0, 0)), 16, "AU"),
                (u32::from(Ipv4Addr::new(1, 0, 4, 0)), 24, "JP"),
                (u32::from(Ipv4Addr::new(8, 8, 8, 0)), 25, "US"),
                (u32::from(Ipv4Addr::new(8, 8, 8, 128)), 25, "US"),
                (u32::from(Ipv4Addr::new(10, 0, 0, 0)), 24, "BOGON"),
            ],
            v4_sp,
        );
        assert_eq!(flattened.len(), 4);
        assert_eq!(
            flattened[0],
            (
                u32::from(Ipv4Addr::new(1, 0, 0, 0)),
                u32::from(Ipv4Addr::new(1, 0, 3, 255)),
                "AU"
            )
        );
        assert_eq!(
            flattened[1],
            (
                u32::from(Ipv4Addr::new(1, 0, 4, 0)),
                u32::from(Ipv4Addr::new(1, 0, 4, 255)),
                "JP"
            )
        );
        assert_eq!(
            flattened[2],
            (
                u32::from(Ipv4Addr::new(1, 0, 5, 0)),
                u32::from(Ipv4Addr::new(1, 0, 255, 255)),
                "AU"
            )
        );
        assert_eq!(
            flattened[3],
            (
                u32::from(Ipv4Addr::new(8, 8, 8, 0)),
                u32::from(Ipv4Addr::new(8, 8, 8, 255)),
                "US"
            )
        );
    }

    #[test]
    fn test_primary_parsers_snapshot_packaging_and_bootstrap_roundtrip() {
        let allowed_cc: HashSet<String> = DEFAULT_COUNTRIES
            .iter()
            .map(|(cc, _, _)| (*cc).to_string())
            .collect();
        let (ref v4_sp, ref v6_sp) = *FALLBACK_SPECIAL_RANGES;

        let rir_sample = concat!(
            "2|arin|20261102|4|19840101|20261102|+0000\n",
            "arin|*|ipv4|*|70000|summary\n",
            "arin|US|ipv4|8.8.8.0|256|20140314|allocated|id1\n",
            "apnic|AU|ipv4|1.1.1.0|768|20110811|assigned|id2\n",
            "arin|US|ipv4|10.0.0.0|256|20000101|allocated|bogon\n",
            "ripe|DE|ipv6|2a00:1450::|32|20090909|allocated|id3\n",
        );
        let (v4_cidrs, v6_cidrs) = parse_rir_delegated_feed(
            "test-rir",
            rir_sample.as_bytes(),
            1024 * 1024,
            3,
            &allowed_cc,
            v4_sp,
            v6_sp,
        )
        .unwrap();
        assert_eq!(v4_cidrs.len(), 3);
        assert_eq!(v6_cidrs.len(), 1);

        let asnames_sample =
            b"13335 CLOUDFLARENET - Cloudflare, Inc., US\n15169 GOOGLE - Google LLC, US\n";
        let orgs = parse_ripe_asnames(asnames_sample, 1024 * 1024, 2).unwrap();
        assert_eq!(orgs[&13335], "Cloudflare, Inc.");
        assert_eq!(orgs[&15169], "Google LLC");

        let s_888 = u32::from(Ipv4Addr::new(8, 8, 8, 0));
        let s_36 = u32::from(Ipv4Addr::new(3, 6, 0, 0));
        let e_36 = u32::from(Ipv4Addr::new(3, 6, 255, 255));
        let s_v6 = u128::from("2606:4700:4700::".parse::<Ipv6Addr>().unwrap());

        let mut asn_orgs = HashMap::new();
        asn_orgs.insert(15169, "Google LLC".to_string());
        asn_orgs.insert(16509, "Amazon.com, Inc.".to_string());
        asn_orgs.insert(13335, "Cloudflare, Inc.".to_string());

        let mut asn_classes = HashMap::new();
        asn_classes.insert(13335, "Content".to_string());
        asn_classes.insert(16509, "Content".to_string());

        let tables = compile_from_registry_inputs(
            &[(s_888, 24, "US".to_string()), (s_36, 16, "US".to_string())],
            &[(s_v6, 48, "US".to_string())],
            &[
                (s_888, 24, 15169, "valid".to_string()),
                (s_36, 16, 16509, "valid".to_string()),
            ],
            &[(s_v6, 48, 13335, "valid".to_string())],
            &asn_orgs,
            &asn_classes,
            &[(s_36, e_36, GeoAttr::new("IN", "IN-MH", "Mumbai", "geofeed"))],
            &[],
            &[
                RawSecurityIntervalV4 {
                    start: s_36,
                    end: e_36,
                    flags: SEC_CLOUD | SEC_DATACENTER,
                    provider: "aws".to_string(),
                    threat_feed: String::new(),
                },
                RawSecurityIntervalV4 {
                    start: s_888,
                    end: s_888,
                    flags: SEC_THREAT,
                    provider: String::new(),
                    threat_feed: "feodo_c2".to_string(),
                },
            ],
            &[RawSecurityIntervalV6 {
                start: s_v6,
                end: s_v6 + ((1u128 << (128 - 48)) - 1),
                flags: SEC_CDN | SEC_CLOUD,
                provider: "cloudflare".to_string(),
                threat_feed: String::new(),
            }],
            v4_sp,
            v6_sp,
        )
        .unwrap();

        let mut country_details = HashMap::new();
        country_details.insert(
            "US".to_string(),
            (
                "United States".to_string(),
                "NA".to_string(),
                "North America".to_string(),
            ),
        );
        country_details.insert(
            "IN".to_string(),
            ("India".to_string(), "AS".to_string(), "Asia".to_string()),
        );

        let now_dt = Utc.with_ymd_and_hms(2026, 11, 2, 12, 0, 0).unwrap();
        let packaged = package_standard_snapshot(
            &tables,
            "v2026.W45",
            "v2026.W45",
            now_dt,
            None,
            DEFAULT_SOURCE_ATTRIBUTION,
            &country_details,
        )
        .unwrap();

        assert_eq!(packaged.dataset_artifacts.len(), 10);
        let geofeed_bytes = decompress_bounded(
            &packaged.dataset_artifacts[GEOFEED_FILENAME].payload,
            1024 * 1024,
        )
        .unwrap();
        let geofeed_txt = String::from_utf8(geofeed_bytes).unwrap();
        assert!(geofeed_txt.contains("3.6.0.0/16,IN,IN-MH,Mumbai,"));
        assert!(geofeed_txt.contains("8.8.8.0/24,US,,,"));
        assert!(geofeed_txt.contains("2606:4700:4700::/48,US,,,"));

        let unpacked = unpack_bootstrap_bundle(&packaged.bundle_bytes, 64 * 1024 * 1024).unwrap();
        assert_eq!(unpacked.version, "v2026.W45");
        assert_eq!(unpacked.tables.normalized_sha256, tables.normalized_sha256);
        assert_eq!(unpacked.tables.asn_v4, tables.asn_v4);
        assert_eq!(unpacked.tables.country_v4, tables.country_v4);
        assert_eq!(unpacked.tables.security_v4, tables.security_v4);

        // Tarbomb limit enforcement
        assert!(unpack_bootstrap_bundle(&packaged.bundle_bytes, 128).is_err());
    }
}
