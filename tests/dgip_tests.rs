//! Comprehensive end-to-end integration test suite for the Rust DGIP port.
//!
//! Covers all 15 verification suites from `tests/test_dgip.py`:
//! 1. `test_ip_parsing_and_classification`
//! 2. `test_dynamic_special_range_override`
//! 3. `test_xff_extraction`
//! 4. `test_sliding_window_rate_limiter`
//! 5. `test_flatten_binary_cidrs_v4_and_v6`
//! 6. `test_rir_ris_and_asnames_parsers`
//! 7. `test_mmdb_v2_and_snapshot_packaging`
//! 8. `test_range_to_cidr_exact_decomposition`
//! 9. `test_openapi_yaml_parity`
//! 10. `test_portal_and_swagger_ui_endpoints`
//! 11. `test_streaming_body_limit_and_security_headers`
//! 12. `test_config_validation_tarbomb_cap_and_copy_escaping`
//! 13. `test_nro_mirror_fallback`
//! 14. `test_cli_argument_parsing`
//! 15. `test_enrichment_layers_2_3_and_4`

use axum::body::{Body, Bytes};
use axum::http::{header, Method, Request, StatusCode};
use chrono::{TimeZone, Utc};
use dgip::cli::{
    parse_config_key_value, try_parse_cli_from, Commands, ConfigCommands, FeedCommands,
    HostCommands,
};
use dgip::compiler::{
    compile_from_registry_inputs, decompress_bounded, deterministic_gzip, flatten_binary_cidrs_v4,
    flatten_binary_cidrs_v6, package_standard_snapshot, parse_ripe_asnames,
    parse_rir_delegated_feed, parse_ris_bgp_feed, unpack_bootstrap_bundle, ASN_IPV4_FILENAME,
    ASN_IPV6_FILENAME, ASN_MMDB_FILENAME, COUNTRY_IPV4_FILENAME, COUNTRY_IPV6_FILENAME,
    COUNTRY_MMDB_FILENAME, GEOFEED_FILENAME, SECURITY_IPV4_FILENAME, SECURITY_IPV6_FILENAME,
    SECURITY_MMDB_FILENAME,
};
use dgip::config::Settings;
use dgip::db::{escape_copy_text, validate_and_normalize_config_updates};
use dgip::enrichment::{
    classify_asn_network_type, merge_security_intervals_v4, overlay_disjoint_intervals_v4,
    parse_asn_classes_csv, parse_cidr_text_list, parse_fastly_json, parse_gcp_cloud_json,
    parse_github_meta_json, parse_ip_literal_list, parse_oracle_cloud_json, parse_rfc8805_geofeed,
    parse_rpki_vrps_csv, parse_spamhaus_drop_jsonl, GeoAttr, RawSecurityIntervalV4,
};
use dgip::http::create_app;
use dgip::ip_utils::{
    compile_special_ranges, extract_client_ip, parse_and_classify_ip, FALLBACK_SPECIAL_RANGES,
};
use dgip::mmdb::{build_dual_stack_mmdb, iter_range_cidrs_v4, iter_range_cidrs_v6, MmdbValue};
use dgip::ratelimit::SlidingWindowRateLimiter;
use dgip::release_notes::{
    compute_diff_and_release_notes, format_iso_week_version, format_release_title,
};
use dgip::seed_data::{DEFAULT_CONTINENTS, DEFAULT_COUNTRIES, DEFAULT_SOURCE_ATTRIBUTION};
use dgip::swagger::{build_branded_openapi_schema, PUBLIC_OPENAPI_PATHS};
use dgip::sync::{
    fetch_single_feed_with_fallback, rir_nro_mirror_url, PRIMARY_RIR_FAST_TIMEOUT_SECONDS,
};
use dgip::types::{
    format_ipv4, DgipError, FeedSourceSpec, IpNet, SEC_CDN, SEC_CLOUD, SEC_DATACENTER,
    SEC_PRIVACY_RELAY, SEC_THREAT, SEC_TOR_EXIT,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn ipv4_u32(s: &str) -> u32 {
    u32::from(s.parse::<Ipv4Addr>().expect("valid IPv4 literal"))
}

fn ipv6_u128(s: &str) -> u128 {
    u128::from(s.parse::<Ipv6Addr>().expect("valid IPv6 literal"))
}

fn default_country_details() -> HashMap<String, (String, String, String)> {
    let cont_map: HashMap<&str, &str> = DEFAULT_CONTINENTS.iter().copied().collect();
    let mut map = HashMap::with_capacity(DEFAULT_COUNTRIES.len());
    for &(cc, cname, cont_code) in DEFAULT_COUNTRIES {
        let cont_name = cont_map.get(cont_code).copied().unwrap_or(cont_code);
        map.insert(
            cc.to_string(),
            (
                cname.to_string(),
                cont_code.to_string(),
                cont_name.to_string(),
            ),
        );
    }
    map
}

fn default_valid_countries() -> HashSet<String> {
    DEFAULT_COUNTRIES
        .iter()
        .map(|&(cc, _, _)| cc.to_string())
        .collect()
}

async fn response_body_bytes(resp: axum::response::Response) -> Bytes {
    axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .expect("read axum response body")
}

async fn response_body_string(resp: axum::response::Response) -> String {
    let bytes = response_body_bytes(resp).await;
    String::from_utf8(bytes.to_vec()).expect("valid utf-8 body")
}

// ============================================================================
// 1. IPv4 / IPv6 Parsing, Normalization & Bogon Classification
// ============================================================================
#[test]
fn test_ip_parsing_and_classification() {
    let v4 = parse_and_classify_ip("8.8.8.8", None, None).expect("8.8.8.8 valid");
    assert_eq!(v4.canonical, "8.8.8.8");
    assert_eq!(v4.version, 4);
    assert!(!v4.is_bogon);
    assert_eq!(v4.bogon_type, None);
    assert!(!v4.is_ipv4_mapped);
    assert_eq!(v4.v4_int, ipv4_u32("8.8.8.8"));

    let mapped = parse_and_classify_ip("::ffff:8.8.8.8", None, None).expect("mapped v4 valid");
    assert_eq!(mapped.canonical, "8.8.8.8");
    assert_eq!(mapped.version, 4);
    assert!(mapped.is_ipv4_mapped);
    assert!(!mapped.is_bogon);

    let mapped_loop =
        parse_and_classify_ip("::ffff:127.0.0.1", None, None).expect("mapped loopback valid");
    assert_eq!(mapped_loop.canonical, "127.0.0.1");
    assert!(mapped_loop.is_bogon);
    assert_eq!(mapped_loop.bogon_type.as_deref(), Some("loopback"));

    let cgnat = parse_and_classify_ip("100.64.10.1", None, None).expect("cgnat valid");
    assert!(cgnat.is_bogon);
    assert_eq!(cgnat.bogon_type.as_deref(), Some("carrier_grade_nat"));

    let doc4 = parse_and_classify_ip("192.0.2.42", None, None).expect("doc v4 valid");
    assert!(doc4.is_bogon);
    assert_eq!(doc4.bogon_type.as_deref(), Some("documentation"));

    let v6 = parse_and_classify_ip("2001:4860:4860:0000:0000:0000:0000:8888", None, None)
        .expect("google v6 valid");
    assert_eq!(v6.canonical, "2001:4860:4860::8888");
    assert_eq!(v6.version, 6);
    assert!(!v6.is_bogon);

    let doc6 = parse_and_classify_ip("2001:db8::1", None, None).expect("doc v6 valid");
    assert!(doc6.is_bogon);
    assert_eq!(doc6.bogon_type.as_deref(), Some("documentation"));

    for bad in [
        "",
        "999.999.999.999",
        "fe80::1%eth0",
        "10.0.0.0/8",
        "example.com",
        "010.0.0.1",
        "::ffff:010.0.0.1",
    ] {
        let res = parse_and_classify_ip(bad, None, None);
        assert!(
            matches!(res, Err(DgipError::InvalidIp(_))),
            "expected InvalidIp for {bad:?}, got {res:?}"
        );
    }
}

// ============================================================================
// 2. Dynamic Special-Range Override
// ============================================================================
#[test]
fn test_dynamic_special_range_override() {
    let (v4_rules, v6_rules) =
        compile_special_ranges([("203.0.113.0/24", 4i16, "custom_lab_block", 1i16)]);

    let hit = parse_and_classify_ip("203.0.113.99", Some(&v4_rules), Some(&v6_rules))
        .expect("parse 203.0.113.99");
    assert!(hit.is_bogon);
    assert_eq!(hit.bogon_type.as_deref(), Some("custom_lab_block"));

    let pub_ip =
        parse_and_classify_ip("8.8.8.8", Some(&v4_rules), Some(&v6_rules)).expect("parse 8.8.8.8");
    assert!(!pub_ip.is_bogon);
    assert_eq!(pub_ip.bogon_type, None);
}

// ============================================================================
// 3. Trusted-Proxy X-Forwarded-For Extraction
// ============================================================================
#[test]
fn test_xff_extraction() {
    // Untrusted peer ignores X-Forwarded-For completely
    let direct = extract_client_ip("198.51.100.7", Some("1.1.1.1, 8.8.8.8"), &[]);
    assert_eq!(direct, "198.51.100.7");

    let trusted = vec![
        IpNet::parse_non_strict("10.0.0.0/8").unwrap(),
        IpNet::parse_non_strict("172.16.0.0/12").unwrap(),
    ];

    // Rightmost-to-leftmost traversal skips trusted hops and stops at first untrusted hop,
    // ignoring spoofed leftmost entries ("203.0.113.9").
    let xff = "203.0.113.9, 198.51.100.44, 172.16.0.5";
    assert_eq!(
        extract_client_ip("10.1.2.3", Some(xff), &trusted),
        "198.51.100.44"
    );

    // IPv4-mapped IPv6 peer socket matches IPv4 trusted proxy CIDR
    assert_eq!(
        extract_client_ip("::ffff:10.1.2.3", Some("9.9.9.9"), &trusted),
        "9.9.9.9"
    );
}

// ============================================================================
// 4. Sliding-Window Rate Limiter & Hot Reconfiguration
// ============================================================================
#[test]
fn test_sliding_window_rate_limiter() {
    let limiter = SlidingWindowRateLimiter::new(3, 60.0, 50_000);

    let d1 = limiter.check_at("198.51.100.1", Some(1000.0));
    let d2 = limiter.check_at("198.51.100.1", Some(1010.0));
    let d3 = limiter.check_at("198.51.100.1", Some(1020.0));
    assert!(d1.allowed && d1.remaining == 2);
    assert!(d2.allowed && d2.remaining == 1);
    assert!(d3.allowed && d3.remaining == 0);

    let d4 = limiter.check_at("198.51.100.1", Some(1025.0));
    assert!(!d4.allowed);
    assert!(d4.retry_after >= 35);
    let headers_map: HashMap<&str, String> = d4.headers().into_iter().collect();
    assert!(headers_map.contains_key("Retry-After"));
    assert_eq!(
        headers_map.get("X-RateLimit-Remaining").map(String::as_str),
        Some("0")
    );

    // Expiry of oldest hit at t=1061.0 re-opens window
    let d5 = limiter.check_at("198.51.100.1", Some(1061.0));
    assert!(d5.allowed);

    // Hot reconfiguration updates capacity immediately
    limiter.reconfigure(10, 60.0, 50_000);
    let d6 = limiter.check_at("198.51.100.1", Some(1062.0));
    assert!(d6.allowed);
    assert_eq!(d6.limit, 10);
}

// ============================================================================
// 5. Binary Longest-Prefix-Match CIDR Flattening (IPv4 & IPv6)
// ============================================================================
#[test]
fn test_flatten_binary_cidrs_v4_and_v6() {
    // IPv4: 1.0.0.0/16 ("AU") overridden by 1.0.1.0/24 ("CN") and 1.0.2.0/24 ("CN"),
    // where the two adjacent /24s merge into [1.0.1.0, 1.0.2.255].
    let cidrs_v4 = vec![
        (ipv4_u32("1.0.0.0"), 16u8, "AU"),
        (ipv4_u32("1.0.1.0"), 24u8, "CN"),
        (ipv4_u32("1.0.2.0"), 24u8, "CN"),
    ];
    let flat_v4 = flatten_binary_cidrs_v4(&cidrs_v4, &FALLBACK_SPECIAL_RANGES.0);
    assert_eq!(
        flat_v4,
        vec![
            (ipv4_u32("1.0.0.0"), ipv4_u32("1.0.0.255"), "AU"),
            (ipv4_u32("1.0.1.0"), ipv4_u32("1.0.2.255"), "CN"),
            (ipv4_u32("1.0.3.0"), ipv4_u32("1.0.255.255"), "AU"),
        ]
    );
    let total_v4_ips: u64 = flat_v4
        .iter()
        .map(|&(s, e, _)| u64::from(e) - u64::from(s) + 1)
        .sum();
    assert_eq!(total_v4_ips, 65_536);
    for pair in flat_v4.windows(2) {
        assert_eq!(pair[0].1 + 1, pair[1].0);
    }

    // IPv6: 2001:4860::/32 (AS15169) with nested 2001:4860:4860::/48 (AS36492)
    let cidrs_v6 = vec![
        (ipv6_u128("2001:4860::"), 32u8, 15169u32),
        (ipv6_u128("2001:4860:4860::"), 48u8, 36492u32),
    ];
    let flat_v6 = flatten_binary_cidrs_v6(&cidrs_v6, &FALLBACK_SPECIAL_RANGES.1);
    assert_eq!(flat_v6.len(), 3);
    assert_eq!(flat_v6[0].2, 15169);
    assert_eq!(flat_v6[1].2, 36492);
    assert_eq!(flat_v6[2].2, 15169);
    assert_eq!(flat_v6[0].1 + 1, flat_v6[1].0);
    assert_eq!(flat_v6[1].1 + 1, flat_v6[2].0);
}

// ============================================================================
// 6. Authoritative RIR Delegated, RIPE RIS BGP & RIPE AS-Names Parsers
// ============================================================================
#[test]
fn test_rir_ris_and_asnames_parsers() {
    let asnames_raw = b"13335 CLOUDFLARENET - Cloudflare, Inc., US\n15169 GOOGLE - Google LLC, US\n64512 PRIVATE-AS, ZZ\n";
    let orgs = parse_ripe_asnames(asnames_raw, 1_048_576, 1).expect("parse_ripe_asnames");
    assert_eq!(
        orgs.get(&13335).map(String::as_str),
        Some("Cloudflare, Inc.")
    );
    assert_eq!(orgs.get(&15169).map(String::as_str), Some("Google LLC"));

    // RIR delegated extended format: non-power-of-two IPv4 count (768 = /23 + /24),
    // IPv6 /32, reserved status ignored, bogon 10.0.0.0 ignored.
    let rir_raw = concat!(
        "2|apnic|20260101|4|19850701|20260101|+1000\n",
        "apnic|AU|ipv4|1.0.1.0|768|20110412|allocated|a1b2c3\n",
        "apnic|US|ipv4|8.8.8.0|256|20140101|assigned|d4e5f6\n",
        "apnic|US|ipv4|10.0.0.0|256|20140101|allocated|bogon\n",
        "apnic|ZZ|ipv4|1.2.3.0|256|20140101|reserved|resv\n",
        "apnic|US|ipv6|2001:4860::|32|20110412|allocated|v6id\n",
    );
    let valid_cc = default_valid_countries();
    let (v4_rir, v6_rir) = parse_rir_delegated_feed(
        "rir-apnic",
        rir_raw.as_bytes(),
        1_048_576,
        1,
        &valid_cc,
        &FALLBACK_SPECIAL_RANGES.0,
        &FALLBACK_SPECIAL_RANGES.1,
    )
    .expect("parse_rir_delegated_feed");
    // 768 starting at 1.0.1.0 (not /23-aligned because 1.0.1.0 has bit 8 = 1) decomposes into
    // 1.0.1.0/24 (256) + 1.0.2.0/23 (512), plus 8.8.8.0/24 = 3 CIDRs total!
    assert_eq!(v4_rir.len(), 3);
    assert!(v4_rir.contains(&(ipv4_u32("1.0.1.0"), 24, "AU".to_string())));
    assert!(v4_rir.contains(&(ipv4_u32("1.0.2.0"), 23, "AU".to_string())));
    assert!(v4_rir.contains(&(ipv4_u32("8.8.8.0"), 24, "US".to_string())));
    assert_eq!(
        v6_rir,
        vec![(ipv6_u128("2001:4860::"), 32, "US".to_string())]
    );

    // RIPE RIS BGP dump: MOAS peer-count winner, private AS-SET dropped, low-peer dropped,
    // overly broad < /8 dropped, bogon dropped.
    let ris_v4_raw = concat!(
        "% RIPE RIS dump\n",
        "13335\t1.1.1.0/24\t280\n",
        "15169\t1.1.1.0/24\t12\n",
        "15169\t8.8.8.0/24\t310\n",
        "{64512,64513}\t9.9.9.0/24\t99\n",
        "13335\t1.0.4.0/24\t2\n",
        "15169\t8.0.0.0/4\t100\n",
        "15169\t192.0.2.0/24\t100\n",
    );
    let (bgp_v4, bgp_v6_empty) = parse_ris_bgp_feed(
        "ris-bgp-ipv4",
        4,
        ris_v4_raw.as_bytes(),
        1_048_576,
        1,
        5,
        8,
        1,
        4_294_967_294,
        &FALLBACK_SPECIAL_RANGES.0,
        &FALLBACK_SPECIAL_RANGES.1,
        None,
        true,
    )
    .expect("parse_ris_bgp_feed");
    assert!(bgp_v6_empty.is_empty());
    assert_eq!(bgp_v4.len(), 2);
    assert!(bgp_v4.contains(&(ipv4_u32("1.1.1.0"), 24, 13335, "unknown".to_string())));
    assert!(bgp_v4.contains(&(ipv4_u32("8.8.8.0"), 24, 15169, "unknown".to_string())));
}

// ============================================================================
// 7. MaxMind MMDB v2.0 Binary Writer (24-bit & 28-bit) & Snapshot Packaging
// ============================================================================
#[test]
fn test_mmdb_v2_and_snapshot_packaging() {
    let mut rec_cf = BTreeMap::new();
    rec_cf.insert("asn".to_string(), MmdbValue::Uint32(13335));
    rec_cf.insert(
        "org".to_string(),
        MmdbValue::Str("Cloudflare, Inc.".to_string()),
    );
    let mut rec_gg = BTreeMap::new();
    rec_gg.insert("asn".to_string(), MmdbValue::Uint32(15169));
    rec_gg.insert("org".to_string(), MmdbValue::Str("Google LLC".to_string()));

    let v4_intervals = vec![
        (ipv4_u32("1.1.1.0"), ipv4_u32("1.1.1.255"), 1u32),
        (ipv4_u32("8.8.8.0"), ipv4_u32("8.8.8.255"), 2u32),
    ];
    let v6_intervals = vec![(
        ipv6_u128("2001:4860:4860::"),
        ipv6_u128("2001:4860:4860:ffff:ffff:ffff:ffff:ffff"),
        2u32,
    )];
    let ordered_records = vec![
        (1u32, MmdbValue::Map(rec_cf)),
        (2u32, MmdbValue::Map(rec_gg)),
    ];

    // Verify both default 24-bit and forced 28-bit MMDB v2.0 trees using maxminddb::Reader
    for forced_size in [None, Some(28u16)] {
        let mmdb_bytes = build_dual_stack_mmdb(
            "DGIP-Test",
            "DGIP Dual-Stack Test DB",
            &v4_intervals,
            &v6_intervals,
            &ordered_records,
            Some(1_760_000_000),
            forced_size,
        );
        let reader = maxminddb::Reader::from_source(mmdb_bytes).expect("valid MMDB v2.0 binary");
        assert_eq!(reader.metadata().binary_format_major_version, 2);
        assert_eq!(reader.metadata().binary_format_minor_version, 0);
        assert_eq!(reader.metadata().ip_version, 6);
        assert_eq!(reader.metadata().record_size, forced_size.unwrap_or(24));

        let hit_cf: Value = reader
            .lookup("1.1.1.1".parse::<IpAddr>().unwrap())
            .expect("lookup 1.1.1.1")
            .decode()
            .expect("decode 1.1.1.1")
            .expect("present 1.1.1.1");
        assert_eq!(hit_cf["asn"], 13335);
        assert_eq!(hit_cf["org"], "Cloudflare, Inc.");

        let hit_v6: Value = reader
            .lookup("2001:4860:4860::8888".parse::<IpAddr>().unwrap())
            .expect("lookup google v6")
            .decode()
            .expect("decode google v6")
            .expect("present google v6");
        assert_eq!(hit_v6["asn"], 15169);

        let miss: Option<Value> = reader
            .lookup("9.9.9.9".parse::<IpAddr>().unwrap())
            .expect("lookup miss")
            .decode()
            .expect("decode miss");
        assert!(miss.is_none());
    }

    // Full 4-layer compilation -> package_standard_snapshot -> unpack_bootstrap_bundle round-trip
    let rir_v4 = vec![
        (ipv4_u32("1.1.1.0"), 24u8, "AU".to_string()),
        (ipv4_u32("8.8.8.0"), 24u8, "US".to_string()),
    ];
    let rir_v6 = vec![(ipv6_u128("2001:4860::"), 32u8, "US".to_string())];
    let bgp_v4 = vec![
        (ipv4_u32("1.1.1.0"), 24u8, 13335u32, "valid".to_string()),
        (ipv4_u32("8.8.8.0"), 24u8, 15169u32, "valid".to_string()),
    ];
    let bgp_v6 = vec![(
        ipv6_u128("2001:4860::"),
        32u8,
        15169u32,
        "valid".to_string(),
    )];
    let mut asn_orgs = HashMap::new();
    asn_orgs.insert(13335u32, "Cloudflare, Inc.".to_string());
    asn_orgs.insert(15169u32, "Google LLC".to_string());
    let mut asn_classes = HashMap::new();
    asn_classes.insert(13335u32, "hosting".to_string());
    asn_classes.insert(15169u32, "hosting".to_string());

    let geo_v4 = vec![(
        ipv4_u32("8.8.8.0"),
        ipv4_u32("8.8.8.255"),
        GeoAttr::new("US", "US-CA", "Mountain View", "geofeed"),
    )];
    let sec_v4 = vec![RawSecurityIntervalV4 {
        start: ipv4_u32("1.1.1.0"),
        end: ipv4_u32("1.1.1.255"),
        flags: SEC_CDN | SEC_CLOUD,
        provider: "cloudflare".to_string(),
        threat_feed: String::new(),
    }];

    let tables = compile_from_registry_inputs(
        &rir_v4,
        &rir_v6,
        &bgp_v4,
        &bgp_v6,
        &asn_orgs,
        &asn_classes,
        &geo_v4,
        &[],
        &sec_v4,
        &[],
        &FALLBACK_SPECIAL_RANGES.0,
        &FALLBACK_SPECIAL_RANGES.1,
    )
    .expect("compile_from_registry_inputs");

    let dt = Utc.with_ymd_and_hms(2026, 3, 9, 3, 0, 0).unwrap();
    let ver1 = format_iso_week_version(dt, &[], "v");
    assert_eq!(ver1, "v2026.W11");
    let ver2 = format_iso_week_version(dt, std::slice::from_ref(&ver1), "v");
    assert_eq!(ver2, "v2026.W11.1");
    let title = format_release_title("DGIP {version} ({date})", &ver1, dt);
    assert_eq!(title, "DGIP v2026.W11 (2026-03-09)");

    let country_details = default_country_details();
    let packaged = package_standard_snapshot(
        &tables,
        &ver1,
        &title,
        dt,
        None,
        DEFAULT_SOURCE_ATTRIBUTION,
        &country_details,
    )
    .expect("package_standard_snapshot");

    // Verify all 10 dataset artifacts exist + RFC 8805 geofeed + all 3 MMDBs readable
    let expected_artifacts = [
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
    ];
    for name in expected_artifacts {
        assert!(
            packaged.dataset_artifacts.contains_key(name),
            "missing packaged artifact {name}"
        );
    }

    let geofeed_raw = decompress_bounded(
        &packaged.dataset_artifacts[GEOFEED_FILENAME].payload,
        8 * 1024 * 1024,
    )
    .expect("decompress geofeed");
    let geofeed_str = String::from_utf8(geofeed_raw).unwrap();
    assert!(geofeed_str.contains("8.8.8.0/24,US,US-CA,Mountain View,"));

    let asn_mmdb = maxminddb::Reader::from_source(
        packaged.dataset_artifacts[ASN_MMDB_FILENAME]
            .payload
            .as_slice(),
    )
    .expect("read dgip-asn.mmdb");
    let asn_rec: Value = asn_mmdb
        .lookup("8.8.8.8".parse::<IpAddr>().unwrap())
        .expect("lookup 8.8.8.8 in dgip-asn.mmdb")
        .decode()
        .expect("decode 8.8.8.8")
        .expect("present 8.8.8.8");
    assert_eq!(asn_rec["autonomous_system_number"], 15169);
    assert_eq!(asn_rec["rpki_status"], "valid");

    let country_mmdb = maxminddb::Reader::from_source(
        packaged.dataset_artifacts[COUNTRY_MMDB_FILENAME]
            .payload
            .as_slice(),
    )
    .expect("read dgip-country.mmdb");
    let cc_rec: Value = country_mmdb
        .lookup("8.8.8.8".parse::<IpAddr>().unwrap())
        .expect("lookup 8.8.8.8 in dgip-country.mmdb")
        .decode()
        .expect("decode cc")
        .expect("present cc");
    assert_eq!(cc_rec["country"]["iso_code"], "US");
    assert_eq!(cc_rec["city"]["names"]["en"], "Mountain View");

    let sec_mmdb = maxminddb::Reader::from_source(
        packaged.dataset_artifacts[SECURITY_MMDB_FILENAME]
            .payload
            .as_slice(),
    )
    .expect("read dgip-security.mmdb");
    let sec_rec: Value = sec_mmdb
        .lookup("1.1.1.1".parse::<IpAddr>().unwrap())
        .expect("lookup 1.1.1.1 in dgip-security.mmdb")
        .decode()
        .expect("decode sec")
        .expect("present sec");
    assert_eq!(sec_rec["is_cdn"], true);
    assert_eq!(sec_rec["is_cloud"], true);
    assert_eq!(sec_rec["provider"], "cloudflare");

    // Verify diff & release notes generation
    let diff_notes = compute_diff_and_release_notes(
        &packaged,
        &tables,
        None,
        None,
        None,
        DEFAULT_SOURCE_ATTRIBUTION,
        Some("Automated CI verification note."),
    )
    .expect("compute_diff_and_release_notes");
    assert!(diff_notes.release_notes_md.contains("v2026.W11"));
    assert!(diff_notes
        .release_notes_md
        .contains("Automated CI verification note."));

    // Unpack bootstrap bundle and verify 1-to-1 SHA-256 & row count parity
    let unpacked = unpack_bootstrap_bundle(&packaged.bundle_bytes, 64 * 1024 * 1024)
        .expect("unpack_bootstrap_bundle");
    assert_eq!(unpacked.version, ver1);
    assert_eq!(unpacked.bundle_sha256, packaged.bundle_sha256);
    assert_eq!(unpacked.tables.asn_v4, tables.asn_v4);
    assert_eq!(unpacked.tables.asn_v6, tables.asn_v6);
    assert_eq!(unpacked.tables.country_v4, tables.country_v4);
    assert_eq!(unpacked.tables.security_v4, tables.security_v4);
}

// ============================================================================
// 8. Exact Range-to-CIDR Bitwise Decomposition (IPv4 & IPv6)
// ============================================================================
#[test]
fn test_range_to_cidr_exact_decomposition() {
    // Non-aligned IPv4 range [1.0.1.0, 1.0.3.255] (768 IPs = 1.0.1.0/24 + 1.0.2.0/23)
    let start_v4 = ipv4_u32("1.0.1.0");
    let end_v4 = ipv4_u32("1.0.3.255");
    let blocks_v4 = iter_range_cidrs_v4(start_v4, end_v4);
    assert_eq!(
        blocks_v4,
        vec![(ipv4_u32("1.0.1.0"), 24), (ipv4_u32("1.0.2.0"), 23)]
    );

    // Arbitrary odd range [10.0.0.1, 10.0.0.6]: verify exact coverage without gaps or overlaps
    let odd_s = ipv4_u32("10.0.0.1");
    let odd_e = ipv4_u32("10.0.0.6");
    let odd_blocks = iter_range_cidrs_v4(odd_s, odd_e);
    let mut cursor = odd_s;
    for (net, plen) in odd_blocks {
        assert_eq!(net, cursor);
        let size = 1u32 << (32 - plen);
        cursor += size;
    }
    assert_eq!(cursor - 1, odd_e);

    // IPv6 decomposition: 2001:db8::1 ..= 2001:db8::4
    let v6_s = ipv6_u128("2001:db8::1");
    let v6_e = ipv6_u128("2001:db8::4");
    let blocks_v6 = iter_range_cidrs_v6(v6_s, v6_e);
    let mut cursor_v6 = v6_s;
    for (net, plen) in blocks_v6 {
        assert_eq!(net, cursor_v6);
        let size = 1u128 << (128 - plen);
        cursor_v6 += size;
    }
    assert_eq!(cursor_v6 - 1, v6_e);
}

// ============================================================================
// 9. OpenAPI 3.1.0 YAML & Live Schema Parity (10 Read-Only Paths, Zero Auth)
// ============================================================================
#[test]
fn test_openapi_yaml_parity() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let yaml_path = manifest_dir.join("openapi.yaml");
    let yaml_raw = std::fs::read_to_string(&yaml_path).expect("read openapi.yaml");
    let disk_spec: Value = serde_saphyr::from_str(&yaml_raw).expect("parse openapi.yaml");
    let runtime_spec = build_branded_openapi_schema();

    assert_eq!(disk_spec["openapi"], "3.1.0");
    assert_eq!(runtime_spec["openapi"], "3.1.0");
    assert_eq!(runtime_spec["info"]["contact"]["name"], "Daviante");
    assert_eq!(runtime_spec["info"]["license"]["name"], "Apache-2.0");

    // Zero auth schemes & zero /v1/admin/* endpoints
    assert!(runtime_spec["components"].get("securitySchemes").is_none());
    assert!(runtime_spec.get("security").is_none());

    let paths_obj = runtime_spec["paths"]
        .as_object()
        .expect("paths must be object");
    assert_eq!(paths_obj.len(), PUBLIC_OPENAPI_PATHS.len());
    assert_eq!(paths_obj.len(), 10);

    for &(expected_path, expected_methods) in PUBLIC_OPENAPI_PATHS {
        assert!(!expected_path.contains("/admin"));
        let item = paths_obj
            .get(expected_path)
            .unwrap_or_else(|| panic!("missing OpenAPI path {expected_path}"));
        for &m in expected_methods {
            assert!(
                item.get(m).is_some(),
                "missing method {m} on OpenAPI path {expected_path}"
            );
        }
    }
}

// ============================================================================
// 10. Home Portal, Swagger UI v5, Brand SVG Assets & Disabled Gate
// ============================================================================
#[tokio::test]
async fn test_portal_and_swagger_ui_endpoints() {
    let (app_enabled, _) = create_app(Settings {
        swagger_enabled: true,
        ..Settings::default()
    })
    .expect("create_app enabled");

    // GET / interactive portal (zero external CDN in CSP)
    let resp_home = app_enabled
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp_home.status(), StatusCode::OK);
    let home_csp = resp_home
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!home_csp.contains("cdn.jsdelivr.net"));
    let home_html = response_body_string(resp_home).await;
    assert!(home_html.contains("Daviante"));
    assert!(home_html.contains("href=\"/docs\""));

    // GET /docs Swagger UI v5 wrapper
    let resp_docs = app_enabled
        .clone()
        .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp_docs.status(), StatusCode::OK);
    let docs_csp = resp_docs
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(docs_csp.contains("https://cdn.jsdelivr.net"));
    let docs_html = response_body_string(resp_docs).await;
    assert!(docs_html.contains("SwaggerUIBundle"));
    assert!(docs_html.contains("/openapi.json"));

    // GET /openapi.json
    let resp_oa = app_enabled
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_oa.status(), StatusCode::OK);
    let oa_json: Value = serde_json::from_slice(&response_body_bytes(resp_oa).await).unwrap();
    assert_eq!(oa_json["openapi"], "3.1.0");

    // Whitelisted SVG brand assets succeed; traversal / unknown asset returns 404 ProblemDetails
    for svg in ["logo.svg", "logo-dark.svg", "favicon.svg"] {
        let r = app_enabled
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/docs/assets/{svg}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml"
        );
        let body = response_body_string(r).await;
        assert!(body.contains("<svg"));
    }

    let bad_asset = app_enabled
        .clone()
        .oneshot(
            Request::builder()
                .uri("/docs/assets/secret.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_asset.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        bad_asset.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );

    // Swagger disabled: /docs, /openapi.json, /docs/assets/logo.svg all return 404 ProblemDetails,
    // while / remains 200 OK without /docs links.
    let (app_disabled, _) = create_app(Settings {
        swagger_enabled: false,
        ..Settings::default()
    })
    .expect("create_app disabled");

    for gated in ["/docs", "/openapi.json", "/docs/assets/logo.svg"] {
        let r = app_disabled
            .clone()
            .oneshot(Request::builder().uri(gated).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }

    let home_off = app_disabled
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(home_off.status(), StatusCode::OK);
    let home_off_html = response_body_string(home_off).await;
    assert!(!home_off_html.contains("href=\"/docs\""));
}

// ============================================================================
// 11. Streaming Body Cap (413), Security Headers & Read-Only HTTP Surface
// ============================================================================
#[tokio::test]
async fn test_streaming_body_limit_and_security_headers() {
    let (app, _) = create_app(Settings::default()).expect("create_app");

    // 1. Streaming POST /v1/ip/batch WITHOUT Content-Length exceeding 256 KiB -> 413 ProblemDetails
    let chunks: Vec<Result<Bytes, std::io::Error>> =
        (0..40).map(|_| Ok(Bytes::from(vec![b'x'; 8192]))).collect();
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
        "application/problem+json"
    );
    assert_eq!(
        resp_413.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp_413.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        resp_413.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    let body_413: Value = serde_json::from_slice(&response_body_bytes(resp_413).await).unwrap();
    assert_eq!(body_413["status"], 413);

    // 2. All legacy /v1/admin/* endpoints return 404 ProblemDetails
    for (method, path) in [
        (Method::GET, "/v1/admin/status"),
        (Method::POST, "/v1/admin/sync"),
        (Method::POST, "/v1/admin/releases"),
        (Method::PATCH, "/v1/admin/config"),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }

    // 3. Disallowed mutation verb PUT /v1/ip/8.8.8.8 returns 405 Method Not Allowed ProblemDetails
    let resp_405 = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/ip/8.8.8.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_405.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        resp_405.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
}

// ============================================================================
// 12. Config Validation, Tar-Bomb Decompression Cap & PostgreSQL COPY Escaping
// ============================================================================
#[test]
fn test_config_validation_tarbomb_cap_and_copy_escaping() {
    // Valid config normalization
    let mut ok_updates = HashMap::new();
    ok_updates.insert("rate_limit_per_minute".to_string(), json!("240"));
    ok_updates.insert("swagger_enabled".to_string(), json!("false"));
    ok_updates.insert(
        "trusted_proxies".to_string(),
        json!(["10.0.0.1/8", "2001:db8::1/32"]),
    );
    let normalized =
        validate_and_normalize_config_updates(&ok_updates, false).expect("valid config updates");
    assert_eq!(normalized["rate_limit_per_minute"], json!(240));
    assert_eq!(normalized["swagger_enabled"], json!(false));
    assert_eq!(
        normalized["trusted_proxies"],
        json!(["10.0.0.0/8", "2001:db8::/32"])
    );

    // Reject unknown keys, out-of-range ints, non-HTTPS bootstrap URL when allow_local_files=false
    let mut bad_key = HashMap::new();
    bad_key.insert("nonexistent_key".to_string(), json!(1));
    assert!(validate_and_normalize_config_updates(&bad_key, false).is_err());

    let mut bad_url = HashMap::new();
    bad_url.insert(
        "bootstrap_bundle_url".to_string(),
        json!("http://insecure.example.com/bundle.tar.gz"),
    );
    assert!(validate_and_normalize_config_updates(&bad_url, false).is_err());

    let mut file_url = HashMap::new();
    file_url.insert(
        "bootstrap_bundle_url".to_string(),
        json!("file:///tmp/bundle.tar.gz"),
    );
    assert!(validate_and_normalize_config_updates(&file_url, false).is_err());
    assert!(validate_and_normalize_config_updates(&file_url, true).is_ok());

    // Gzip decompression bomb cap
    let big_zeros = vec![b'A'; 128 * 1024];
    let gz_bomb = deterministic_gzip(&big_zeros, 6);
    assert!(gz_bomb.len() < 1024);
    assert!(decompress_bounded(&gz_bomb, 16 * 1024).is_err());
    assert_eq!(
        decompress_bounded(&gz_bomb, 256 * 1024).unwrap().len(),
        128 * 1024
    );

    // Tar archive cumulative byte cap in unpack_bootstrap_bundle
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let payload = vec![b'Z'; 32 * 1024];
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", payload.as_slice())
            .unwrap();
        builder.finish().unwrap();
    }
    let tar_gz = deterministic_gzip(&tar_buf, 6);
    let tar_err = unpack_bootstrap_bundle(&tar_gz, 8 * 1024);
    assert!(tar_err.is_err());

    // PostgreSQL COPY TEXT escaping (`\`, `\t`, `\n`, `\r`, NUL stripped)
    assert_eq!(
        escape_copy_text("Cloud\\Net\tCorp\nLine2\r\0End"),
        "Cloud\\\\Net\\tCorp\\nLine2\\rEnd"
    );
}

// ============================================================================
// 13. Automatic RIPE NCC NRO Mirror Fallback on RIR Stall / Failure
// ============================================================================
#[tokio::test]
async fn test_nro_mirror_fallback() {
    assert_eq!(
        rir_nro_mirror_url(
            "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
        ),
        Some("https://ftp.ripe.net/pub/stats/afrinic/delegated-afrinic-extended-latest")
    );
    assert_eq!(
        rir_nro_mirror_url(
            "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
        ),
        None
    );

    let spec = FeedSourceSpec {
        feed_key: "rir-afrinic".to_string(),
        kind: "rir_delegated".to_string(),
        ip_version: 0,
        source_url: "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
            .to_string(),
        min_records: 100,
        max_compressed_bytes: 67_108_864,
        max_uncompressed_bytes: 268_435_456,
        enabled: true,
        display_order: 5,
    };

    let mut allowed_hosts = HashSet::new();
    allowed_hosts.insert("ftp.afrinic.net".to_string());
    allowed_hosts.insert("ftp.ripe.net".to_string());

    let seen_calls: Arc<Mutex<Vec<(String, f64)>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = Arc::clone(&seen_calls);

    let res = fetch_single_feed_with_fallback(
        &spec,
        &allowed_hosts,
        120.0,
        false,
        move |url: String, timeout_secs: f64| {
            let log = Arc::clone(&seen_clone);
            async move {
                log.lock().unwrap().push((url.clone(), timeout_secs));
                if url.contains("ftp.afrinic.net") {
                    Err(DgipError::Compilation(
                        "primary RIR connection stalled".to_string(),
                    ))
                } else {
                    Ok(b"2|afrinic|20260101|1|19850101|20260101|+0000\n".to_vec())
                }
            }
        },
    )
    .await
    .expect("mirror fallback must succeed");

    assert!(res.is_some());
    {
        let calls = seen_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].0.contains("ftp.afrinic.net"));
        assert!((calls[0].1 - PRIMARY_RIR_FAST_TIMEOUT_SECONDS).abs() < 1e-6);
        assert_eq!(
            calls[1].0,
            "https://ftp.ripe.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
        );
        assert!((calls[1].1 - 120.0).abs() < 1e-6);
    }

    // Optional enrichment feed soft-fails to Ok(None) when enrichment_strict = false,
    // and hard-fails with Err when enrichment_strict = true.
    let opt_spec = FeedSourceSpec {
        feed_key: "sec-tor-exits".to_string(),
        kind: "tor_exit_list".to_string(),
        ip_version: 0,
        source_url: "https://check.torproject.org/torbulkexitlist".to_string(),
        min_records: 10,
        max_compressed_bytes: 10_485_760,
        max_uncompressed_bytes: 33_554_432,
        enabled: true,
        display_order: 40,
    };
    let soft =
        fetch_single_feed_with_fallback(&opt_spec, &allowed_hosts, 30.0, false, |_url, _t| async {
            Err(DgipError::Compilation("upstream 503".to_string()))
        })
        .await
        .expect("soft fail returns Ok(None)");
    assert!(soft.is_none());

    let strict_err =
        fetch_single_feed_with_fallback(&opt_spec, &allowed_hosts, 30.0, true, |_url, _t| async {
            Err(DgipError::Compilation("upstream 503".to_string()))
        })
        .await;
    assert!(strict_err.is_err());
}

// ============================================================================
// 14. Operational CLI Subcommand & Key-Value Argument Parsing
// ============================================================================
#[test]
fn test_cli_argument_parsing() {
    // Default (no subcommand) -> None (dispatches to serve)
    let def_cli = try_parse_cli_from(["dgip"]).expect("dgip no-arg");
    assert_eq!(def_cli.command, None);
    assert!(!def_cli.verbose);

    // Explicit `serve` and `healthcheck`
    let serve_cli = try_parse_cli_from(["dgip", "-v", "serve"]).expect("dgip -v serve");
    assert!(serve_cli.verbose);
    assert_eq!(serve_cli.command, Some(Commands::Serve));

    let hc_cli = try_parse_cli_from(["dgip", "healthcheck"]).expect("dgip healthcheck");
    assert_eq!(hc_cli.command, Some(Commands::Healthcheck));

    // `status --json`, `sync --force --json`, `release --force --note ... --json`
    let st_cli = try_parse_cli_from(["dgip", "status", "--json"]).expect("status --json");
    assert_eq!(st_cli.command, Some(Commands::Status { json: true }));

    let sync_cli =
        try_parse_cli_from(["dgip", "sync", "--force", "--json"]).expect("sync --force --json");
    assert_eq!(
        sync_cli.command,
        Some(Commands::Sync {
            force: true,
            json: true
        })
    );

    let rel_cli = try_parse_cli_from([
        "dgip",
        "release",
        "--force",
        "--note",
        "Weekly cut",
        "--json",
    ])
    .expect("release");
    assert_eq!(
        rel_cli.command,
        Some(Commands::Release {
            force: true,
            note: Some("Weekly cut".to_string()),
            json: true,
        })
    );

    // `config set`, `feed set-url`, `host allow`, `build-release` + `compile-local` alias
    let cfg_cli = try_parse_cli_from([
        "dgip",
        "config",
        "set",
        "rate_limit_per_minute=180",
        "swagger_enabled=false",
        "--json",
    ])
    .expect("config set");
    assert_eq!(
        cfg_cli.command,
        Some(Commands::Config {
            cmd: ConfigCommands::Set {
                pairs: vec![
                    "rate_limit_per_minute=180".to_string(),
                    "swagger_enabled=false".to_string()
                ],
                json: true,
            }
        })
    );

    let feed_cli = try_parse_cli_from([
        "dgip",
        "feed",
        "set-url",
        "rir-arin",
        "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "--min-records",
        "5000",
    ])
    .expect("feed set-url");
    assert_eq!(
        feed_cli.command,
        Some(Commands::Feed {
            cmd: FeedCommands::SetUrl {
                feed_key: "rir-arin".to_string(),
                url: "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
                    .to_string(),
                min_records: Some(5000),
                json: false,
            }
        })
    );

    let host_cli = try_parse_cli_from(["dgip", "host", "allow", "ftp.ripe.net", "--notes", "NRO"])
        .expect("host allow");
    assert_eq!(
        host_cli.command,
        Some(Commands::Host {
            cmd: HostCommands::Allow {
                hostname: "ftp.ripe.net".to_string(),
                notes: Some("NRO".to_string()),
                json: false,
            }
        })
    );

    let br_cli = try_parse_cli_from([
        "dgip",
        "build-release",
        "--output-dir",
        "/tmp/dgip-out",
        "--version",
        "v2026.W11",
    ])
    .expect("build-release");
    assert_eq!(
        br_cli.command,
        Some(Commands::BuildRelease {
            output_dir: Path::new("/tmp/dgip-out").to_path_buf(),
            version: Some("v2026.W11".to_string()),
        })
    );

    let alias_cli = try_parse_cli_from(["dgip", "compile-local", "--output-dir", "/tmp/dgip-out"])
        .expect("compile-local alias");
    assert_eq!(
        alias_cli.command,
        Some(Commands::BuildRelease {
            output_dir: Path::new("/tmp/dgip-out").to_path_buf(),
            version: None,
        })
    );

    // Key=Value parser
    let (k1, v1) = parse_config_key_value("rate_limit_per_minute=180").unwrap();
    assert_eq!(k1, "rate_limit_per_minute");
    assert_eq!(v1, json!("180"));

    let (k2, v2) = parse_config_key_value("trusted_proxies=10.0.0.0/8, 172.16.0.0/12").unwrap();
    assert_eq!(k2, "trusted_proxies");
    assert_eq!(v2, json!(["10.0.0.0/8", "172.16.0.0/12"]));

    let (_, v3) = parse_config_key_value("trusted_proxies=[]").unwrap();
    assert_eq!(v3, json!([]));

    assert!(parse_config_key_value("missing_equals").is_err());
}

// ============================================================================
// 15. Enrichment Layers 2, 3 & 4 (Geofeed, Cloud Geo, RPKI, ASN Type, Security)
// ============================================================================
#[test]
fn test_enrichment_layers_2_3_and_4() {
    let valid_cc = default_valid_countries();
    let sp_v4 = &FALLBACK_SPECIAL_RANGES.0;
    let sp_v6 = &FALLBACK_SPECIAL_RANGES.1;

    // Layer 2A: RFC 8805 Geofeed + Apple Private Relay detection + GCP & Oracle Cloud JSON
    let rfc8805_csv = concat!(
        "# RFC 8805 Geofeed\n",
        "172.224.226.0/27,US,US-CA,San Jose,\n",
        "8.8.8.0/24,US,US-CA,Mountain View,\n",
    );
    let (apple_geo_v4, _, apple_sec_v4, _) = parse_rfc8805_geofeed(
        "geo-apple-relay",
        rfc8805_csv.as_bytes(),
        1_048_576,
        1,
        &valid_cc,
        sp_v4,
        sp_v6,
    )
    .expect("parse_rfc8805_geofeed");
    assert_eq!(apple_geo_v4.len(), 2);
    // `geo-apple-relay` feed key automatically tags SEC_PRIVACY_RELAY!
    assert!(!apple_sec_v4.is_empty());
    assert_eq!(apple_sec_v4[0].flags & SEC_PRIVACY_RELAY, SEC_PRIVACY_RELAY);
    assert_eq!(apple_sec_v4[0].provider, "apple_icloud_relay");

    let gcp_json = br#"{
        "prefixes": [
            {"ipv4Prefix": "34.80.0.0/15", "scope": "asia-east1", "service": "Google Cloud"},
            {"ipv6Prefix": "2600:1900:4000::/44", "scope": "us-central1", "service": "Google Cloud"}
        ]
    }"#;
    let (gcp_geo_v4, gcp_geo_v6, gcp_sec_v4, _) =
        parse_gcp_cloud_json("cloud-gcp", gcp_json, 1_048_576, 1, &valid_cc, sp_v4, sp_v6)
            .expect("parse_gcp_cloud_json");
    assert_eq!(gcp_geo_v4.len(), 1);
    assert_eq!(gcp_geo_v4[0].2.cc, "TW");
    assert_eq!(gcp_geo_v6.len(), 1);
    assert_eq!(gcp_geo_v6[0].2.cc, "US");
    assert_eq!(gcp_sec_v4[0].flags, SEC_CLOUD | SEC_DATACENTER);

    let oracle_json = br#"{
        "regions": [
            {
                "region": "eu-frankfurt-1",
                "cidrs": [{"cidr": "130.61.0.0/16", "tags": ["OCI"]}]
            }
        ]
    }"#;
    let (oci_geo_v4, _, _, _) = parse_oracle_cloud_json(
        "cloud-oracle",
        oracle_json,
        1_048_576,
        1,
        &valid_cc,
        sp_v4,
        sp_v6,
    )
    .expect("parse_oracle_cloud_json");
    assert_eq!(oci_geo_v4.len(), 1);
    assert_eq!(oci_geo_v4[0].2.cc, "DE");
    assert_eq!(oci_geo_v4[0].2.city, "Frankfurt");

    // Disjoint geo overlay punches sub-national city into RIR country base
    let base_geo = vec![(
        ipv4_u32("8.8.0.0"),
        ipv4_u32("8.8.255.255"),
        GeoAttr::new("US", "", "", "rir"),
    )];
    let over_geo = vec![(
        ipv4_u32("8.8.8.0"),
        ipv4_u32("8.8.8.255"),
        GeoAttr::new("US", "US-CA", "Mountain View", "geofeed"),
    )];
    let merged_geo = overlay_disjoint_intervals_v4(&base_geo, &over_geo);
    assert_eq!(merged_geo.len(), 3);
    assert_eq!(merged_geo[1].2.city, "Mountain View");
    assert_eq!(merged_geo[0].2.geo_source, "rir");

    // Layer 3: RPKI VRP route-origin validation & hijack rejection + ASN network_type
    let vrp_csv = concat!(
        "ASN,IP Prefix,Max Length,Trust Anchor\n",
        "AS13335,1.1.1.0/24,24,apnic\n",
        "AS15169,8.8.8.0/24,24,arin\n",
        "AS15169,2001:4860::/32,48,arin\n",
    );
    let rpki_tbl = parse_rpki_vrps_csv("rpki-vrps", vrp_csv.as_bytes(), 1_048_576, 1, sp_v4, sp_v6)
        .expect("parse_rpki_vrps_csv");
    assert_eq!(
        rpki_tbl.validate_v4(ipv4_u32("1.1.1.0"), 24, 13335),
        "valid"
    );
    // Unauthorized origin ASN -> invalid
    assert_eq!(
        rpki_tbl.validate_v4(ipv4_u32("1.1.1.0"), 24, 64496),
        "invalid"
    );
    // Prefix more specific than MaxLength (/25 > 24) -> invalid
    assert_eq!(
        rpki_tbl.validate_v4(ipv4_u32("1.1.1.0"), 25, 13335),
        "invalid"
    );
    // Uncovered prefix -> unknown
    assert_eq!(
        rpki_tbl.validate_v4(ipv4_u32("9.9.9.0"), 24, 19281),
        "unknown"
    );
    // IPv6 covered within MaxLength 48 -> valid
    assert_eq!(
        rpki_tbl.validate_v6(ipv6_u128("2001:4860:4860::"), 48, 15169),
        "valid"
    );

    // Verify BGP hijack route is dropped when rpki_reject_invalid = true
    let hijack_ris = "64500\t1.1.1.0/24\t50\n13335\t1.1.1.0/24\t200\n9999\t8.8.8.0/24\t80\n";
    let (filtered_bgp, _) = parse_ris_bgp_feed(
        "ris-bgp-ipv4",
        4,
        hijack_ris.as_bytes(),
        1_048_576,
        1,
        5,
        8,
        1,
        4_294_967_294,
        sp_v4,
        sp_v6,
        Some(&rpki_tbl),
        true,
    )
    .expect("parse_ris_bgp_feed with RPKI");
    assert_eq!(
        filtered_bgp,
        vec![(ipv4_u32("1.1.1.0"), 24, 13335, "valid".to_string())]
    );

    // ASN network_type classification (CSV map + org-name heuristics)
    let asn_csv =
        b"asn,org,class\n2906,Netflix Streaming Services,Content\n7922,Comcast, eyeball \n";
    let (classes_map, _) =
        parse_asn_classes_csv("asn-classes", asn_csv, 1_048_576, 1).expect("parse_asn_classes_csv");
    assert_eq!(
        classify_asn_network_type(13335, "Cloudflare, Inc.", &classes_map),
        "cdn"
    );
    assert_eq!(
        classify_asn_network_type(2906, "Netflix Streaming Services Inc.", &classes_map),
        "content"
    );
    assert_eq!(
        classify_asn_network_type(7922, "Cable Holdings Corp.", &classes_map),
        "isp"
    );
    assert_eq!(
        classify_asn_network_type(
            400001,
            "Massachusetts Institute of Technology University",
            &classes_map
        ),
        "education"
    );
    assert_eq!(
        classify_asn_network_type(400002, "DigitalOcean Cloud Hosting LLC", &classes_map),
        "hosting"
    );

    // Layer 4: Fastly CDN, GitHub Meta, Spamhaus DROP JSONL, Tor Exits, Feodo C2 & Sweep-Line Bitmask Union
    let fastly_raw = br#"{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}"#;
    let (fastly_v4, fastly_v6) =
        parse_fastly_json("cdn-fastly", fastly_raw, 1_048_576, 1, sp_v4, sp_v6)
            .expect("parse_fastly_json");
    assert_eq!(fastly_v4.len(), 1);
    assert_eq!(fastly_v6.len(), 1);
    assert_eq!(fastly_v4[0].flags, SEC_CDN | SEC_CLOUD);
    assert_eq!(fastly_v4[0].provider, "fastly");

    let gh_raw = br#"{"hooks":["192.30.252.0/22"],"actions":["4.175.114.56/32"]}"#;
    let (gh_v4, _) = parse_github_meta_json("cloud-github", gh_raw, 1_048_576, 1, sp_v4, sp_v6)
        .expect("parse_github_meta_json");
    assert_eq!(gh_v4.len(), 2);

    let drop_jsonl = concat!(
        r#"{"cidr":"198.51.100.0/24","sblid":"SBL1"}"#,
        "\n",
        r#"{"cidr":"45.95.168.0/24","sblid":"SBL12345"}"#,
        "\n",
        r#"{"type":"metadata","timestamp":1760000000}"#,
        "\n",
    );
    let (drop_v4, _) = parse_spamhaus_drop_jsonl(
        "sec-spamhaus-drop",
        drop_jsonl.as_bytes(),
        1_048_576,
        1,
        sp_v4,
        sp_v6,
    )
    .expect("parse_spamhaus_drop_jsonl");
    // 198.51.100.0/24 is TEST-NET-2 bogon -> filtered out; 45.95.168.0/24 is retained!
    assert_eq!(drop_v4.len(), 1);
    assert_eq!(drop_v4[0].flags, SEC_THREAT);
    assert_eq!(drop_v4[0].threat_feed, "spamhaus_drop");

    let feodo_txt = b"# Abuse.ch Feodo C2\n45.95.168.42\n";
    let (feodo_v4, _) = parse_ip_literal_list(
        "sec-feodo-c2",
        feodo_txt,
        1_048_576,
        1,
        SEC_THREAT,
        "",
        "feodo_c2",
        sp_v4,
        sp_v6,
    )
    .expect("parse_ip_literal_list");
    assert_eq!(feodo_v4.len(), 1);

    let cf_cidrs = b"45.95.168.0/24\n";
    let (cf_v4, _) = parse_cidr_text_list(
        "cdn-cloudflare-v4",
        cf_cidrs,
        1_048_576,
        1,
        SEC_CDN | SEC_CLOUD,
        "cloudflare",
        "",
        sp_v4,
        sp_v6,
    )
    .expect("parse_cidr_text_list");

    // Sweep-line merge of overlapping security intervals:
    // 45.95.168.0..=45.95.168.255 has Spamhaus DROP + Cloudflare, and 45.95.168.42 ALSO has Feodo C2 + Tor Exit!
    let mut raw_sec = Vec::new();
    raw_sec.extend(drop_v4);
    raw_sec.extend(feodo_v4);
    raw_sec.extend(cf_v4);
    raw_sec.push(RawSecurityIntervalV4 {
        start: ipv4_u32("45.95.168.42"),
        end: ipv4_u32("45.95.168.42"),
        flags: SEC_TOR_EXIT,
        provider: String::new(),
        threat_feed: String::new(),
    });

    let merged_sec = merge_security_intervals_v4(&raw_sec);
    assert_eq!(merged_sec.len(), 3);
    assert_eq!(
        (
            format_ipv4(merged_sec[0].start),
            format_ipv4(merged_sec[0].end)
        ),
        ("45.95.168.0".to_string(), "45.95.168.41".to_string())
    );
    assert_eq!(
        (
            format_ipv4(merged_sec[1].start),
            format_ipv4(merged_sec[1].end)
        ),
        ("45.95.168.42".to_string(), "45.95.168.42".to_string())
    );
    assert_eq!(
        merged_sec[1].flags,
        SEC_CDN | SEC_CLOUD | SEC_THREAT | SEC_TOR_EXIT
    );
    assert_eq!(merged_sec[1].provider, "cloudflare");
    assert_eq!(merged_sec[1].threat_feeds, "feodo_c2,spamhaus_drop");
}
