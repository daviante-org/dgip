//! ISO-8601 week release versioning, dataset diff calculation, and Markdown release notes.

use crate::types::{
    format_ipv4, format_ipv6, AsnRow, CompiledTables, CountryRow, DgipError, DgipResult,
    PackagedSnapshot, SecurityRow, ASN_IPV4_FILENAME, ASN_IPV6_FILENAME, COUNTRY_IPV4_FILENAME,
    COUNTRY_IPV6_FILENAME, SECURITY_IPV4_FILENAME, SECURITY_IPV6_FILENAME,
};
use chrono::{DateTime, Datelike, Utc};
use flate2::bufread::MultiGzDecoder;
use serde_json::{json, Map as JsonMap, Value};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Structured JSON diff summary and rendered Markdown release notes for a snapshot cut.
#[derive(Debug, Clone)]
pub struct ReleaseDiffAndNotes {
    pub diff_summary: Value,
    pub release_notes_md: String,
}

/// Format an ISO-8601 week version tag:
/// - Primary weekly cut: `{prefix}YYYY.Www` (for example `v2026.W45`)
/// - Same-week rebuilds: `{prefix}YYYY.Www.1`, `{prefix}YYYY.Www.2`, ...
pub fn format_iso_week_version(
    dt_utc: DateTime<Utc>,
    existing_versions: &[String],
    prefix: &str,
) -> String {
    let iso = dt_utc.iso_week();
    let base_ver = format!("{}{}.W{:02}", prefix, iso.year(), iso.week());

    let existing_set: HashSet<&str> = existing_versions.iter().map(String::as_str).collect();
    if !existing_set.contains(base_ver.as_str()) {
        return base_ver;
    }

    let mut max_patch: u64 = 0;
    let patch_prefix = format!("{base_ver}.");
    for &ver in &existing_set {
        if let Some(suffix) = ver.strip_prefix(&patch_prefix) {
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(patch_num) = suffix.parse::<u64>() {
                    max_patch = max_patch.max(patch_num);
                }
            }
        }
    }

    format!("{base_ver}.{}", max_patch + 1)
}

/// Render a release title template supporting `{version}` and `{date}` (`YYYY-MM-DD`),
/// plus escaped braces `{{` and `}}`. Falls back to `version` if the
/// template contains malformed braces or unknown placeholders.
pub fn format_release_title(template: &str, version: &str, dt_utc: DateTime<Utc>) -> String {
    let date_str = dt_utc.format("%Y-%m-%d").to_string();
    let mut out = String::with_capacity(template.len() + version.len() + date_str.len());
    let mut chars = template.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    out.push('{');
                    continue;
                }
                let mut key = String::new();
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        closed = true;
                        break;
                    }
                    if inner == '{' {
                        return version.to_string();
                    }
                    key.push(inner);
                }
                if !closed {
                    return version.to_string();
                }
                let field = key.strip_suffix("!s").unwrap_or(&key);
                match field {
                    "version" => out.push_str(version),
                    "date" => out.push_str(&date_str),
                    _ => return version.to_string(),
                }
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    out.push('}');
                } else {
                    return version.to_string();
                }
            }
            other => out.push(other),
        }
    }

    out
}

fn human_bytes(num_bytes: usize) -> String {
    if num_bytes >= 1_048_576 {
        format!("{:.2} MB", (num_bytes as f64) / 1_048_576.0)
    } else if num_bytes >= 1024 {
        format!("{:.1} KB", (num_bytes as f64) / 1024.0)
    } else {
        format!("{num_bytes} B")
    }
}

fn format_u64_commas(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 3 {
        return s;
    }
    let mut out = String::with_capacity(len + (len - 1) / 3);
    for (idx, &b) in bytes.iter().enumerate() {
        if idx > 0 && (len - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn format_usize_commas(n: usize) -> String {
    format_u64_commas(n as u64)
}

fn format_i64_signed_commas(n: i64) -> String {
    if n >= 0 {
        format!("+{}", format_u64_commas(n as u64))
    } else {
        format!("-{}", format_u64_commas(n.unsigned_abs()))
    }
}

fn split_splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            lines.push(&s[start..i]);
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
            start = i;
        } else if bytes[i] == b'\n' {
            lines.push(&s[start..i]);
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < bytes.len() {
        lines.push(&s[start..]);
    }
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableKind {
    Asn,
    Country,
    Security,
}

type ExtractedCsvStats = (
    HashSet<(String, String)>,
    HashMap<u32, String>,
    HashMap<String, usize>,
);

fn extract_csv_gz_stats(table_kind: TableKind, gz_bytes: &[u8]) -> DgipResult<ExtractedCsvStats> {
    let mut ranges: HashSet<(String, String)> = HashSet::new();
    let mut asn_orgs: HashMap<u32, String> = HashMap::new();
    let mut country_counts: HashMap<String, usize> = HashMap::new();

    let decoder = MultiGzDecoder::new(gz_bytes);
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(decoder);

    let mut rec = csv::StringRecord::new();
    while rdr.read_record(&mut rec).map_err(|e| {
        DgipError::Compilation(format!("Failed reading previous CSV.gz diff stream: {e}"))
    })? {
        if rec.len() < 3 {
            continue;
        }
        ranges.insert((rec[0].to_string(), rec[1].to_string()));
        match table_kind {
            TableKind::Asn => {
                let asn: u32 = rec[2].trim().parse().map_err(|e| {
                    DgipError::Compilation(format!(
                        "Invalid ASN {:?} in previous CSV.gz diff stream: {e}",
                        &rec[2]
                    ))
                })?;
                let org = rec.get(3).unwrap_or("");
                let should_update = match asn_orgs.get(&asn) {
                    None => true,
                    Some(existing) => !org.is_empty() && existing.is_empty(),
                };
                if should_update {
                    asn_orgs.insert(asn, org.to_string());
                }
            }
            TableKind::Country => {
                let cc = &rec[2];
                if let Some(cnt) = country_counts.get_mut(cc) {
                    *cnt += 1;
                } else {
                    country_counts.insert(cc.to_string(), 1);
                }
            }
            TableKind::Security => {}
        }
    }

    Ok((ranges, asn_orgs, country_counts))
}

#[derive(Debug, Clone)]
struct DatasetDiffMetrics {
    rows: usize,
    previous_rows: Option<usize>,
    net_delta: Option<i64>,
    ranges_added: Option<usize>,
    ranges_removed: Option<usize>,
    size_bytes: usize,
}

enum TableRef<'a> {
    AsnV4(&'a [AsnRow<u32>]),
    AsnV6(&'a [AsnRow<u128>]),
    CountryV4(&'a [CountryRow<u32>]),
    CountryV6(&'a [CountryRow<u128>]),
    SecurityV4(&'a [SecurityRow<u32>]),
    SecurityV6(&'a [SecurityRow<u128>]),
}

impl<'a> TableRef<'a> {
    fn kind(&self) -> TableKind {
        match self {
            TableRef::AsnV4(_) | TableRef::AsnV6(_) => TableKind::Asn,
            TableRef::CountryV4(_) | TableRef::CountryV6(_) => TableKind::Country,
            TableRef::SecurityV4(_) | TableRef::SecurityV6(_) => TableKind::Security,
        }
    }

    fn len(&self) -> usize {
        match self {
            TableRef::AsnV4(r) => r.len(),
            TableRef::AsnV6(r) => r.len(),
            TableRef::CountryV4(r) => r.len(),
            TableRef::CountryV6(r) => r.len(),
            TableRef::SecurityV4(r) => r.len(),
            TableRef::SecurityV6(r) => r.len(),
        }
    }
}

fn upsert_asn_org(map: &mut HashMap<u32, String>, asn: u32, org: &str) {
    let should_update = match map.get(&asn) {
        None => true,
        Some(existing) => !org.is_empty() && existing.is_empty(),
    };
    if should_update {
        map.insert(asn, org.to_string());
    }
}

fn increment_cc_count(map: &mut HashMap<String, usize>, cc: &str, delta: usize) {
    if let Some(cnt) = map.get_mut(cc) {
        *cnt += delta;
    } else {
        map.insert(cc.to_string(), delta);
    }
}

/// Compare compiled tables against the prior weekly snapshot and render Markdown release notes.
pub fn compute_diff_and_release_notes(
    packaged: &PackagedSnapshot,
    tables: &CompiledTables,
    previous_version: Option<&str>,
    previous_csv_gz: Option<&HashMap<String, Vec<u8>>>,
    previous_row_counts: Option<&HashMap<String, usize>>,
    source_attribution: &str,
    operator_note: Option<&str>,
) -> DgipResult<ReleaseDiffAndNotes> {
    let table_specs: [(&str, TableRef<'_>); 6] = [
        (ASN_IPV4_FILENAME, TableRef::AsnV4(&tables.asn_v4)),
        (ASN_IPV6_FILENAME, TableRef::AsnV6(&tables.asn_v6)),
        (
            COUNTRY_IPV4_FILENAME,
            TableRef::CountryV4(&tables.country_v4),
        ),
        (
            COUNTRY_IPV6_FILENAME,
            TableRef::CountryV6(&tables.country_v6),
        ),
        (
            SECURITY_IPV4_FILENAME,
            TableRef::SecurityV4(&tables.security_v4),
        ),
        (
            SECURITY_IPV6_FILENAME,
            TableRef::SecurityV6(&tables.security_v6),
        ),
    ];

    let mut dataset_metrics: HashMap<String, DatasetDiffMetrics> = HashMap::with_capacity(6);
    let mut datasets_json = JsonMap::new();
    let mut new_asn_orgs: HashMap<u32, String> = HashMap::new();
    let mut old_asn_orgs: HashMap<u32, String> = HashMap::new();
    let mut new_cc_counts: HashMap<String, usize> = HashMap::new();
    let mut old_cc_counts: HashMap<String, usize> = HashMap::new();

    let has_prev_version = previous_version.is_some_and(|v| !v.is_empty());
    let has_prev_blobs = has_prev_version && previous_csv_gz.is_some_and(|m| !m.is_empty());

    for (fname, table_ref) in &table_specs {
        let prev_gz = previous_csv_gz.and_then(|m| m.get(*fname));
        let need_curr_ranges = prev_gz.is_some();
        let mut curr_ranges: HashSet<(String, String)> = if need_curr_ranges {
            HashSet::with_capacity(table_ref.len())
        } else {
            HashSet::new()
        };

        match table_ref {
            TableRef::AsnV4(rows) => {
                for row in *rows {
                    if need_curr_ranges {
                        curr_ranges.insert((format_ipv4(row.start), format_ipv4(row.end)));
                    }
                    upsert_asn_org(&mut new_asn_orgs, row.asn, &row.org);
                }
            }
            TableRef::AsnV6(rows) => {
                for row in *rows {
                    if need_curr_ranges {
                        curr_ranges.insert((format_ipv6(row.start), format_ipv6(row.end)));
                    }
                    upsert_asn_org(&mut new_asn_orgs, row.asn, &row.org);
                }
            }
            TableRef::CountryV4(rows) => {
                for row in *rows {
                    if need_curr_ranges {
                        curr_ranges.insert((format_ipv4(row.start), format_ipv4(row.end)));
                    }
                    increment_cc_count(&mut new_cc_counts, &row.cc, 1);
                }
            }
            TableRef::CountryV6(rows) => {
                for row in *rows {
                    if need_curr_ranges {
                        curr_ranges.insert((format_ipv6(row.start), format_ipv6(row.end)));
                    }
                    increment_cc_count(&mut new_cc_counts, &row.cc, 1);
                }
            }
            TableRef::SecurityV4(rows) => {
                if need_curr_ranges {
                    for row in *rows {
                        curr_ranges.insert((format_ipv4(row.start), format_ipv4(row.end)));
                    }
                }
            }
            TableRef::SecurityV6(rows) => {
                if need_curr_ranges {
                    for row in *rows {
                        curr_ranges.insert((format_ipv6(row.start), format_ipv6(row.end)));
                    }
                }
            }
        }

        let row_len = table_ref.len();
        let (prev_cnt, added, removed, net_delta) = if let Some(gz_bytes) = prev_gz {
            let (prev_ranges, p_asns, p_ccs) = extract_csv_gz_stats(table_ref.kind(), gz_bytes)?;
            for (k_asn, v_org) in p_asns {
                upsert_asn_org(&mut old_asn_orgs, k_asn, &v_org);
            }
            for (k_cc, v_cnt) in p_ccs {
                increment_cc_count(&mut old_cc_counts, &k_cc, v_cnt);
            }

            let added_cnt = curr_ranges.difference(&prev_ranges).count();
            let removed_cnt = prev_ranges.difference(&curr_ranges).count();
            let p_cnt = prev_ranges.len();
            let delta = (row_len as i64) - (p_cnt as i64);
            (Some(p_cnt), Some(added_cnt), Some(removed_cnt), Some(delta))
        } else {
            let p_cnt = previous_row_counts.and_then(|m| m.get(*fname).copied());
            let delta = p_cnt.map(|pc| (row_len as i64) - (pc as i64));
            (p_cnt, None, None, delta)
        };

        let art = packaged.dataset_artifacts.get(*fname).ok_or_else(|| {
            DgipError::Compilation(format!(
                "PackagedSnapshot missing dataset artifact {fname:?}"
            ))
        })?;
        let size_bytes = art.payload.len();

        let metrics = DatasetDiffMetrics {
            rows: row_len,
            previous_rows: prev_cnt,
            net_delta,
            ranges_added: added,
            ranges_removed: removed,
            size_bytes,
        };

        datasets_json.insert(
            (*fname).to_string(),
            json!({
                "rows": metrics.rows,
                "previous_rows": metrics.previous_rows,
                "net_delta": metrics.net_delta,
                "ranges_added": metrics.ranges_added,
                "ranges_removed": metrics.ranges_removed,
                "size_bytes": metrics.size_bytes,
            }),
        );
        dataset_metrics.insert((*fname).to_string(), metrics);
    }

    let active_asns = new_asn_orgs.len();
    type AsnDelta = (Vec<u32>, Vec<u32>, usize, Vec<(String, String, Value)>);
    let (added_asns, removed_asns, renamed_orgs, sample_new): AsnDelta =
        if has_prev_blobs && !old_asn_orgs.is_empty() {
            let mut added: Vec<u32> = new_asn_orgs
                .keys()
                .filter(|a| !old_asn_orgs.contains_key(a))
                .copied()
                .collect();
            added.sort_unstable();

            let mut removed: Vec<u32> = old_asn_orgs
                .keys()
                .filter(|a| !new_asn_orgs.contains_key(a))
                .copied()
                .collect();
            removed.sort_unstable();

            let renamed = new_asn_orgs
                .iter()
                .filter(|(asn, new_org)| {
                    old_asn_orgs
                        .get(asn)
                        .is_some_and(|old_org| old_org != *new_org)
                })
                .count();

            let samples: Vec<(String, String, Value)> = added
                .iter()
                .take(10)
                .map(|&a| {
                    let code = format!("AS{a}");
                    let org_raw = new_asn_orgs.get(&a).map(String::as_str).unwrap_or("");
                    let org_label = if org_raw.is_empty() {
                        "Unlisted".to_string()
                    } else {
                        org_raw.to_string()
                    };
                    let val = json!({
                        "asn": a,
                        "code": code,
                        "organization": org_label,
                    });
                    (code, org_label, val)
                })
                .collect();

            (added, removed, renamed, samples)
        } else {
            (Vec::new(), Vec::new(), 0, Vec::new())
        };

    let active_countries = new_cc_counts.len();
    let mut top_cc_tuples: Vec<(String, i64, usize)> = Vec::new();
    if has_prev_blobs && !old_cc_counts.is_empty() {
        let mut all_ccs: BTreeSet<&str> = BTreeSet::new();
        for k in new_cc_counts.keys() {
            all_ccs.insert(k.as_str());
        }
        for k in old_cc_counts.keys() {
            all_ccs.insert(k.as_str());
        }

        let mut deltas: Vec<(String, i64, usize)> = Vec::new();
        for cc in all_ccs {
            let new_c = new_cc_counts.get(cc).copied().unwrap_or(0);
            let old_c = old_cc_counts.get(cc).copied().unwrap_or(0);
            if new_c != old_c {
                let d = (new_c as i64) - (old_c as i64);
                deltas.push((cc.to_string(), d, new_c));
            }
        }
        deltas.sort_by(|a, b| {
            b.1.unsigned_abs()
                .cmp(&a.1.unsigned_abs())
                .then_with(|| a.0.cmp(&b.0))
        });
        top_cc_tuples = deltas.into_iter().take(5).collect();
    }

    let sample_new_json: Vec<Value> = sample_new.iter().map(|(_, _, v)| v.clone()).collect();
    let top_cc_json: Vec<Value> = top_cc_tuples
        .iter()
        .map(|(cc, d, tot)| {
            json!({
                "country_code": cc,
                "net_range_delta": d,
                "total_ranges": tot,
            })
        })
        .collect();

    let diff_summary = json!({
        "previous_version": previous_version,
        "datasets": Value::Object(datasets_json),
        "asn_summary": {
            "active_asns": active_asns,
            "newly_announced": if has_prev_blobs { Some(added_asns.len()) } else { None },
            "withdrawn": if has_prev_blobs { Some(removed_asns.len()) } else { None },
            "organization_updates": if has_prev_blobs { Some(renamed_orgs) } else { None },
            "sample_new_asns": sample_new_json,
        },
        "country_summary": {
            "active_countries": active_countries,
            "top_changed_countries": top_cc_json,
        },
    });

    let mut md: Vec<String> = Vec::new();
    if let Some(note) = operator_note {
        let trimmed = note.trim();
        if !trimmed.is_empty() {
            md.push("> [!IMPORTANT]".to_string());
            for line in split_splitlines(trimmed) {
                md.push(format!("> {line}"));
            }
            md.push(String::new());
        }
    }

    let baseline = match previous_version {
        Some(pv) if !pv.is_empty() => format!("`{pv}`"),
        _ => "Initial Release".to_string(),
    };

    md.push(format!("## DGIP Dataset Release `{}`", packaged.version));
    md.push(String::new());
    md.push(format!("- **Released (UTC):** `{}`", packaged.released_iso));
    md.push(format!("- **Comparison Baseline:** {baseline}"));
    md.push(format!(
        "- **Active Globally Routed ASNs:** `{}`",
        format_usize_commas(active_asns)
    ));
    md.push(format!(
        "- **Countries & Territories Covered:** `{}`",
        format_usize_commas(active_countries)
    ));
    md.push(String::new());
    md.push("### Range Table Summary".to_string());
    md.push(String::new());
    md.push("| Table | Intervals | Churn (`+Added / -Removed`) | Net Delta | Size |".to_string());
    md.push("| :--- | ---: | ---: | ---: | ---: |".to_string());

    for (fname, _) in &table_specs {
        let d = &dataset_metrics[*fname];
        let churn = match (d.ranges_added, d.ranges_removed) {
            (Some(add_n), Some(rem_n)) => {
                format!(
                    "+{} / -{}",
                    format_usize_commas(add_n),
                    format_usize_commas(rem_n)
                )
            }
            _ => "Baseline".to_string(),
        };
        let delta_str = match d.net_delta {
            Some(nd) => format_i64_signed_commas(nd),
            None => "Baseline".to_string(),
        };
        md.push(format!(
            "| `{fname}` | {} | {churn} | {delta_str} | {} |",
            format_usize_commas(d.rows),
            human_bytes(d.size_bytes)
        ));
    }

    if has_prev_blobs {
        md.push(String::new());
        md.push("### Routing & Allocation Changes".to_string());
        md.push(format!(
            "- **ASN Deltas:** `+{}` newly announced, `-{}` withdrawn, `{}` organization name updates.",
            format_usize_commas(added_asns.len()),
            format_usize_commas(removed_asns.len()),
            format_usize_commas(renamed_orgs)
        ));
        if !sample_new.is_empty() {
            let sample_txt = sample_new
                .iter()
                .take(6)
                .map(|(code, org, _)| format!("`{code}` ({org})"))
                .collect::<Vec<_>>()
                .join(", ");
            md.push(format!("- **Sample Newly Announced ASNs:** {sample_txt}"));
        }
        if !top_cc_tuples.is_empty() {
            let cc_txt = top_cc_tuples
                .iter()
                .map(|(cc, d, _)| format!("`{cc}` ({})", format_i64_signed_commas(*d)))
                .collect::<Vec<_>>()
                .join(", ");
            md.push(format!("- **Largest Country Interval Deltas:** {cc_txt}"));
        }
    }

    let mut all_checksums: Vec<(String, usize, String)> =
        Vec::with_capacity(3 + packaged.dataset_artifacts.len());
    all_checksums.push((
        "bundle.tar.gz".to_string(),
        packaged.bundle_bytes.len(),
        packaged.bundle_sha256.clone(),
    ));
    all_checksums.push((
        "manifest.json".to_string(),
        packaged.manifest_bytes.len(),
        packaged.manifest_sha256.clone(),
    ));
    all_checksums.push((
        "SHA256SUMS.txt".to_string(),
        packaged.sha256sums_bytes.len(),
        packaged.sha256sums_sha256.clone(),
    ));
    for (fname, art) in &packaged.dataset_artifacts {
        all_checksums.push((fname.clone(), art.payload.len(), art.sha256.clone()));
    }
    all_checksums.sort_by(|a, b| a.0.cmp(&b.0));

    md.push(String::new());
    md.push("### Release Artifacts (`SHA-256`)".to_string());
    md.push(String::new());
    md.push("| Artifact | Size | SHA-256 |".to_string());
    md.push("| :--- | ---: | :--- |".to_string());
    for (fname, sz, sha) in &all_checksums {
        md.push(format!("| `{fname}` | {} | `{sha}` |", human_bytes(*sz)));
    }

    md.push(String::new());
    md.push("### Verification & Data Sources".to_string());
    md.push("- Verify checksums with `sha256sum --ignore-missing -c SHA256SUMS.txt` or `python3 scripts/verify_snapshot.py --dir .`.".to_string());
    md.push("- Verify GitHub OIDC build provenance with `gh attestation verify bundle.tar.gz --repo daviante-org/dgip-data`.".to_string());
    md.push(format!("- {source_attribution}"));
    md.push(String::new());

    Ok(ReleaseDiffAndNotes {
        diff_summary,
        release_notes_md: md.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_from_registry_inputs, package_standard_snapshot};
    use crate::enrichment::{
        GeoAttr, RawSecurityIntervalV4, RawSecurityIntervalV6, SEC_CDN, SEC_CLOUD, SEC_DATACENTER,
        SEC_THREAT,
    };
    use crate::ip_utils::FALLBACK_SPECIAL_RANGES;
    use crate::seed_data::DEFAULT_SOURCE_ATTRIBUTION;
    use chrono::TimeZone;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_iso_week_version_and_release_title() {
        let dt = Utc.with_ymd_and_hms(2026, 11, 2, 12, 0, 0).unwrap();
        assert_eq!(format_iso_week_version(dt, &[], "v"), "v2026.W45");
        assert_eq!(
            format_iso_week_version(dt, &["v2026.W45".to_string()], "v"),
            "v2026.W45.1"
        );
        assert_eq!(
            format_iso_week_version(
                dt,
                &[
                    "v2026.W45".to_string(),
                    "v2026.W45.1".to_string(),
                    "v2026.W45.4".to_string(),
                    "v2026.W45.rc1".to_string(),
                ],
                "v"
            ),
            "v2026.W45.5"
        );

        // ISO week boundary check: 2026-12-31 is ISO 2026-W53; 2027-01-01 is also ISO 2026-W53
        let dt_nye = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(format_iso_week_version(dt_nye, &[], "v"), "v2026.W53");

        assert_eq!(
            format_release_title("DGIP Weekly Snapshot {version} ({date})", "v2026.W45", dt),
            "DGIP Weekly Snapshot v2026.W45 (2026-11-02)"
        );
        assert_eq!(
            format_release_title("{{escaped}} {version}", "v2026.W45", dt),
            "{escaped} v2026.W45"
        );
        assert_eq!(
            format_release_title("Invalid {unknown}", "v2026.W45", dt),
            "v2026.W45"
        );
        assert_eq!(
            format_release_title("Broken {brace", "v2026.W45", dt),
            "v2026.W45"
        );
    }

    #[test]
    fn test_number_and_byte_formatting() {
        assert_eq!(format_u64_commas(0), "0");
        assert_eq!(format_u64_commas(999), "999");
        assert_eq!(format_u64_commas(1_000), "1,000");
        assert_eq!(format_u64_commas(1_234_567), "1,234,567");
        assert_eq!(format_i64_signed_commas(0), "+0");
        assert_eq!(format_i64_signed_commas(12_345), "+12,345");
        assert_eq!(format_i64_signed_commas(-12_345), "-12,345");

        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(1_572_864), "1.50 MB");
    }

    #[test]
    fn test_baseline_and_incremental_diff_release_notes() {
        let (ref v4_sp, ref v6_sp) = *FALLBACK_SPECIAL_RANGES;
        let s_888 = u32::from(Ipv4Addr::new(8, 8, 8, 0));
        let s_36 = u32::from(Ipv4Addr::new(3, 6, 0, 0));
        let e_36 = u32::from(Ipv4Addr::new(3, 6, 255, 255));
        let s_111 = u32::from(Ipv4Addr::new(1, 1, 1, 0));
        let s_v6 = u128::from("2606:4700:4700::".parse::<Ipv6Addr>().unwrap());
        let e_v6 = s_v6 + ((1u128 << (128 - 48)) - 1);

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
        country_details.insert(
            "AU".to_string(),
            (
                "Australia".to_string(),
                "OC".to_string(),
                "Oceania".to_string(),
            ),
        );

        let mut orgs_v1 = HashMap::new();
        orgs_v1.insert(15169, "Google Inc.".to_string());
        orgs_v1.insert(13335, "Cloudflare, Inc.".to_string());

        let tables_v1 = compile_from_registry_inputs(
            &[(s_888, 24, "US".to_string())],
            &[(s_v6, 48, "US".to_string())],
            &[(s_888, 24, 15169, "valid".to_string())],
            &[(s_v6, 48, 13335, "valid".to_string())],
            &orgs_v1,
            &HashMap::new(),
            &[],
            &[],
            &[RawSecurityIntervalV4 {
                start: s_888,
                end: s_888,
                flags: SEC_THREAT,
                provider: String::new(),
                threat_feed: "feodo_c2".to_string(),
            }],
            &[RawSecurityIntervalV6 {
                start: s_v6,
                end: e_v6,
                flags: SEC_CDN | SEC_CLOUD,
                provider: "cloudflare".to_string(),
                threat_feed: String::new(),
            }],
            v4_sp,
            v6_sp,
        )
        .unwrap();

        let dt_v1 = Utc.with_ymd_and_hms(2026, 10, 26, 12, 0, 0).unwrap();
        let pkg_v1 = package_standard_snapshot(
            &tables_v1,
            "v2026.W44",
            "v2026.W44",
            dt_v1,
            None,
            DEFAULT_SOURCE_ATTRIBUTION,
            &country_details,
        )
        .unwrap();

        let base_notes = compute_diff_and_release_notes(
            &pkg_v1,
            &tables_v1,
            None,
            None,
            None,
            DEFAULT_SOURCE_ATTRIBUTION,
            Some("Bootstrap cut\nVerified."),
        )
        .unwrap();

        assert!(base_notes
            .release_notes_md
            .contains("> [!IMPORTANT]\n> Bootstrap cut\n> Verified."));
        assert!(base_notes
            .release_notes_md
            .contains("- **Comparison Baseline:** Initial Release"));
        assert!(base_notes
            .release_notes_md
            .contains("| `dgip-asn-ipv4.csv.gz` | 1 | Baseline | Baseline |"));
        assert!(base_notes.release_notes_md.ends_with('\n'));
        assert!(base_notes.diff_summary["asn_summary"]["newly_announced"].is_null());

        // Build v2 with 1 renamed org (15169 -> Google LLC), 2 new ASNs (4755, 16509), and new IN/AU country intervals
        let mut orgs_v2 = HashMap::new();
        orgs_v2.insert(15169, "Google LLC".to_string());
        orgs_v2.insert(16509, "Amazon.com, Inc.".to_string());
        orgs_v2.insert(13335, "Cloudflare, Inc.".to_string());
        orgs_v2.insert(4755, String::new()); // Unlisted org check

        let tables_v2 = compile_from_registry_inputs(
            &[
                (s_888, 24, "US".to_string()),
                (s_36, 16, "US".to_string()),
                (s_111, 24, "AU".to_string()),
            ],
            &[(s_v6, 48, "US".to_string())],
            &[
                (s_888, 24, 15169, "valid".to_string()),
                (s_36, 16, 16509, "valid".to_string()),
                (s_111, 24, 4755, "unknown".to_string()),
            ],
            &[(s_v6, 48, 13335, "valid".to_string())],
            &orgs_v2,
            &HashMap::new(),
            &[(s_36, e_36, GeoAttr::new("IN", "IN-MH", "Mumbai", "geofeed"))],
            &[],
            &[RawSecurityIntervalV4 {
                start: s_36,
                end: e_36,
                flags: SEC_CLOUD | SEC_DATACENTER,
                provider: "aws".to_string(),
                threat_feed: String::new(),
            }],
            &[RawSecurityIntervalV6 {
                start: s_v6,
                end: e_v6,
                flags: SEC_CDN | SEC_CLOUD,
                provider: "cloudflare".to_string(),
                threat_feed: String::new(),
            }],
            v4_sp,
            v6_sp,
        )
        .unwrap();

        let dt_v2 = Utc.with_ymd_and_hms(2026, 11, 2, 12, 0, 0).unwrap();
        let pkg_v2 = package_standard_snapshot(
            &tables_v2,
            "v2026.W45",
            "v2026.W45",
            dt_v2,
            Some("v2026.W44"),
            DEFAULT_SOURCE_ATTRIBUTION,
            &country_details,
        )
        .unwrap();

        let mut prev_gz: HashMap<String, Vec<u8>> = HashMap::new();
        for fname in [
            ASN_IPV4_FILENAME,
            ASN_IPV6_FILENAME,
            COUNTRY_IPV4_FILENAME,
            COUNTRY_IPV6_FILENAME,
            SECURITY_IPV4_FILENAME,
            SECURITY_IPV6_FILENAME,
        ] {
            prev_gz.insert(
                fname.to_string(),
                pkg_v1.dataset_artifacts[fname].payload.clone(),
            );
        }

        let prev_counts = tables_v1.row_counts();
        let diff_notes = compute_diff_and_release_notes(
            &pkg_v2,
            &tables_v2,
            Some("v2026.W44"),
            Some(&prev_gz),
            Some(&prev_counts),
            DEFAULT_SOURCE_ATTRIBUTION,
            None,
        )
        .unwrap();

        assert_eq!(diff_notes.diff_summary["previous_version"], "v2026.W44");
        assert_eq!(diff_notes.diff_summary["asn_summary"]["active_asns"], 4);
        assert_eq!(diff_notes.diff_summary["asn_summary"]["newly_announced"], 2);
        assert_eq!(diff_notes.diff_summary["asn_summary"]["withdrawn"], 0);
        assert_eq!(
            diff_notes.diff_summary["asn_summary"]["organization_updates"],
            1
        );
        assert!(diff_notes.release_notes_md.contains(
            "- **Sample Newly Announced ASNs:** `AS4755` (Unlisted), `AS16509` (Amazon.com, Inc.)"
        ));
        assert!(diff_notes
            .release_notes_md
            .contains("- **Largest Country Interval Deltas:** `AU` (+1), `IN` (+1)"));
    }
}
