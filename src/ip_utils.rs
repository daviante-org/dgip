//! RFC-compliant IP parsing, special-purpose range classification, XFF extraction, and SSRF validation.

use crate::seed_data::DEFAULT_SPECIAL_RANGES;
use crate::types::{
    format_ipv4, format_ipv6, DgipError, DgipResult, IpNet, SpecialRangeRuleV4, SpecialRangeRuleV6,
};
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIp {
    pub canonical: String,
    pub version: u8,
    pub v4_int: u32,
    pub v6_int: u128,
    pub is_ipv4_mapped: bool,
    pub is_bogon: bool,
    pub bogon_type: Option<String>,
}

pub fn compile_special_ranges<'a, I>(rows: I) -> (Vec<SpecialRangeRuleV4>, Vec<SpecialRangeRuleV6>)
where
    I: IntoIterator<Item = (&'a str, i16, &'a str, i16)>,
{
    let mut v4_list: Vec<(i16, i16, SpecialRangeRuleV4)> = Vec::new();
    let mut v6_list: Vec<(i16, i16, SpecialRangeRuleV6)> = Vec::new();

    for (cidr, ip_ver, category, priority) in rows {
        let Ok(net) = IpNet::parse_non_strict(cidr) else {
            continue;
        };
        if i16::from(net.version()) != ip_ver {
            continue;
        }
        let neg_plen = -i16::from(net.prefix_len());
        match net {
            IpNet::V4 {
                network, broadcast, ..
            } => {
                v4_list.push((
                    priority,
                    neg_plen,
                    SpecialRangeRuleV4 {
                        start_int: network,
                        end_int: broadcast,
                        category: category.to_string(),
                        priority,
                    },
                ));
            }
            IpNet::V6 {
                network, broadcast, ..
            } => {
                v6_list.push((
                    priority,
                    neg_plen,
                    SpecialRangeRuleV6 {
                        start_int: network,
                        end_int: broadcast,
                        category: category.to_string(),
                        priority,
                    },
                ));
            }
        }
    }

    v4_list.sort_by_key(|(prio, neg_plen, _)| (*prio, *neg_plen));
    v6_list.sort_by_key(|(prio, neg_plen, _)| (*prio, *neg_plen));

    (
        v4_list.into_iter().map(|(_, _, r)| r).collect(),
        v6_list.into_iter().map(|(_, _, r)| r).collect(),
    )
}

pub static FALLBACK_SPECIAL_RANGES: Lazy<(Vec<SpecialRangeRuleV4>, Vec<SpecialRangeRuleV6>)> =
    Lazy::new(|| {
        compile_special_ranges(
            DEFAULT_SPECIAL_RANGES
                .iter()
                .map(|&(cidr, ver, cat, _rfc, prio)| (cidr, ver, cat, prio)),
        )
    });

#[inline]
pub fn classify_special_v4(ip_int: u32, rules: &[SpecialRangeRuleV4]) -> Option<&str> {
    for r in rules {
        if ip_int >= r.start_int && ip_int <= r.end_int {
            return Some(r.category.as_str());
        }
    }
    None
}

#[inline]
pub fn classify_special_v6(ip_int: u128, rules: &[SpecialRangeRuleV6]) -> Option<&str> {
    for r in rules {
        if ip_int >= r.start_int && ip_int <= r.end_int {
            return Some(r.category.as_str());
        }
    }
    None
}

/// Unwrap RFC 4291 IPv4-mapped IPv6 addresses (`::ffff:0:0/96`).
#[inline]
fn unwrap_ipv4_mapped(v6: Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let raw = u128::from(v6);
    if (raw >> 32) == 0xFFFF {
        Some(std::net::Ipv4Addr::from((raw & 0xFFFF_FFFF) as u32))
    } else {
        None
    }
}

pub fn parse_and_classify_ip(
    raw: &str,
    v4_rules: Option<&[SpecialRangeRuleV4]>,
    v6_rules: Option<&[SpecialRangeRuleV6]>,
) -> DgipResult<ParsedIp> {
    let cleaned = raw.trim();
    if cleaned.is_empty() || cleaned.len() > 64 || cleaned.contains('%') || cleaned.contains('/') {
        return Err(DgipError::InvalidIp(format!(
            "Invalid IPv4 or IPv6 address literal: {raw:?}"
        )));
    }

    let addr: IpAddr = cleaned.parse().map_err(|_| {
        DgipError::InvalidIp(format!("Invalid IPv4 or IPv6 address literal: {raw:?}"))
    })?;

    let v4_r = v4_rules.unwrap_or_else(|| &FALLBACK_SPECIAL_RANGES.0);
    let v6_r = v6_rules.unwrap_or_else(|| &FALLBACK_SPECIAL_RANGES.1);

    match addr {
        IpAddr::V4(v4) => {
            let v4_int = u32::from(v4);
            let bogon = classify_special_v4(v4_int, v4_r).map(str::to_string);
            Ok(ParsedIp {
                canonical: format_ipv4(v4_int),
                version: 4,
                v4_int,
                v6_int: 0,
                is_ipv4_mapped: false,
                is_bogon: bogon.is_some(),
                bogon_type: bogon,
            })
        }
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = unwrap_ipv4_mapped(v6) {
                let v4_int = u32::from(mapped_v4);
                let bogon = classify_special_v4(v4_int, v4_r).map(str::to_string);
                Ok(ParsedIp {
                    canonical: format_ipv4(v4_int),
                    version: 4,
                    v4_int,
                    v6_int: 0,
                    is_ipv4_mapped: true,
                    is_bogon: bogon.is_some(),
                    bogon_type: bogon,
                })
            } else {
                let v6_int = u128::from(v6);
                let bogon = classify_special_v6(v6_int, v6_r).map(str::to_string);
                Ok(ParsedIp {
                    canonical: format_ipv6(v6_int),
                    version: 6,
                    v4_int: 0,
                    v6_int,
                    is_ipv4_mapped: false,
                    is_bogon: bogon.is_some(),
                    bogon_type: bogon,
                })
            }
        }
    }
}

fn parse_normalized_ip(raw: &str) -> Option<(IpAddr, String)> {
    let addr: IpAddr = raw.trim().parse().ok()?;
    match addr {
        IpAddr::V4(v4) => Some((IpAddr::V4(v4), format_ipv4(u32::from(v4)))),
        IpAddr::V6(v6) => {
            if let Some(mapped) = unwrap_ipv4_mapped(v6) {
                Some((IpAddr::V4(mapped), format_ipv4(u32::from(mapped))))
            } else {
                Some((IpAddr::V6(v6), format_ipv6(u128::from(v6))))
            }
        }
    }
}

pub fn extract_client_ip(
    peer_host: &str,
    xff_header: Option<&str>,
    trusted_proxies: &[IpNet],
) -> String {
    let Some((peer_ip, peer_canon)) = parse_normalized_ip(peer_host) else {
        return "127.0.0.1".to_string();
    };

    let Some(xff) = xff_header else {
        return peer_canon;
    };
    if trusted_proxies.is_empty() {
        return peer_canon;
    }
    if !trusted_proxies.iter().any(|net| net.contains_ip(peer_ip)) {
        return peer_canon;
    }

    let hops: Vec<&str> = xff
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if hops.is_empty() {
        return peer_canon;
    }

    for &raw_hop in hops.iter().rev() {
        let Some((hop_ip, hop_canon)) = parse_normalized_ip(raw_hop) else {
            return peer_canon;
        };
        if !trusted_proxies.iter().any(|net| net.contains_ip(hop_ip)) {
            return hop_canon;
        }
    }

    if let Some((_, first_canon)) = parse_normalized_ip(hops[0]) {
        first_canon
    } else {
        peer_canon
    }
}

pub fn verify_public_upstream_host(
    hostname: &str,
    v4_rules: &[SpecialRangeRuleV4],
    v6_rules: &[SpecialRangeRuleV6],
) -> DgipResult<Vec<std::net::SocketAddr>> {
    let addrs: Vec<std::net::SocketAddr> = (hostname, 443u16)
        .to_socket_addrs()
        .map_err(|e| {
            DgipError::Compilation(format!("Unable to resolve upstream host {hostname:?}: {e}"))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(DgipError::Compilation(format!(
            "Upstream host {hostname:?} resolved to zero addresses."
        )));
    }

    for sa in &addrs {
        let ip_str = sa.ip().to_string();
        let parsed = parse_and_classify_ip(&ip_str, Some(v4_rules), Some(v6_rules))?;
        if parsed.is_bogon {
            return Err(DgipError::Compilation(format!(
                "SSRF protection blocked {hostname:?} resolving to non-global IP {} ({}).",
                parsed.canonical,
                parsed.bogon_type.as_deref().unwrap_or("bogon")
            )));
        }
    }

    Ok(addrs)
}
