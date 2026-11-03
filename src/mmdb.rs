//! MaxMind DB Binary Format v2.0 (MMDB) dual-stack writer.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{SystemTime, UNIX_EPOCH};

pub const METADATA_START_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

const TYPE_UTF8_STRING: u8 = 2;
const TYPE_UINT16: u8 = 5;
const TYPE_UINT32: u8 = 6;
const TYPE_MAP: u8 = 7;
const TYPE_UINT64: u8 = 9;
const TYPE_ARRAY: u8 = 11;
const TYPE_BOOLEAN: u8 = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmdbValue {
    Str(String),
    Bool(bool),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Array(Vec<MmdbValue>),
    Map(BTreeMap<String, MmdbValue>),
}

/// Decompose an inclusive IPv4 `[start, end]` interval into minimal exact `(network, prefixlen)` blocks.
pub fn iter_range_cidrs_v4(start: u32, end: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    let mut cur = u64::from(start);
    let end64 = u64::from(end);
    while cur <= end64 {
        let tz = if cur == 0 {
            32u32
        } else {
            (cur as u32).trailing_zeros()
        };
        let rem = end64 - cur + 1;
        let rem_bits = 63 - rem.leading_zeros();
        let k = tz.min(rem_bits);
        out.push((cur as u32, (32 - k) as u8));
        cur += 1u64 << k;
    }
    out
}

/// Decompose an inclusive IPv6 `[start, end]` interval into minimal exact `(network, prefixlen)` blocks.
pub fn iter_range_cidrs_v6(start: u128, end: u128) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    let mut cur = start;
    loop {
        let tz = if cur == 0 {
            128u32
        } else {
            cur.trailing_zeros()
        };
        let diff = end - cur; // rem - 1
        let rem_bits = if diff == u128::MAX {
            128u32
        } else {
            let rem = diff + 1;
            127 - rem.leading_zeros()
        };
        let k = tz.min(rem_bits);
        out.push((cur, (128 - k) as u8));
        if k == 128 {
            break;
        }
        let step = 1u128 << k;
        if end - cur < step {
            break;
        }
        cur += step;
    }
    out
}

fn encode_header(out: &mut Vec<u8>, type_num: u8, size: usize) {
    let (size_bits, extra): (u8, &[u8]) = if size < 29 {
        (size as u8, &[])
    } else if size < 285 {
        let b = [(size - 29) as u8];
        if type_num < 8 {
            out.push((type_num << 5) | 29);
        } else {
            out.push(29);
            out.push(type_num - 7);
        }
        out.extend_from_slice(&b);
        return;
    } else if size < 65_821 {
        let v = (size - 285) as u16;
        let b = v.to_be_bytes();
        if type_num < 8 {
            out.push((type_num << 5) | 30);
        } else {
            out.push(30);
            out.push(type_num - 7);
        }
        out.extend_from_slice(&b);
        return;
    } else {
        let v = (size - 65_821) as u32;
        let b = [
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        ];
        if type_num < 8 {
            out.push((type_num << 5) | 31);
        } else {
            out.push(31);
            out.push(type_num - 7);
        }
        out.extend_from_slice(&b);
        return;
    };

    if type_num < 8 {
        out.push((type_num << 5) | size_bits);
    } else {
        out.push(size_bits);
        out.push(type_num - 7);
    }
    out.extend_from_slice(extra);
}

fn encode_uint(out: &mut Vec<u8>, type_num: u8, value: u64) {
    if value == 0 {
        encode_header(out, type_num, 0);
        return;
    }
    let be = value.to_be_bytes();
    let first_non_zero = be.iter().position(|&b| b != 0).unwrap_or(7);
    let slice = &be[first_non_zero..];
    encode_header(out, type_num, slice.len());
    out.extend_from_slice(slice);
}

pub fn encode_mmdb_value(out: &mut Vec<u8>, val: &MmdbValue) {
    match val {
        MmdbValue::Bool(b) => {
            out.push(u8::from(*b));
            out.push(TYPE_BOOLEAN - 7);
        }
        MmdbValue::Uint16(v) => encode_uint(out, TYPE_UINT16, u64::from(*v)),
        MmdbValue::Uint32(v) => encode_uint(out, TYPE_UINT32, u64::from(*v)),
        MmdbValue::Uint64(v) => encode_uint(out, TYPE_UINT64, *v),
        MmdbValue::Str(s) => {
            let bytes = s.as_bytes();
            encode_header(out, TYPE_UTF8_STRING, bytes.len());
            out.extend_from_slice(bytes);
        }
        MmdbValue::Array(items) => {
            encode_header(out, TYPE_ARRAY, items.len());
            for item in items {
                encode_mmdb_value(out, item);
            }
        }
        MmdbValue::Map(map) => {
            encode_header(out, TYPE_MAP, map.len());
            for (k, v) in map {
                let kb = k.as_bytes();
                encode_header(out, TYPE_UTF8_STRING, kb.len());
                out.extend_from_slice(kb);
                encode_mmdb_value(out, v);
            }
        }
    }
}

fn insert_prefix_v6(
    left: &mut Vec<i32>,
    right: &mut Vec<i32>,
    root_idx: usize,
    net_int: u128,
    prefixlen: u8,
    leaf_code: i32,
) {
    if prefixlen == 0 {
        return;
    }
    let mut curr = root_idx;
    let stop_bit = 128 - usize::from(prefixlen);
    for bit_pos in ((stop_bit + 1)..128).rev() {
        let bit = ((net_int >> bit_pos) & 1) == 1;
        let mut nxt = if bit { right[curr] } else { left[curr] };
        if nxt < 0 {
            let existing = nxt;
            nxt = left.len() as i32;
            left.push(existing);
            right.push(existing);
            if bit {
                right[curr] = nxt;
            } else {
                left[curr] = nxt;
            }
        }
        curr = nxt as usize;
    }
    let last_bit = ((net_int >> stop_bit) & 1) == 1;
    if last_bit {
        right[curr] = leaf_code;
    } else {
        left[curr] = leaf_code;
    }
}

fn insert_prefix_v4(
    left: &mut Vec<i32>,
    right: &mut Vec<i32>,
    root_idx: usize,
    net_int: u32,
    prefixlen: u8,
    leaf_code: i32,
) {
    if prefixlen == 0 {
        return;
    }
    let mut curr = root_idx;
    let stop_bit = 32 - usize::from(prefixlen);
    for bit_pos in ((stop_bit + 1)..32).rev() {
        let bit = ((net_int >> bit_pos) & 1) == 1;
        let mut nxt = if bit { right[curr] } else { left[curr] };
        if nxt < 0 {
            let existing = nxt;
            nxt = left.len() as i32;
            left.push(existing);
            right.push(existing);
            if bit {
                right[curr] = nxt;
            } else {
                left[curr] = nxt;
            }
        }
        curr = nxt as usize;
    }
    let last_bit = ((net_int >> stop_bit) & 1) == 1;
    if last_bit {
        right[curr] = leaf_code;
    } else {
        left[curr] = leaf_code;
    }
}

fn ensure_branch_path(
    left: &mut Vec<i32>,
    right: &mut Vec<i32>,
    root_idx: usize,
    bits: &[u8],
    target_node: i32,
) {
    let mut curr = root_idx;
    for &b in &bits[..bits.len() - 1] {
        let bit = b != 0;
        let mut nxt = if bit { right[curr] } else { left[curr] };
        if nxt < 0 {
            let existing = nxt;
            nxt = left.len() as i32;
            left.push(existing);
            right.push(existing);
            if bit {
                right[curr] = nxt;
            } else {
                left[curr] = nxt;
            }
        }
        curr = nxt as usize;
    }
    if bits[bits.len() - 1] != 0 {
        right[curr] = target_node;
    } else {
        left[curr] = target_node;
    }
}

pub fn build_dual_stack_mmdb<K: Eq + Hash + Clone>(
    database_type: &str,
    description_en: &str,
    v4_intervals: &[(u32, u32, K)],
    v6_intervals: &[(u128, u128, K)],
    ordered_records: &[(K, MmdbValue)],
    build_epoch: Option<u64>,
    force_record_size: Option<u16>,
) -> Vec<u8> {
    let mut data_buf = Vec::new();
    let mut key_to_leaf: HashMap<K, i32> = HashMap::with_capacity(ordered_records.len());

    for (key, rec) in ordered_records {
        if key_to_leaf.contains_key(key) {
            continue;
        }
        let offset = data_buf.len() as i32;
        encode_mmdb_value(&mut data_buf, rec);
        key_to_leaf.insert(key.clone(), -(2 + offset));
    }

    let mut left: Vec<i32> = vec![-1];
    let mut right: Vec<i32> = vec![-1];

    let v4_mapped_start: u128 = 0xFFFF_0000_0000;
    let v4_mapped_end: u128 = 0xFFFF_FFFF_FFFF;

    for (s_int, e_int, key) in v6_intervals {
        let Some(&leaf) = key_to_leaf.get(key) else {
            continue;
        };
        if *e_int <= 0xFFFF_FFFF || (*s_int >= v4_mapped_start && *e_int <= v4_mapped_end) {
            continue;
        }
        for (net_int, plen) in iter_range_cidrs_v6(*s_int, *e_int) {
            insert_prefix_v6(&mut left, &mut right, 0, net_int, plen, leaf);
        }
    }

    if !v4_intervals.is_empty() {
        let v4_root = left.len();
        left.push(-1);
        right.push(-1);
        for (s_int, e_int, key) in v4_intervals {
            let Some(&leaf) = key_to_leaf.get(key) else {
                continue;
            };
            for (net_int, plen) in iter_range_cidrs_v4(*s_int, *e_int) {
                insert_prefix_v4(&mut left, &mut right, v4_root, net_int, plen, leaf);
            }
        }
        let zeros_96 = [0u8; 96];
        ensure_branch_path(&mut left, &mut right, 0, &zeros_96, v4_root as i32);
        let mut mapped_96 = [0u8; 96];
        for b in &mut mapped_96[80..96] {
            *b = 1;
        }
        ensure_branch_path(&mut left, &mut right, 0, &mapped_96, v4_root as i32);
    }

    let node_count = left.len();
    let max_ptr = node_count + 16 + data_buf.len();

    let record_size: u16 = if let Some(forced) = force_record_size {
        forced
    } else if max_ptr < (1 << 24) {
        24
    } else if max_ptr < (1 << 28) {
        28
    } else {
        32
    };

    let bytes_per_node = (usize::from(record_size) * 2) / 8;
    let mut tree_buf = vec![0u8; node_count * bytes_per_node];
    let data_base = (node_count + 16) as u32;
    let nc_u32 = node_count as u32;

    for idx in 0..node_count {
        let raw_l = left[idx];
        let raw_r = right[idx];
        let val_l: u32 = if raw_l == -1 {
            nc_u32
        } else if raw_l >= 0 {
            raw_l as u32
        } else {
            data_base + ((-raw_l - 2) as u32)
        };
        let val_r: u32 = if raw_r == -1 {
            nc_u32
        } else if raw_r >= 0 {
            raw_r as u32
        } else {
            data_base + ((-raw_r - 2) as u32)
        };

        let pos = idx * bytes_per_node;
        match record_size {
            24 => {
                tree_buf[pos] = ((val_l >> 16) & 0xFF) as u8;
                tree_buf[pos + 1] = ((val_l >> 8) & 0xFF) as u8;
                tree_buf[pos + 2] = (val_l & 0xFF) as u8;
                tree_buf[pos + 3] = ((val_r >> 16) & 0xFF) as u8;
                tree_buf[pos + 4] = ((val_r >> 8) & 0xFF) as u8;
                tree_buf[pos + 5] = (val_r & 0xFF) as u8;
            }
            28 => {
                tree_buf[pos] = ((val_l >> 16) & 0xFF) as u8;
                tree_buf[pos + 1] = ((val_l >> 8) & 0xFF) as u8;
                tree_buf[pos + 2] = (val_l & 0xFF) as u8;
                tree_buf[pos + 3] = ((((val_l >> 24) & 0x0F) << 4) | ((val_r >> 24) & 0x0F)) as u8;
                tree_buf[pos + 4] = ((val_r >> 16) & 0xFF) as u8;
                tree_buf[pos + 5] = ((val_r >> 8) & 0xFF) as u8;
                tree_buf[pos + 6] = (val_r & 0xFF) as u8;
            }
            32 => {
                tree_buf[pos..pos + 4].copy_from_slice(&val_l.to_be_bytes());
                tree_buf[pos + 4..pos + 8].copy_from_slice(&val_r.to_be_bytes());
            }
            other => panic!("Unsupported MMDB record_size: {other}"),
        }
    }

    let epoch = build_epoch.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let mut desc_map = BTreeMap::new();
    desc_map.insert("en".to_string(), MmdbValue::Str(description_en.to_string()));

    let mut meta = BTreeMap::new();
    meta.insert(
        "binary_format_major_version".to_string(),
        MmdbValue::Uint16(2),
    );
    meta.insert(
        "binary_format_minor_version".to_string(),
        MmdbValue::Uint16(0),
    );
    meta.insert("build_epoch".to_string(), MmdbValue::Uint64(epoch));
    meta.insert(
        "database_type".to_string(),
        MmdbValue::Str(database_type.to_string()),
    );
    meta.insert("description".to_string(), MmdbValue::Map(desc_map));
    meta.insert("ip_version".to_string(), MmdbValue::Uint16(6));
    meta.insert(
        "languages".to_string(),
        MmdbValue::Array(vec![MmdbValue::Str("en".to_string())]),
    );
    meta.insert("node_count".to_string(), MmdbValue::Uint32(nc_u32));
    meta.insert("record_size".to_string(), MmdbValue::Uint16(record_size));

    let mut meta_bytes = Vec::new();
    encode_mmdb_value(&mut meta_bytes, &MmdbValue::Map(meta));

    let mut out = Vec::with_capacity(
        tree_buf.len() + 16 + data_buf.len() + METADATA_START_MARKER.len() + meta_bytes.len(),
    );
    out.extend_from_slice(&tree_buf);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&data_buf);
    out.extend_from_slice(METADATA_START_MARKER);
    out.extend_from_slice(&meta_bytes);
    out
}
