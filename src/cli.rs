//! Operational command-line interface (`dgip`) for the DGIP Network Intelligence Service.
//!
//! Replaces HTTP admin routes so the public HTTP server remains 100% read-only.
//! Supports container server execution (`dgip` / `dgip serve`), `FROM scratch` container
//! liveness healthchecks (`dgip healthcheck`), PostgreSQL operational management, and
//! standalone database-free dataset compilation (`dgip build-release`).

use crate::compiler::{compile_feed_payloads, package_standard_snapshot, CORE_FEED_KINDS};
use crate::config::Settings;
use crate::db::Database;
use crate::http::run_http_server;
use crate::ip_utils::FALLBACK_SPECIAL_RANGES;
use crate::models::{
    AllowedHostItem, FeedSourceItem, OperationalCatalogResponse, OperationalStatusResponse,
};
use crate::release_notes::{
    compute_diff_and_release_notes, format_iso_week_version, format_release_title,
};
use crate::seed_data::{
    build_default_feed_sources, DEFAULT_ALLOWED_HOSTS, DEFAULT_CONTINENTS, DEFAULT_COUNTRIES,
    DEFAULT_SOURCE_ATTRIBUTION,
};
use crate::sync::{
    download_https_bounded, rir_nro_mirror_url, SyncManager, PRIMARY_RIR_FAST_TIMEOUT_SECONDS,
};
use crate::types::{DgipError, DgipResult, FeedSourceSpec, VERSION};
use chrono::{DateTime, Utc};
use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_UPSTREAM_USER_AGENT: &str =
    "DGIP/1.0 (+https://daviante.org; mailto:code@daviante.org)";

/// DGIP Network Intelligence operational & dataset management CLI.
#[derive(Debug, Parser)]
#[command(
    name = "dgip",
    version = VERSION,
    about = "DGIP Network Intelligence operational & dataset management CLI."
)]
pub struct Cli {
    /// Emit detailed INFO progress logs to stderr.
    #[arg(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Commands {
    /// Start the read-only HTTP server and background scheduler (default when no subcommand is given).
    Serve,

    /// Probe `http://127.0.0.1:{port}/healthz/live` for `FROM scratch` container healthchecks.
    Healthcheck,

    /// Inspect active GiST slot, bootstrap state, sync/release timestamps, and cache status.
    Status {
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Refresh inactive Blue/Green lookup slot from official RIR & RIPE RIS feeds and flip atomically.
    Sync {
        /// Repopulate inactive slot even when upstream registry SHA-256 is unchanged.
        #[arg(long)]
        force: bool,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Compile and publish a multi-format dataset snapshot (CSV, Geofeed, MMDB v2.0) into PostgreSQL.
    Release {
        /// Cut a new snapshot version even when upstream data matches the latest snapshot.
        #[arg(long)]
        force: bool,
        /// Optional operator callout prepended to the Markdown release notes.
        #[arg(long)]
        note: Option<String>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Inspect PostgreSQL runtime catalog summary (config, feeds, SSRF allowlist, countries, CIDRs).
    Catalog {
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Inspect or update hot-reloaded runtime configuration in PostgreSQL (`dgip_config`).
    Config {
        #[command(subcommand)]
        cmd: ConfigCommands,
    },

    /// Manage upstream RIR and RIPE RIS registry feeds (`dgip_feed_sources`).
    Feed {
        #[command(subcommand)]
        cmd: FeedCommands,
    },

    /// Manage outbound HTTPS SSRF hostname allowlist (`dgip_allowed_hosts`).
    Host {
        #[command(subcommand)]
        cmd: HostCommands,
    },

    /// Compile a standalone dataset release onto local disk directly from RIR/RIPE feeds (no DB required).
    #[command(
        name = "build-release",
        visible_alias = "compile-local",
        disable_version_flag = true
    )]
    BuildRelease {
        /// Root output directory.
        #[arg(long = "output-dir")]
        output_dir: PathBuf,
        /// Optional explicit version tag.
        #[arg(long = "version")]
        version: Option<String>,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum ConfigCommands {
    /// List all runtime configuration entries.
    List {
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Get a single runtime configuration key.
    Get {
        /// Configuration key name.
        key: String,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate and persist one or more KEY=VALUE updates (hot-reloaded by running workers).
    Set {
        /// One or more KEY=VALUE pairs (e.g. rate_limit_per_minute=180 swagger_enabled=false).
        #[arg(required = true, num_args = 1.., value_name = "KEY=VALUE")]
        pairs: Vec<String>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum FeedCommands {
    /// List configured upstream registry feeds.
    List {
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Enable an upstream registry feed.
    Enable {
        /// Feed identifier (e.g. rir-arin, ris-bgp-ipv4).
        feed_key: String,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Disable an upstream registry feed.
    Disable {
        /// Feed identifier (e.g. rir-afrinic).
        feed_key: String,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Update the HTTPS source URL for a registry feed.
    #[command(name = "set-url")]
    SetUrl {
        /// Feed identifier.
        feed_key: String,
        /// New https:// feed URL.
        url: String,
        /// Optional minimum record count threshold.
        #[arg(long = "min-records")]
        min_records: Option<i32>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum HostCommands {
    /// List outbound HTTPS allowlist entries.
    List {
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add or enable an outbound HTTPS hostname.
    Allow {
        /// Exact FQDN (e.g. ftp.ripe.net).
        hostname: String,
        /// Optional operator note.
        #[arg(long)]
        notes: Option<String>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Disable an outbound HTTPS hostname in the allowlist.
    Deny {
        /// Exact FQDN to disable.
        hostname: String,
        /// Optional operator note.
        #[arg(long)]
        notes: Option<String>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Parse CLI arguments directly without exiting the process (used by unit tests and `run_cli`).
pub fn try_parse_cli_from<I, T>(itr: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(itr)
}

/// Parse a `key=value` CLI argument into a `(key, raw_or_parsed_value)` pair.
///
/// Supports scalar strings/numbers/booleans, JSON arrays/objects/strings, and ergonomic
/// comma-separated CIDRs for `trusted_proxies` (e.g. `trusted_proxies=10.0.0.0/8,172.16.0.0/12`
/// or `trusted_proxies=[]`).
pub fn parse_config_key_value(pair: &str) -> DgipResult<(String, Value)> {
    let Some((raw_key, raw_val)) = pair.split_once('=') else {
        return Err(DgipError::InvalidConfig(format!(
            "Expected KEY=VALUE syntax, got {pair:?} (example: rate_limit_per_minute=180)."
        )));
    };
    let key = raw_key.trim().to_string();
    if key.is_empty() {
        return Err(DgipError::InvalidConfig(format!(
            "Empty configuration key in {pair:?}."
        )));
    }

    let stripped = raw_val.trim();
    if key == "trusted_proxies" {
        if stripped.is_empty() || stripped == "[]" {
            return Ok((key, Value::Array(Vec::new())));
        }
        if stripped.starts_with('[') {
            let parsed: Value = serde_json::from_str(stripped).map_err(|exc| {
                DgipError::InvalidConfig(format!(
                    "Malformed JSON list for 'trusted_proxies': {exc}"
                ))
            })?;
            return Ok((key, parsed));
        }
        let items: Vec<Value> = stripped
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect();
        return Ok((key, Value::Array(items)));
    }

    if stripped.starts_with('[') || stripped.starts_with('{') || stripped.starts_with('"') {
        let parsed: Value = serde_json::from_str(stripped).map_err(|exc| {
            DgipError::InvalidConfig(format!("Malformed JSON value for {key:?}: {exc}"))
        })?;
        return Ok((key, parsed));
    }

    Ok((key, Value::String(raw_val.to_string())))
}

/// Route operational logs exclusively to `stderr` so `--json` `stdout` stays pure JSON.
fn configure_logging(info_level: bool) {
    let default_directive = if info_level { "info" } else { "warn" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .try_init();
}

fn fmt_dt(dt: Option<DateTime<Utc>>) -> String {
    match dt {
        Some(d) => d.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => "-".to_string(),
    }
}

fn fmt_commas_u64(val: u64) -> String {
    let s = val.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (idx, &ch) in bytes.iter().enumerate() {
        if idx > 0 && (bytes.len() - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(ch as char);
    }
    out
}

fn fmt_row_counts(counts: &HashMap<String, usize>) -> String {
    let mut sorted: Vec<(&String, &usize)> = counts.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .into_iter()
        .map(|(k, &v)| format!("{k}={}", fmt_commas_u64(v as u64)))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn cmd_healthcheck() -> i32 {
    let settings = Settings::from_env();
    let url = format!("http://127.0.0.1:{}/healthz/live", settings.port);
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
    else {
        return 1;
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status() == reqwest::StatusCode::OK => 0,
        _ => 1,
    }
}

async fn cmd_status(as_json: bool) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings)?;
    db.startup().await?;
    let outcome = async {
        let cat = db.ensure_catalog_fresh(true).await?;
        let state = db.get_state().await?;
        let blob_cnt = db.count_stored_blob_versions().await?;
        Ok::<OperationalStatusResponse, DgipError>(OperationalStatusResponse {
            service_version: VERSION.to_string(),
            initial_bootstrapped: state.initial_bootstrapped,
            active_slot: state.active_slot,
            live_updated_at: state.live_updated_at,
            live_row_counts: state.live_row_counts,
            active_version: state.active_version,
            catalog_version: cat.catalog_version,
            last_sync_attempt_at: state.last_sync_attempt_at,
            last_sync_success_at: state.last_sync_success_at,
            last_sync_error: state.last_sync_error,
            last_release_attempt_at: state.last_release_attempt_at,
            last_release_success_at: state.last_release_success_at,
            last_release_error: state.last_release_error,
            snapshot_retention: cat.snapshot_retention,
            stored_blob_versions: blob_cnt,
            local_cached_versions: db.list_local_cached_versions(),
        })
    }
    .await;
    db.shutdown().await;
    let status = outcome?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string())
        );
        return Ok(0);
    }

    println!("DGIP Service Status (v{})", status.service_version);
    println!("{}", "=".repeat(56));
    println!("  Bootstrapped          : {}", status.initial_bootstrapped);
    let slot_lbl = if status.active_slot.is_empty() {
        "(uninitialized)"
    } else {
        status.active_slot.as_str()
    };
    println!("  Active GiST Slot      : {slot_lbl}");
    println!(
        "  Active Snapshot       : {}",
        status.active_version.as_deref().unwrap_or("-")
    );
    println!("  Catalog Version       : {}", status.catalog_version);
    println!(
        "  Live Updated At       : {}",
        fmt_dt(status.live_updated_at)
    );
    if let Some(ref counts) = status.live_row_counts {
        if !counts.is_empty() {
            println!("  Live Row Counts       : {}", fmt_row_counts(counts));
        }
    }
    println!(
        "  Last Sync Attempt     : {}",
        fmt_dt(status.last_sync_attempt_at)
    );
    println!(
        "  Last Sync Success     : {}",
        fmt_dt(status.last_sync_success_at)
    );
    if let Some(ref err) = status.last_sync_error {
        if !err.is_empty() {
            println!("  Last Sync Error       : {err}");
        }
    }
    println!(
        "  Last Release Attempt  : {}",
        fmt_dt(status.last_release_attempt_at)
    );
    println!(
        "  Last Release Success  : {}",
        fmt_dt(status.last_release_success_at)
    );
    if let Some(ref err) = status.last_release_error {
        if !err.is_empty() {
            println!("  Last Release Error    : {err}");
        }
    }
    println!(
        "  Snapshot Blobs (PG)   : {} / retention={}",
        status.stored_blob_versions, status.snapshot_retention
    );
    let cached_str = if status.local_cached_versions.is_empty() {
        "-".to_string()
    } else {
        status.local_cached_versions.join(", ")
    };
    println!("  Local Disk Cache      : {cached_str}");
    Ok(0)
}

async fn cmd_sync(force: bool, as_json: bool) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings.clone())?;
    let sync_manager = SyncManager::new(settings, Arc::clone(&db));
    db.startup().await?;
    let outcome = sync_manager.run_live_sync(force).await;
    sync_manager.shutdown().await;
    db.shutdown().await;
    let res = outcome?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&res).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Sync status     : {}", res.status);
        let slot_str = res
            .active_slot
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("-");
        println!("Active slot     : {slot_str}");
        println!("Duration        : {:.2}s", res.duration_seconds);
        if let Some(ref counts) = res.live_row_counts {
            if !counts.is_empty() {
                println!("Live row counts : {}", fmt_row_counts(counts));
            }
        }
        println!("Detail          : {}", res.detail);
    }
    Ok(0)
}

async fn cmd_release(force: bool, note: Option<&str>, as_json: bool) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings.clone())?;
    let sync_manager = SyncManager::new(settings, Arc::clone(&db));
    db.startup().await?;
    let outcome = sync_manager.run_weekly_release(force, note).await;
    sync_manager.shutdown().await;
    db.shutdown().await;
    let res = outcome?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&res).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Release status  : {}", res.status);
        println!(
            "Version         : {}",
            res.version.as_deref().unwrap_or("-")
        );
        if let Some(ref prev) = res.previous_version {
            println!("Previous        : {prev}");
        }
        let slot_str = res
            .active_slot
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("-");
        println!("Active slot     : {slot_str}");
        println!("Duration        : {:.2}s", res.duration_seconds);
        if let Some(ref counts) = res.row_counts {
            if !counts.is_empty() {
                println!("Row counts      : {}", fmt_row_counts(counts));
            }
        }
        println!("Detail          : {}", res.detail);
    }
    Ok(0)
}

async fn cmd_catalog(as_json: bool) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings)?;
    db.startup().await?;
    let outcome = async {
        let cat = db.ensure_catalog_fresh(true).await?;
        Ok::<OperationalCatalogResponse, DgipError>(OperationalCatalogResponse {
            catalog_version: cat.catalog_version,
            config: cat.raw_config.clone(),
            feed_sources: cat.feed_sources.iter().map(FeedSourceItem::from).collect(),
            allowed_hosts: cat
                .allowed_host_rows
                .iter()
                .map(|(h, en, notes)| AllowedHostItem {
                    hostname: h.clone(),
                    enabled: *en,
                    notes: notes.clone(),
                })
                .collect(),
            active_continents_count: cat.continents_count,
            active_countries_count: cat.valid_country_codes.len(),
            active_special_ranges_count: cat.special_v4_rules.len() + cat.special_v6_rules.len(),
        })
    }
    .await;
    db.shutdown().await;
    let resp = outcome?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string())
        );
        return Ok(0);
    }

    let enabled_feeds = resp.feed_sources.iter().filter(|f| f.enabled).count();
    let enabled_hosts = resp.allowed_hosts.iter().filter(|h| h.enabled).count();
    println!("DGIP Runtime Catalog (version {})", resp.catalog_version);
    println!("{}", "=".repeat(56));
    println!("  Config Entries        : {}", resp.config.len());
    println!(
        "  Registry Feeds        : {enabled_feeds} enabled / {} total",
        resp.feed_sources.len()
    );
    println!(
        "  Allowed HTTPS Hosts   : {enabled_hosts} enabled / {} total",
        resp.allowed_hosts.len()
    );
    println!("  Active Continents     : {}", resp.active_continents_count);
    println!("  Active Countries      : {}", resp.active_countries_count);
    println!(
        "  Special CIDR Ranges   : {}",
        resp.active_special_ranges_count
    );
    Ok(0)
}

async fn cmd_config(cmd: ConfigCommands) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings)?;
    db.startup().await?;
    let outcome = async {
        match cmd {
            ConfigCommands::List { json } => {
                let cat = db.ensure_catalog_fresh(true).await?;
                let ordered: BTreeMap<String, Value> = cat
                    .raw_config
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if json {
                    let body = json!({
                        "catalog_version": cat.catalog_version,
                        "config": ordered,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "DGIP Configuration (catalog_version={}):",
                        cat.catalog_version
                    );
                    for (k, v) in &ordered {
                        println!(
                            "  {k} = {}",
                            serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
                        );
                    }
                }
                Ok(0)
            }
            ConfigCommands::Get { key, json } => {
                let cat = db.ensure_catalog_fresh(true).await?;
                let Some(val) = cat.raw_config.get(&key) else {
                    eprintln!("Error: Unknown configuration key {key:?}.");
                    return Ok(2);
                };
                if json {
                    let body = json!({
                        "key": key,
                        "value": val,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else if let Some(s) = val.as_str() {
                    println!("{s}");
                } else {
                    println!(
                        "{}",
                        serde_json::to_string(val).unwrap_or_else(|_| "null".to_string())
                    );
                }
                Ok(0)
            }
            ConfigCommands::Set { pairs, json } => {
                let mut updates: HashMap<String, Value> = HashMap::new();
                let mut key_order: Vec<String> = Vec::new();
                for pair in &pairs {
                    let (k, v) = parse_config_key_value(pair)?;
                    if !updates.contains_key(&k) {
                        key_order.push(k.clone());
                    }
                    updates.insert(k, v);
                }
                let cat = db.update_config_entries(&updates).await?;
                let mut applied = serde_json::Map::new();
                for k in &key_order {
                    let v = cat.raw_config.get(k).cloned().unwrap_or(Value::Null);
                    applied.insert(k.clone(), v);
                }
                if json {
                    let body = json!({
                        "status": "updated",
                        "catalog_version": cat.catalog_version,
                        "updated": applied,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Updated {} key(s) (catalog_version={}; running workers hot-reload automatically):",
                        applied.len(),
                        cat.catalog_version
                    );
                    for (k, v) in &applied {
                        println!(
                            "  {k} = {}",
                            serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
                        );
                    }
                }
                Ok(0)
            }
        }
    }
    .await;
    db.shutdown().await;
    outcome
}

async fn cmd_feed(cmd: FeedCommands) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings)?;
    db.startup().await?;
    let outcome = async {
        match cmd {
            FeedCommands::List { json } => {
                let cat = db.ensure_catalog_fresh(true).await?;
                let items: Vec<FeedSourceItem> =
                    cat.feed_sources.iter().map(FeedSourceItem::from).collect();
                if json {
                    let body = json!({
                        "catalog_version": cat.catalog_version,
                        "feeds": items,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Upstream Registry Feeds (catalog_version={}):",
                        cat.catalog_version
                    );
                    for f in &cat.feed_sources {
                        let state_lbl = if f.enabled { "ENABLED " } else { "DISABLED" };
                        let min_str = fmt_commas_u64(f.min_records.max(0) as u64);
                        println!(
                            "  [{state_lbl}] {:<14} ({}, min={min_str}) -> {}",
                            f.feed_key, f.kind, f.source_url
                        );
                    }
                }
                Ok(0)
            }
            FeedCommands::Enable { feed_key, json } => {
                let cat = db
                    .set_feed_source(&feed_key, Some(true), None, None)
                    .await?;
                if json {
                    let body = json!({
                        "status": "updated",
                        "feed_key": feed_key,
                        "enabled": true,
                        "catalog_version": cat.catalog_version,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Feed {feed_key:?} set to enabled=true (catalog_version={}).",
                        cat.catalog_version
                    );
                }
                Ok(0)
            }
            FeedCommands::Disable { feed_key, json } => {
                let cat = db
                    .set_feed_source(&feed_key, Some(false), None, None)
                    .await?;
                if json {
                    let body = json!({
                        "status": "updated",
                        "feed_key": feed_key,
                        "enabled": false,
                        "catalog_version": cat.catalog_version,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Feed {feed_key:?} set to enabled=false (catalog_version={}).",
                        cat.catalog_version
                    );
                }
                Ok(0)
            }
            FeedCommands::SetUrl {
                feed_key,
                url,
                min_records,
                json,
            } => {
                let cat = db
                    .set_feed_source(&feed_key, None, Some(&url), min_records)
                    .await?;
                let trimmed_url = url.trim();
                if json {
                    let body = json!({
                        "status": "updated",
                        "feed_key": feed_key,
                        "source_url": trimmed_url,
                        "min_records": min_records,
                        "catalog_version": cat.catalog_version,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Updated feed {feed_key:?} -> {trimmed_url} (catalog_version={}).",
                        cat.catalog_version
                    );
                }
                Ok(0)
            }
        }
    }
    .await;
    db.shutdown().await;
    outcome
}

async fn cmd_host(cmd: HostCommands) -> DgipResult<i32> {
    let settings = Settings::from_env();
    let db = Database::new(settings)?;
    db.startup().await?;
    let outcome = async {
        match cmd {
            HostCommands::List { json } => {
                let cat = db.ensure_catalog_fresh(true).await?;
                let items: Vec<AllowedHostItem> = cat
                    .allowed_host_rows
                    .iter()
                    .map(|(h, en, notes)| AllowedHostItem {
                        hostname: h.clone(),
                        enabled: *en,
                        notes: notes.clone(),
                    })
                    .collect();
                if json {
                    let body = json!({
                        "catalog_version": cat.catalog_version,
                        "allowed_hosts": items,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Outbound HTTPS SSRF Allowlist (catalog_version={}):",
                        cat.catalog_version
                    );
                    for (h, en, notes) in &cat.allowed_host_rows {
                        let state_lbl = if *en { "ALLOW" } else { "DENY " };
                        match notes.as_deref().filter(|s| !s.is_empty()) {
                            Some(n) => println!("  [{state_lbl}] {h} — {n}"),
                            None => println!("  [{state_lbl}] {h}"),
                        }
                    }
                }
                Ok(0)
            }
            HostCommands::Allow {
                hostname,
                notes,
                json,
            } => {
                let cat = db
                    .set_allowed_host(&hostname, true, notes.as_deref())
                    .await?;
                let norm = hostname.trim().to_ascii_lowercase();
                if json {
                    let body = json!({
                        "status": "updated",
                        "hostname": norm,
                        "enabled": true,
                        "catalog_version": cat.catalog_version,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Allowed outbound HTTPS host {norm:?} (catalog_version={}).",
                        cat.catalog_version
                    );
                }
                Ok(0)
            }
            HostCommands::Deny {
                hostname,
                notes,
                json,
            } => {
                let cat = db
                    .set_allowed_host(&hostname, false, notes.as_deref())
                    .await?;
                let norm = hostname.trim().to_ascii_lowercase();
                if json {
                    let body = json!({
                        "status": "updated",
                        "hostname": norm,
                        "enabled": false,
                        "catalog_version": cat.catalog_version,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_default()
                    );
                } else {
                    println!(
                        "Denied outbound HTTPS host {norm:?} (catalog_version={}).",
                        cat.catalog_version
                    );
                }
                Ok(0)
            }
        }
    }
    .await;
    db.shutdown().await;
    outcome
}

async fn build_standalone_release(
    output_root: &Path,
    explicit_version: Option<&str>,
) -> DgipResult<PathBuf> {
    let t0 = Instant::now();
    let allowed_hosts: Arc<HashSet<String>> = Arc::new(
        DEFAULT_ALLOWED_HOSTS
            .iter()
            .map(|&(h, _note)| h.to_string())
            .collect(),
    );
    let continent_map: HashMap<&str, &str> = DEFAULT_CONTINENTS.iter().copied().collect();
    let mut country_details: HashMap<String, (String, String, String)> =
        HashMap::with_capacity(DEFAULT_COUNTRIES.len());
    for &(cc, c_name, cont_code) in DEFAULT_COUNTRIES {
        let cont_name = continent_map.get(cont_code).copied().unwrap_or(cont_code);
        country_details.insert(
            cc.to_string(),
            (
                c_name.to_string(),
                cont_code.to_string(),
                cont_name.to_string(),
            ),
        );
    }
    let valid_countries: HashSet<String> = country_details.keys().cloned().collect();

    let specs: Vec<FeedSourceSpec> = build_default_feed_sources()
        .into_iter()
        .map(
            |(
                feed_key,
                kind,
                ip_version,
                source_url,
                min_records,
                max_compressed_bytes,
                max_uncompressed_bytes,
                display_order,
            )| FeedSourceSpec {
                feed_key: feed_key.to_string(),
                kind: kind.to_string(),
                ip_version,
                source_url: source_url.to_string(),
                min_records,
                max_compressed_bytes,
                max_uncompressed_bytes,
                enabled: true,
                display_order,
            },
        )
        .collect();
    let sem = Arc::new(Semaphore::new(8));
    let mut handles = Vec::with_capacity(specs.len());

    for spec in specs {
        let sem_cl = Arc::clone(&sem);
        let hosts_cl = Arc::clone(&allowed_hosts);
        handles.push(tokio::spawn(async move {
            let _permit = sem_cl
                .acquire()
                .await
                .map_err(|_| DgipError::Compilation("Download semaphore closed.".to_string()))?;

            let mirror_opt = rir_nro_mirror_url(&spec.source_url);
            let use_mirror = mirror_opt
                .map(|m| hosts_cl.contains("ftp.ripe.net") && m != spec.source_url)
                .unwrap_or(false);
            let primary_timeout = if use_mirror {
                PRIMARY_RIR_FAST_TIMEOUT_SECONDS
            } else {
                120.0
            };

            let max_comp_bytes =
                usize::try_from(spec.max_compressed_bytes.max(1)).unwrap_or(usize::MAX);
            info!("Downloading {} ({}) ...", spec.feed_key, spec.source_url);
            let primary_res = download_https_bounded(
                &spec.source_url,
                &hosts_cl,
                primary_timeout,
                max_comp_bytes,
                5,
                DEFAULT_UPSTREAM_USER_AGENT,
                &FALLBACK_SPECIAL_RANGES.0,
                &FALLBACK_SPECIAL_RANGES.1,
                if use_mirror { 1 } else { 3 },
            )
            .await;

            let raw = match primary_res {
                Ok(bytes) => bytes,
                Err(exc) => {
                    if let (true, Some(mirror_url)) = (use_mirror, mirror_opt) {
                        warn!(
                            "Primary RIR {} stalled ({}); falling back to official NRO mirror {}",
                            spec.feed_key, exc, mirror_url
                        );
                        download_https_bounded(
                            mirror_url,
                            &hosts_cl,
                            180.0,
                            max_comp_bytes,
                            5,
                            DEFAULT_UPSTREAM_USER_AGENT,
                            &FALLBACK_SPECIAL_RANGES.0,
                            &FALLBACK_SPECIAL_RANGES.1,
                            3,
                        )
                        .await?
                    } else if CORE_FEED_KINDS.contains(&spec.kind.as_str()) {
                        return Err(exc);
                    } else {
                        warn!(
                            "Enrichment feed {} ({}) unavailable during standalone build: {}",
                            spec.feed_key, spec.kind, exc
                        );
                        return Ok::<Option<(FeedSourceSpec, Vec<u8>)>, DgipError>(None);
                    }
                }
            };

            info!(
                "Downloaded {} ({:.2} MB)",
                spec.feed_key,
                (raw.len() as f64) / 1_048_576.0
            );
            Ok(Some((spec, raw)))
        }));
    }

    let mut downloaded: Vec<(FeedSourceSpec, Vec<u8>)> = Vec::with_capacity(handles.len());
    for h in handles {
        let joined = h
            .await
            .map_err(|e| DgipError::Compilation(format!("Download task panicked: {e}")))??;
        if let Some(pair) = joined {
            downloaded.push(pair);
        }
    }

    info!(
        "Parsing and compiling {} Layer 1–4 intelligence feeds (RPKI + Geofeeds + Security) ...",
        downloaded.len()
    );

    let explicit_ver_owned = explicit_version.map(str::to_string);
    let (version, packaged, diff_notes) = tokio::task::spawn_blocking(move || {
        let tables = compile_feed_payloads(
            &downloaded,
            &valid_countries,
            &FALLBACK_SPECIAL_RANGES.0,
            &FALLBACK_SPECIAL_RANGES.1,
            5,
            8,
            12,
            1,
            4_294_967_294,
            true,
            false,
        )?;
        info!("Compiled disjoint tables: {:?}", tables.row_counts());

        let now_utc = Utc::now();
        let empty_existing: [String; 0] = [];
        let version = explicit_ver_owned
            .unwrap_or_else(|| format_iso_week_version(now_utc, &empty_existing, "v"));
        let release_title = format_release_title("{version}", &version, now_utc);

        info!(
            "Packaging CSV, RFC 8805 Geofeed, and MaxMind MMDB v2.0 databases for {} ...",
            version
        );
        let packaged = package_standard_snapshot(
            &tables,
            &version,
            &release_title,
            now_utc,
            None,
            DEFAULT_SOURCE_ATTRIBUTION,
            &country_details,
        )?;
        let diff_notes = compute_diff_and_release_notes(
            &packaged,
            &tables,
            None,
            None,
            None,
            DEFAULT_SOURCE_ATTRIBUTION,
            None,
        )?;
        Ok::<_, DgipError>((version, packaged, diff_notes))
    })
    .await
    .map_err(|e| DgipError::Compilation(format!("Standalone compilation panicked: {e}")))??;

    let rel_dir = output_root.join(&version);
    std::fs::create_dir_all(&rel_dir)?;

    std::fs::write(rel_dir.join("bundle.tar.gz"), &packaged.bundle_bytes)?;
    std::fs::write(rel_dir.join("manifest.json"), &packaged.manifest_bytes)?;
    std::fs::write(rel_dir.join("SHA256SUMS.txt"), &packaged.sha256sums_bytes)?;
    std::fs::write(
        rel_dir.join("RELEASE_NOTES.md"),
        diff_notes.release_notes_md.as_bytes(),
    )?;

    let mut sorted_files: Vec<(&String, &Vec<u8>)> = packaged
        .dataset_artifacts
        .iter()
        .map(|(fname, art)| (fname, &art.payload))
        .collect();
    sorted_files.sort_by(|a, b| a.0.cmp(b.0));
    for (fname, payload) in sorted_files {
        std::fs::write(rel_dir.join(fname), payload)?;
    }

    info!(
        "Built standalone release {} in {:.1}s -> {}",
        version,
        t0.elapsed().as_secs_f64(),
        rel_dir.display()
    );
    Ok(rel_dir)
}

/// Top-level CLI dispatcher returning POSIX exit codes (`0` success, `1` runtime error, `2` usage/config error).
pub async fn run_cli(argv: Vec<OsString>) -> i32 {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = match Cli::try_parse_from(argv) {
        Ok(parsed) => parsed,
        Err(err) => {
            let code = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
            let _ = err.print();
            return code;
        }
    };

    if matches!(cli.command, Some(Commands::Healthcheck)) {
        return cmd_healthcheck().await;
    }

    let is_serve = matches!(cli.command, None | Some(Commands::Serve));
    let long_running_non_json = matches!(
        cli.command,
        Some(
            Commands::Sync { json: false, .. }
                | Commands::Release { json: false, .. }
                | Commands::BuildRelease { .. }
        )
    );
    configure_logging(is_serve || cli.verbose || long_running_non_json);

    let result: DgipResult<i32> = match cli.command {
        None | Some(Commands::Serve) => run_http_server(Settings::from_env()).await.map(|()| 0),
        Some(Commands::Healthcheck) => Ok(cmd_healthcheck().await),
        Some(Commands::Status { json }) => cmd_status(json).await,
        Some(Commands::Sync { force, json }) => cmd_sync(force, json).await,
        Some(Commands::Release { force, note, json }) => {
            cmd_release(force, note.as_deref(), json).await
        }
        Some(Commands::Catalog { json }) => cmd_catalog(json).await,
        Some(Commands::Config { cmd }) => cmd_config(cmd).await,
        Some(Commands::Feed { cmd }) => cmd_feed(cmd).await,
        Some(Commands::Host { cmd }) => cmd_host(cmd).await,
        Some(Commands::BuildRelease {
            output_dir,
            version,
        }) => match build_standalone_release(&output_dir, version.as_deref()).await {
            Ok(out_dir) => {
                println!("Release artifacts written to {}", out_dir.display());
                Ok(0)
            }
            Err(e) => Err(e),
        },
    };

    match result {
        Ok(code) => code,
        Err(DgipError::InvalidConfig(msg)) => {
            eprintln!("Configuration error: {msg}");
            2
        }
        Err(exc) => {
            eprintln!("Error: {exc}");
            1
        }
    }
}
