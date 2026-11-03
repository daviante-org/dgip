//! Bootstrap container environment configuration (`DGIP_*`) for DGIP.

use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Settings {
    pub database_url: String,
    pub db_pool_min_size: usize,
    pub db_pool_max_size: usize,
    pub host: String,
    pub port: u16,
    pub swagger_enabled: bool,
    pub assets_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub catalog_poll_seconds: f64,
    pub allow_local_files: bool,
    pub initial_bootstrap_url: String,
    pub initial_snapshot_retention: i32,
    pub cors_allow_origins: String,
}

fn default_assets_dir() -> PathBuf {
    let container_dir = Path::new("/app/assets");
    if container_dir.is_dir() {
        container_dir.to_path_buf()
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets")
    }
}

fn parse_env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn parse_env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            database_url: "postgresql://dgip:dgip@localhost:5432/dgip".to_string(),
            db_pool_min_size: 2,
            db_pool_max_size: 16,
            host: "0.0.0.0".to_string(),
            port: 8090,
            swagger_enabled: true,
            assets_dir: default_assets_dir(),
            cache_dir: PathBuf::from("/tmp/dgip-cache"),
            catalog_poll_seconds: 2.0,
            allow_local_files: false,
            initial_bootstrap_url:
                "https://github.com/daviante-org/dgip-data/releases/latest/download/bundle.tar.gz"
                    .to_string(),
            initial_snapshot_retention: 5,
            cors_allow_origins: "*".to_string(),
        }
    }
}

impl Settings {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();
        let def = Self::default();
        let database_url = env::var("DGIP_DATABASE_URL").unwrap_or(def.database_url);
        let db_pool_min_size =
            parse_env_usize("DGIP_DB_POOL_MIN_SIZE", def.db_pool_min_size, 1, 64);
        let db_pool_max_size = parse_env_usize(
            "DGIP_DB_POOL_MAX_SIZE",
            def.db_pool_max_size,
            db_pool_min_size.max(2),
            256,
        );
        let host = env::var("DGIP_HOST").unwrap_or(def.host);
        let port = env::var("DGIP_PORT")
            .ok()
            .and_then(|v| v.trim().parse::<u16>().ok())
            .filter(|&p| p >= 1)
            .unwrap_or(def.port);
        let swagger_enabled = parse_env_bool("DGIP_SWAGGER_ENABLED", def.swagger_enabled);
        let assets_dir = env::var("DGIP_ASSETS_DIR")
            .map(PathBuf::from)
            .unwrap_or(def.assets_dir);
        let cache_dir = env::var("DGIP_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or(def.cache_dir);
        let catalog_poll_seconds = env::var("DGIP_CATALOG_POLL_SECONDS")
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .map(|v| v.clamp(0.2, 300.0))
            .unwrap_or(def.catalog_poll_seconds);
        let allow_local_files = parse_env_bool("DGIP_ALLOW_LOCAL_FILES", def.allow_local_files);
        let initial_bootstrap_url =
            env::var("DGIP_INITIAL_BOOTSTRAP_URL").unwrap_or(def.initial_bootstrap_url);
        let initial_snapshot_retention = env::var("DGIP_INITIAL_SNAPSHOT_RETENTION")
            .ok()
            .and_then(|v| v.trim().parse::<i32>().ok())
            .map(|v| v.clamp(1, 52))
            .unwrap_or(def.initial_snapshot_retention);
        let cors_allow_origins =
            env::var("DGIP_CORS_ALLOW_ORIGINS").unwrap_or(def.cors_allow_origins);

        Self {
            database_url,
            db_pool_min_size,
            db_pool_max_size,
            host,
            port,
            swagger_enabled,
            assets_dir,
            cache_dir,
            catalog_poll_seconds,
            allow_local_files,
            initial_bootstrap_url,
            initial_snapshot_retention,
            cors_allow_origins,
        }
    }

    pub fn parsed_cors_origins(&self) -> Vec<String> {
        let raw = self.cors_allow_origins.trim();
        if raw.is_empty() {
            return Vec::new();
        }
        if raw == "*" {
            return vec!["*".to_string()];
        }
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}
