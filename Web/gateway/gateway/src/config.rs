use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::Method;
use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::Error;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub selector: SelectorConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(
        default = "default_request_timeout",
        rename = "request_timeout_ms",
        deserialize_with = "duration_millis::deserialize"
    )]
    pub request_timeout: Duration,
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SelectorConfig {
    #[serde(default)]
    pub snapshot_url: Option<String>,
    #[serde(
        default = "default_selector_refresh_interval",
        rename = "refresh_interval_ms",
        deserialize_with = "duration_millis::deserialize"
    )]
    pub refresh_interval: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    #[serde(default)]
    pub kind: RouteKind,
    #[serde(default)]
    pub host: Option<String>,
    pub path_prefix: String,
    #[serde(default, deserialize_with = "deserialize_methods")]
    pub methods: Vec<Method>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    #[default]
    Proxy,
    Static,
}

impl Config {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn from_toml(contents: &str) -> Result<Self, Error> {
        let config = toml::from_str(contents)?;
        Ok(config)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            request_timeout: default_request_timeout(),
            max_concurrency: default_max_concurrency(),
        }
    }
}

impl Default for SelectorConfig {
    fn default() -> Self {
        Self {
            snapshot_url: None,
            refresh_interval: default_selector_refresh_interval(),
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8080"
        .parse()
        .expect("default listen address is valid")
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_max_concurrency() -> usize {
    16_384
}

fn default_selector_refresh_interval() -> Duration {
    Duration::from_millis(200)
}

fn deserialize_methods<'de, D>(deserializer: D) -> Result<Vec<Method>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            value
                .parse::<Method>()
                .map_err(|err| de::Error::custom(format!("invalid HTTP method {value}: {err}")))
        })
        .collect()
}

mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
