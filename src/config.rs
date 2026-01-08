use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

use crate::output::OutputConfig;
use crate::route::RuleConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Config {
    Hub(HubConfig),
    Out(OutConfig),
    In(InConfig),
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    /// Tags this HUB provides when acting as an OUT.
    #[serde(default)]
    pub tags: Vec<String>,
    pub listen: SocketAddr,
    pub connection_count: Option<usize>,
    /// Routing rules (sent to IN nodes).
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutConfig {
    /// Tags this OUT node provides for routing.
    pub tags: Vec<String>,
    pub hub_addr: SocketAddr,
    pub hub_host: Option<String>,
    pub connection_count: Option<usize>,
    /// Routing rules this OUT provides.
    #[serde(default)]
    pub routing: OutRoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InConfig {
    pub hub_addr: SocketAddr,
    pub hub_host: Option<String>,
    pub connection_count: Option<usize>,
    pub socks5: Option<Socks5Config>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    pub listen: SocketAddr,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

/// Routing configuration for Hub (sent to IN nodes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Routing rules.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// Routing configuration for OUT nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutRoutingConfig {
    /// Priority for rules from this OUT (lower = higher priority).
    #[serde(default)]
    pub priority: i64,
    /// Routing rules this OUT provides.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Output configurations for second-level routing.
    /// Each output has a tag that can be selected by routing rules.
    #[serde(default)]
    pub outputs: Vec<OutputConfig>,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            tags: vec![],
            listen: "127.0.0.1:8765".parse().unwrap(),
            connection_count: Some(4),
            routing: RoutingConfig::default(),
        }
    }
}

impl Default for OutConfig {
    fn default() -> Self {
        Self {
            tags: vec!["default".to_string()],
            hub_addr: "127.0.0.1:8765".parse().unwrap(),
            hub_host: Some("localhost".to_string()),
            connection_count: Some(4),
            routing: OutRoutingConfig::default(),
        }
    }
}

impl Default for InConfig {
    fn default() -> Self {
        Self {
            hub_addr: "127.0.0.1:8765".parse().unwrap(),
            hub_host: Some("localhost".to_string()),
            connection_count: Some(4),
            socks5: Some(Socks5Config::default()),
        }
    }
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".parse().unwrap(),
            auth: None,
        }
    }
}
