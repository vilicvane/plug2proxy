use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

use crate::output::OutputConfig;
use crate::route::{OneOrMany, RuleConfig};

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
    /// Can be a single tag or array of tags.
    #[serde(default)]
    pub tag: OneOrMany<String>,
    pub listen: SocketAddr,
    /// Number of TCP connections underlying QUIC.
    pub connections: Option<usize>,
    /// Routing rules (sent to IN nodes).
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutConfig {
    /// Tags this OUT node provides for routing.
    /// Can be a single tag or array of tags.
    #[serde(default)]
    pub tag: OneOrMany<String>,
    /// HUB connection config. Can be just an address string or a struct.
    pub hub: HubConnectionConfig,
    /// Number of TCP connections underlying QUIC.
    pub connections: Option<usize>,
    /// Output configurations for second-level routing.
    /// Each output has a tag that can be selected by routing rules.
    #[serde(default)]
    pub outputs: Vec<OutputConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InConfig {
    /// HUB connection config. Can be just an address string or a struct.
    pub hub: HubConnectionConfig,
    /// Number of TCP connections underlying QUIC.
    pub connections: Option<usize>,
    pub socks5: Option<Socks5Config>,
}

/// HUB connection configuration.
/// Can be deserialized from either:
/// - A string: `hub: "127.0.0.1:8765"`
/// - A struct: `hub: { address: "127.0.0.1:8765" }`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HubConnectionConfig {
    /// Just the address string.
    Address(SocketAddr),
    /// Full config with address field.
    Full(HubConnectionFullConfig),
}

impl HubConnectionConfig {
    pub fn address(&self) -> SocketAddr {
        match self {
            HubConnectionConfig::Address(addr) => *addr,
            HubConnectionConfig::Full(config) => config.address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConnectionFullConfig {
    pub address: SocketAddr,
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

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            tag: OneOrMany::Many(vec![]),
            listen: "127.0.0.1:8765".parse().unwrap(),
            connections: Some(4),
            routing: RoutingConfig::default(),
        }
    }
}

impl Default for OutConfig {
    fn default() -> Self {
        Self {
            tag: OneOrMany::Many(vec![]),
            hub: HubConnectionConfig::Address("127.0.0.1:8765".parse().unwrap()),
            connections: Some(4),
            outputs: vec![],
        }
    }
}

impl Default for InConfig {
    fn default() -> Self {
        Self {
            hub: HubConnectionConfig::Address("127.0.0.1:8765".parse().unwrap()),
            connections: Some(4),
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
