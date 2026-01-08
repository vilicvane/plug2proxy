use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::output::OutputConfig;
use crate::route::{OneOrMany, RuleConfig};

/// Top-level config structure.
/// Only one of `hub`, `out`, or `in` should be present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// HUB node configuration.
    pub hub: Option<HubConfig>,
    /// OUT node configuration.
    pub out: Option<OutConfig>,
    /// IN node configuration (use `r#in` in code due to reserved keyword).
    #[serde(rename = "in")]
    pub in_config: Option<InConfig>,
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Get the node type from the config.
    pub fn node_type(&self) -> Option<NodeType> {
        if self.hub.is_some() {
            Some(NodeType::Hub)
        } else if self.out.is_some() {
            Some(NodeType::Out)
        } else if self.in_config.is_some() {
            Some(NodeType::In)
        } else {
            None
        }
    }
}

/// Node type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Hub,
    Out,
    In,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    /// Labels this HUB provides when acting as an OUT (for level 1 routing).
    /// Can be a single label or array of labels.
    #[serde(default)]
    pub label: OneOrMany<String>,
    pub listen: SocketAddr,
    /// Number of TCP connections underlying QUIC.
    pub connections: Option<usize>,
    /// Routing rules (sent to IN nodes).
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutConfig {
    /// Labels this OUT node provides for level 1 routing.
    /// Can be a single label or array of labels.
    #[serde(default)]
    pub label: OneOrMany<String>,
    /// HUB connection config. Can be just an address string or a struct.
    pub hub: HubConnectionConfig,
    /// Number of TCP connections underlying QUIC.
    pub connections: Option<usize>,
    /// Listen address for direct IN→OUT connections (bypassing HUB relay).
    /// If set, IN nodes can connect directly to this OUT.
    pub listen: Option<SocketAddr>,
    /// Output configurations for level 2 routing.
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
    /// OUT labels to connect directly (bypassing HUB relay).
    /// Only OUTs matching these labels will be connected directly.
    /// If empty, no direct connections are made (all traffic goes through HUB).
    #[serde(default)]
    pub direct: OneOrMany<String>,
    /// Path to GeoLite2 database file for GeoIP-based routing rules.
    pub geoip_db: Option<PathBuf>,
    /// Fake-IP DNS listen address.
    /// If set, a fake-IP DNS server will be started on this address.
    /// Uses `fakeip.db` as the database file (convention).
    pub fake_ip: Option<SocketAddr>,
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
            label: OneOrMany::Many(vec![]),
            listen: "127.0.0.1:8765".parse().unwrap(),
            connections: Some(4),
            routing: RoutingConfig::default(),
        }
    }
}

impl Default for OutConfig {
    fn default() -> Self {
        Self {
            label: OneOrMany::Many(vec![]),
            hub: HubConnectionConfig::Address("127.0.0.1:8765".parse().unwrap()),
            connections: Some(4),
            listen: None,
            outputs: vec![],
        }
    }
}

impl Default for InConfig {
    fn default() -> Self {
        Self {
            hub: HubConnectionConfig::Address("127.0.0.1:8765".parse().unwrap()),
            connections: Some(4),
            direct: OneOrMany::default(),
            geoip_db: None,
            fake_ip: None,
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
