use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

use crate::exit::ExitConfig;
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
    /// Exit configurations for level 2 routing.
    /// Each exit has a tag that can be selected by routing rules.
    #[serde(default)]
    pub exits: Vec<ExitConfig>,
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
    /// Traffic mark (SO_MARK) for all outgoing packets (TCP and UDP).
    /// Used for TPROXY interception. Set to 0 to disable marking.
    #[serde(default)]
    pub mark: Option<u32>,
    /// Fake-IP DNS configuration.
    /// Can be just an address string or a struct.
    /// Uses `fakeip.db` as the database file (convention).
    pub fake_ip: Option<FakeIpConfig>,
    /// SOCKS5 server configuration.
    /// Can be just an address string or a struct.
    pub socks5: Option<Socks5Config>,
    /// TPROXY (transparent proxy) configuration (Linux only).
    /// Can be just an address string or a struct.
    pub tproxy: Option<TProxyConfig>,
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

/// SOCKS5 server configuration.
/// Can be deserialized from either:
/// - A string: `socks5: "127.0.0.1:1080"`
/// - A struct: `socks5: { listen: "127.0.0.1:1080", auth: { ... } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Socks5Config {
    /// Just the listen address string.
    Address(SocketAddr),
    /// Full config with listen address and optional auth.
    Full(Socks5FullConfig),
}

impl Socks5Config {
    pub fn listen(&self) -> SocketAddr {
        match self {
            Socks5Config::Address(addr) => *addr,
            Socks5Config::Full(config) => config.listen,
        }
    }

    pub fn auth(&self) -> Option<&AuthConfig> {
        match self {
            Socks5Config::Address(_) => None,
            Socks5Config::Full(config) => config.auth.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5FullConfig {
    pub listen: SocketAddr,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

/// TPROXY (transparent proxy) configuration.
/// Can be deserialized from either:
/// - A string: `tproxy: "127.0.0.1:12345"`
/// - A struct: `tproxy: { listen: "127.0.0.1:12345" }`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TProxyConfig {
    /// Just the listen address string.
    Address(SocketAddr),
    /// Full config with listen address.
    Full(TProxyFullConfig),
}

impl TProxyConfig {
    pub fn listen(&self) -> SocketAddr {
        match self {
            TProxyConfig::Address(addr) => *addr,
            TProxyConfig::Full(config) => config.listen,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TProxyFullConfig {
    pub listen: SocketAddr,
}

/// Fake-IP DNS configuration.
/// Can be deserialized from either:
/// - A string: `fake_ip: "127.0.0.1:53"`
/// - A struct: `fake_ip: { listen: "127.0.0.1:53" }`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FakeIpConfig {
    /// Just the listen address string.
    Address(SocketAddr),
    /// Full config with listen address.
    Full(FakeIpFullConfig),
}

impl FakeIpConfig {
    pub fn listen(&self) -> SocketAddr {
        match self {
            FakeIpConfig::Address(addr) => *addr,
            FakeIpConfig::Full(config) => config.listen,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpFullConfig {
    pub listen: SocketAddr,
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
            exits: vec![],
        }
    }
}

impl Default for InConfig {
    fn default() -> Self {
        Self {
            hub: HubConnectionConfig::Address("127.0.0.1:8765".parse().unwrap()),
            connections: Some(4),
            direct: OneOrMany::default(),
            mark: None,
            fake_ip: None,
            socks5: Some(Socks5Config::default()),
            tproxy: None,
        }
    }
}

impl Default for Socks5Config {
    fn default() -> Self {
        Socks5Config::Address("127.0.0.1:1080".parse().unwrap())
    }
}
