//! Exit configuration for OUT node.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::local::LocalIpOrInterface;
use super::{DirectExit, Exit, LocalExit, Socks5Exit};

/// Exit configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ExitConfig {
    /// Local exit with specific bind address/interface.
    Local(LocalExitConfig),
    /// SOCKS5 proxy exit.
    Socks5(Socks5ExitConfig),
}

impl ExitConfig {
    /// Get the tag for this exit.
    pub fn tag(&self) -> &str {
        match self {
            ExitConfig::Local(config) => &config.tag,
            ExitConfig::Socks5(config) => &config.tag,
        }
    }

    /// Convert to an Exit implementation.
    pub fn into_exit(self) -> Arc<dyn Exit> {
        match self {
            ExitConfig::Local(config) => Arc::new(LocalExit::new(config.bind)),
            ExitConfig::Socks5(config) => {
                let exit = Socks5Exit::new(config.address);
                if let Some(auth) = config.auth {
                    Arc::new(exit.with_auth(auth.username, auth.password))
                } else {
                    Arc::new(exit)
                }
            }
        }
    }
}

/// Local exit configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalExitConfig {
    /// Tag to identify this exit.
    pub tag: String,
    /// Bind address or interface.
    #[serde(default)]
    pub bind: Option<LocalIpOrInterface>,
}

/// SOCKS5 exit configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Socks5ExitConfig {
    /// Tag to identify this exit.
    pub tag: String,
    /// SOCKS5 proxy address.
    #[serde(default = "default_socks5_address")]
    pub address: SocketAddr,
    /// Optional authentication.
    #[serde(default)]
    pub auth: Option<Socks5AuthConfig>,
}

/// SOCKS5 authentication configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Socks5AuthConfig {
    pub username: String,
    pub password: String,
}

fn default_socks5_address() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

/// Map of tag -> exit.
pub struct ExitMap {
    exits: HashMap<String, Arc<dyn Exit>>,
    default: Arc<dyn Exit>,
}

impl Default for ExitMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitMap {
    /// Create a new exit map with direct exit as default.
    pub fn new() -> Self {
        Self {
            exits: HashMap::new(),
            default: Arc::new(DirectExit),
        }
    }

    /// Create from a list of exit configs.
    pub fn from_configs(configs: Vec<ExitConfig>) -> Self {
        let mut map = Self::new();
        for config in configs {
            let tag = config.tag().to_string();
            let exit = config.into_exit();
            map.exits.insert(tag, exit);
        }
        map
    }

    /// Get exit by tag, returns default (direct) if not found.
    pub fn get(&self, tag: Option<&str>) -> Arc<dyn Exit> {
        if let Some(tag) = tag {
            self.exits
                .get(tag)
                .cloned()
                .unwrap_or_else(|| Arc::clone(&self.default))
        } else {
            Arc::clone(&self.default)
        }
    }

    /// Check if a tag has a configured exit.
    pub fn has(&self, tag: &str) -> bool {
        self.exits.contains_key(tag)
    }

    /// List all configured tags.
    pub fn tags(&self) -> Vec<&str> {
        self.exits.keys().map(|s| s.as_str()).collect()
    }
}
