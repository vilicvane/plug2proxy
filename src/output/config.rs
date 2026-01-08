//! Output configuration for OUT node.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::local::LocalIpOrInterface;
use super::{DirectOutput, LocalOutput, Output, Socks5Output};

/// Output configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutputConfig {
    /// Local output with specific bind address/interface.
    Local(LocalOutputConfig),
    /// SOCKS5 proxy output.
    Socks5(Socks5OutputConfig),
}

impl OutputConfig {
    /// Get the tag for this output.
    pub fn tag(&self) -> &str {
        match self {
            OutputConfig::Local(config) => &config.tag,
            OutputConfig::Socks5(config) => &config.tag,
        }
    }

    /// Convert to an Output implementation.
    pub fn into_output(self) -> Arc<dyn Output> {
        match self {
            OutputConfig::Local(config) => Arc::new(LocalOutput::new(config.bind)),
            OutputConfig::Socks5(config) => {
                let output = Socks5Output::new(config.address);
                if let Some(auth) = config.auth {
                    Arc::new(output.with_auth(auth.username, auth.password))
                } else {
                    Arc::new(output)
                }
            }
        }
    }
}

/// Local output configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalOutputConfig {
    /// Tag to identify this output.
    pub tag: String,
    /// Bind address or interface.
    #[serde(default)]
    pub bind: Option<LocalIpOrInterface>,
}

/// SOCKS5 output configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Socks5OutputConfig {
    /// Tag to identify this output.
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

/// Map of tag -> output.
pub struct OutputMap {
    outputs: HashMap<String, Arc<dyn Output>>,
    default: Arc<dyn Output>,
}

impl Default for OutputMap {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputMap {
    /// Create a new output map with direct output as default.
    pub fn new() -> Self {
        Self {
            outputs: HashMap::new(),
            default: Arc::new(DirectOutput),
        }
    }

    /// Create from a list of output configs.
    pub fn from_configs(configs: Vec<OutputConfig>) -> Self {
        let mut map = Self::new();
        for config in configs {
            let tag = config.tag().to_string();
            let output = config.into_output();
            map.outputs.insert(tag, output);
        }
        map
    }

    /// Get output by tag, returns default (direct) if not found.
    pub fn get(&self, tag: Option<&str>) -> Arc<dyn Output> {
        if let Some(tag) = tag {
            self.outputs
                .get(tag)
                .cloned()
                .unwrap_or_else(|| Arc::clone(&self.default))
        } else {
            Arc::clone(&self.default)
        }
    }

    /// Check if a tag has a configured output.
    pub fn has(&self, tag: &str) -> bool {
        self.outputs.contains_key(tag)
    }

    /// List all configured tags.
    pub fn tags(&self) -> Vec<&str> {
        self.outputs.keys().map(|s| s.as_str()).collect()
    }
}
