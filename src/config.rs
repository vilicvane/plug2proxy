use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

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
    pub id: String,
    pub listen: SocketAddr,
    pub connection_count: Option<usize>,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutConfig {
    pub id: String,
    pub tags: Vec<String>,
    pub hub_addr: SocketAddr,
    pub hub_host: Option<String>,
    pub connection_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InConfig {
    pub id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub pattern: String,
    pub tag: String,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            id: "hub".to_string(),
            listen: "127.0.0.1:8765".parse().unwrap(),
            connection_count: Some(4),
            routes: vec![],
        }
    }
}

impl Default for OutConfig {
    fn default() -> Self {
        Self {
            id: "out".to_string(),
            tags: vec!["default".to_string()],
            hub_addr: "127.0.0.1:8765".parse().unwrap(),
            hub_host: Some("localhost".to_string()),
            connection_count: Some(4),
        }
    }
}

impl Default for InConfig {
    fn default() -> Self {
        Self {
            id: "in".to_string(),
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
