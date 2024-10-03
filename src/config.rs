use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use plug2proxy::{
    config::{MatchServerConfig, RedisMatchServerConfig},
    utils::OneOrMany,
};

use crate::constants::{
    fake_ip_dns_port_default, stun_server_address_default, transparent_proxy_port_default,
};

#[derive(Clone, serde::Deserialize)]
pub struct InConfig {
    #[serde(default)]
    pub transparent_proxy: InTransparentProxyConfig,
    #[serde(default)]
    pub fake_ip_dns: InFakeIpDnsConfig,
    pub tunneling: InTunnelingConfig,
}

#[derive(Clone, serde::Deserialize)]
pub struct InTransparentProxyConfig {
    pub listen: SocketAddr,
}

impl Default for InTransparentProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                transparent_proxy_port_default(),
            )),
        }
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct InFakeIpDnsConfig {
    pub listen: SocketAddr,
}

impl Default for InFakeIpDnsConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                fake_ip_dns_port_default(),
            )),
        }
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct InTunnelingConfig {
    #[serde(default = "stun_server_address_default")]
    pub stun_server: String,
    pub match_server: MatchServerUrlOrConfig,
}

#[derive(Clone, serde::Deserialize)]
pub struct OutConfig {
    pub tunneling: OutTunnelingConfig,
}

#[derive(Clone, serde::Deserialize)]
pub struct OutTunnelingConfig {
    pub label: Option<OneOrMany<String>>,
    #[serde(default = "stun_server_address_default")]
    pub stun_server: String,
    pub match_server: MatchServerUrlOrConfig,
}

#[derive(Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum MatchServerUrlOrConfig {
    Url(String),
    Config(MatchServerConfig),
}

impl MatchServerUrlOrConfig {
    pub fn into_config(self) -> MatchServerConfig {
        match self {
            Self::Url(url) => {
                let parsed_url = url::Url::parse(&url).expect("invalid match server url.");

                let scheme = parsed_url.scheme();

                match scheme {
                    "redis" | "rediss" => MatchServerConfig::Redis(RedisMatchServerConfig { url }),
                    _ => panic!("unsupported match server url."),
                }
            }
            Self::Config(config) => config,
        }
    }
}
