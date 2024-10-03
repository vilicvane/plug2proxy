use std::{
    default,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use plug2proxy::{
    config::MatchServerUrlOrConfig,
    routing::config::{InRuleConfig, OutRuleConfig},
    utils::OneOrMany,
};

use crate::constants::{
    fake_ip_dns_port_default, geolite2_update_interval_default, geolite2_url_default,
    in_routing_rules_default, stun_server_address_default, transparent_proxy_port_default,
};

#[derive(serde::Deserialize)]
pub struct InConfig {
    #[serde(default)]
    pub transparent_proxy: InTransparentProxyConfig,
    #[serde(default)]
    pub fake_ip_dns: InFakeIpDnsConfig,
    pub tunneling: InTunnelingConfig,
    #[serde(default)]
    pub routing: InRoutingConfig,
}

#[derive(serde::Deserialize)]
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

#[derive(serde::Deserialize)]
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

#[derive(serde::Deserialize)]
pub struct InTunnelingConfig {
    #[serde(default = "stun_server_address_default")]
    pub stun_server: String,
    pub match_server: MatchServerUrlOrConfig,
}

#[derive(serde::Deserialize)]
pub struct InRoutingConfig {
    #[serde(default)]
    pub geolite2: InRoutingGeoLite2Config,
    #[serde(default = "in_routing_rules_default")]
    pub rules: Vec<InRuleConfig>,
}

impl Default for InRoutingConfig {
    fn default() -> Self {
        Self {
            geolite2: Default::default(),
            rules: in_routing_rules_default(),
        }
    }
}

#[derive(serde::Deserialize)]
pub struct InRoutingGeoLite2Config {
    #[serde(default = "geolite2_url_default")]
    pub url: String,
    pub update_interval: Option<String>,
}

impl Default for InRoutingGeoLite2Config {
    fn default() -> Self {
        Self {
            url: geolite2_url_default(),
            update_interval: None,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct OutConfig {
    pub tunneling: OutTunnelingConfig,
    #[serde(default)]
    pub routing: OutRoutingConfig,
}

#[derive(serde::Deserialize)]
pub struct OutTunnelingConfig {
    pub label: Option<OneOrMany<String>>,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "stun_server_address_default")]
    pub stun_server: String,
    pub match_server: MatchServerUrlOrConfig,
}

#[derive(serde::Deserialize)]
pub struct OutRoutingConfig {
    #[serde(default)]
    pub rules: Vec<OutRuleConfig>,
}

#[allow(clippy::derivable_impls)]
impl Default for OutRoutingConfig {
    fn default() -> Self {
        Self { rules: Vec::new() }
    }
}
