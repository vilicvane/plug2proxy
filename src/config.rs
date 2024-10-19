use std::net::SocketAddr;

use plug2proxy::{
    config::MatchServerUrlOrConfig,
    route::{
        config::{InFallbackRuleConfig, InRuleConfig, OutOutputConfig, OutRuleConfig},
        rule::{BuiltInLabel, Label},
    },
    utils::OneOrMany,
};

use crate::constants::{
    fake_ip_dns_address_default, geolite2_url_default, transparent_proxy_address_default,
    transparent_proxy_traffic_mark_default, tunneling_http2_connections_default,
};

#[derive(serde::Deserialize)]
pub struct InConfig {
    #[serde(default)]
    pub dns_resolver: InDnsResolverConfig,
    #[serde(default)]
    pub fake_ip_dns: InFakeIpDnsConfig,
    #[serde(default)]
    pub transparent_proxy: InTransparentProxyConfig,
    pub tunneling: InTunnelingConfig,
    #[serde(default)]
    pub routing: InRoutingConfig,
}

#[derive(serde::Deserialize)]
pub struct InDnsResolverConfig {
    pub server: Option<OneOrMany<String>>,
}

#[allow(clippy::derivable_impls)]
impl Default for InDnsResolverConfig {
    fn default() -> Self {
        Self { server: None }
    }
}

#[derive(serde::Deserialize)]
pub struct InFakeIpDnsConfig {
    #[serde(default = "fake_ip_dns_address_default")]
    pub listen: SocketAddr,
}

impl Default for InFakeIpDnsConfig {
    fn default() -> Self {
        Self {
            listen: fake_ip_dns_address_default(),
        }
    }
}

#[derive(serde::Deserialize)]
pub struct InTransparentProxyConfig {
    #[serde(default = "transparent_proxy_address_default")]
    pub listen: SocketAddr,
    #[serde(default = "transparent_proxy_traffic_mark_default")]
    pub traffic_mark: u32,
}

impl Default for InTransparentProxyConfig {
    fn default() -> Self {
        Self {
            listen: transparent_proxy_address_default(),
            traffic_mark: transparent_proxy_traffic_mark_default(),
        }
    }
}

#[derive(serde::Deserialize)]
pub struct InTunnelingConfig {
    pub stun_server: Option<OneOrMany<String>>,
    pub match_server: MatchServerUrlOrConfig,
    #[serde(default)]
    pub http2: InTunnelingHttp2Config,
    #[serde(default)]
    pub quic: InTunnelingQuicConfig,
}

#[derive(serde::Deserialize)]
pub struct InTunnelingHttp2Config {
    #[serde(default = "true_default")]
    pub enabled: bool,
    #[serde(default = "tunneling_http2_connections_default")]
    pub connections: usize,
    pub priority: Option<i64>,
}

impl Default for InTunnelingHttp2Config {
    fn default() -> Self {
        Self {
            enabled: true,
            connections: tunneling_http2_connections_default(),
            priority: None,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct InTunnelingQuicConfig {
    #[serde(default = "true_default")]
    pub enabled: bool,
    pub priority: Option<i64>,
}

impl Default for InTunnelingQuicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            priority: None,
        }
    }
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
    pub outputs: Vec<OutOutputConfig>,
    #[serde(default)]
    pub routing: OutRoutingConfig,
}

#[derive(serde::Deserialize)]
pub struct OutTunnelingConfig {
    pub label: Option<OneOrMany<Label>>,
    pub stun_server: Option<OneOrMany<String>>,
    pub match_server: MatchServerUrlOrConfig,
    #[serde(default)]
    pub http2: OutTunnelingHttp2Config,
    #[serde(default)]
    pub quic: OutTunnelingQuicConfig,
}

#[derive(Default, serde::Deserialize)]
pub struct OutTunnelingHttp2Config {
    pub priority: Option<i64>,
}

#[derive(Default, serde::Deserialize)]
pub struct OutTunnelingQuicConfig {
    pub priority: Option<i64>,
}

#[derive(Default, serde::Deserialize)]
pub struct OutRoutingConfig {
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub rules: Vec<OutRuleConfig>,
}

fn in_routing_rules_default() -> Vec<InRuleConfig> {
    vec![InRuleConfig::Fallback(InFallbackRuleConfig {
        out: OneOrMany::One(Label::BuiltIn(BuiltInLabel::Any)),
        tag: None,
    })]
}

fn true_default() -> bool {
    true
}
