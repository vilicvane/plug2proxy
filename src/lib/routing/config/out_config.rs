use std::str::FromStr as _;

use itertools::Itertools;

use crate::{
    routing::rule::{
        AddressRule, DomainPatternRule, DomainRule, DynRuleBox, FallbackRule, GeoIpRule,
    },
    tunnel::TunnelId,
    utils::{net::parse_ip_net, OneOrMany},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum OutRuleConfig {
    #[serde(rename = "geoip")]
    GeoIp(OutGeoIpRuleConfig),
    #[serde(rename = "address")]
    Address(OutAddressRuleConfig),
    #[serde(rename = "domain")]
    Domain(OutDomainRuleConfig),
    #[serde(rename = "domain_pattern")]
    DomainPattern(OutDomainPatternRuleConfig),
    #[serde(rename = "fallback")]
    Fallback(OutFallbackRuleConfig),
}

impl OutRuleConfig {
    pub fn into_rule(self, tunnel_id: TunnelId, priority_default: i64) -> DynRuleBox {
        match self {
            OutRuleConfig::GeoIp(config) => Box::new(GeoIpRule {
                matches: config.r#match.into_vec(),
                labels: vec![tunnel_id.to_string()],
                priority: config.priority.unwrap_or(priority_default),
                negate: config.negate,
            }),
            OutRuleConfig::Address(config) => Box::new(AddressRule {
                match_ips: config.match_ip.map(|match_ip| {
                    match_ip
                        .into_vec()
                        .iter()
                        .filter_map(|ip| {
                            parse_ip_net(ip)
                                .inspect_err(|_| log::error!("invalid ip address: {ip}"))
                                .ok()
                        })
                        .collect_vec()
                }),
                match_ports: config.match_port.map(|match_port| match_port.into_vec()),
                labels: vec![tunnel_id.to_string()],
                priority: config.priority.unwrap_or(priority_default),
                negate: config.negate,
            }),
            OutRuleConfig::Domain(config) => Box::new(DomainRule {
                matches: config.r#match.into_vec(),
                labels: vec![tunnel_id.to_string()],
                priority: config.priority.unwrap_or(priority_default),
                negate: config.negate,
            }),
            OutRuleConfig::DomainPattern(config) => Box::new(DomainPatternRule {
                matches: config
                    .r#match
                    .into_vec()
                    .into_iter()
                    .filter_map(|pattern| {
                        regex::Regex::from_str(&pattern)
                            .inspect_err(|_| {
                                log::error!(
                                    "invalid domain_pattern rule match pattern: {}",
                                    pattern
                                );
                            })
                            .ok()
                    })
                    .collect_vec(),
                labels: vec![tunnel_id.to_string()],
                priority: config.priority.unwrap_or(priority_default),
                negate: config.negate,
            }),
            OutRuleConfig::Fallback(_) => Box::new(FallbackRule {
                labels: vec![tunnel_id.to_string()],
            }),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OutGeoIpRuleConfig {
    pub r#match: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub priority: Option<i64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OutAddressRuleConfig {
    pub match_ip: Option<OneOrMany<String>>,
    pub match_port: Option<OneOrMany<u16>>,
    #[serde(default)]
    pub negate: bool,
    pub priority: Option<i64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OutDomainRuleConfig {
    pub r#match: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub priority: Option<i64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OutDomainPatternRuleConfig {
    pub r#match: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub priority: Option<i64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OutFallbackRuleConfig {}
