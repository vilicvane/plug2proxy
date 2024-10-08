use std::str::FromStr as _;

use itertools::Itertools;

use crate::{
    route::rule::{
        AddressRule, DomainPatternRule, DomainRule, DynRuleBox, FallbackRule, GeoIpRule,
    },
    utils::{net::parse_ip_net, OneOrMany},
};

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum InRuleConfig {
    #[serde(rename = "geoip")]
    GeoIp(InGeoIpRuleConfig),
    #[serde(rename = "address")]
    Address(InAddressRuleConfig),
    #[serde(rename = "domain")]
    Domain(InDomainRuleConfig),
    #[serde(rename = "domain_pattern")]
    DomainPattern(InDomainPatternRuleConfig),
    #[serde(rename = "fallback")]
    Fallback(InFallbackRuleConfig),
}

impl InRuleConfig {
    pub fn into_rule(self) -> DynRuleBox {
        match self {
            InRuleConfig::GeoIp(config) => Box::new(GeoIpRule {
                matches: config.r#match.into_vec(),
                labels: config.out.into_vec(),
                priority: i64::MIN,
                negate: config.negate,
            }),
            InRuleConfig::Address(config) => Box::new(AddressRule {
                match_ips: config.match_ip.map(|match_ip| {
                    match_ip
                        .into_vec()
                        .iter()
                        .map(|ip| {
                            parse_ip_net(ip).unwrap_or_else(|_| panic!("invalid ip address: {ip}"))
                        })
                        .collect_vec()
                }),
                match_ports: config.match_port.map(|match_port| match_port.into_vec()),
                labels: config.out.into_vec(),
                priority: i64::MIN,
                negate: config.negate,
            }),
            InRuleConfig::Domain(config) => Box::new(DomainRule {
                matches: config.r#match.into_vec(),
                labels: config.out.into_vec(),
                priority: i64::MIN,
                negate: config.negate,
            }),
            InRuleConfig::DomainPattern(config) => Box::new(DomainPatternRule {
                matches: config
                    .r#match
                    .into_vec()
                    .into_iter()
                    .map(|pattern| {
                        regex::Regex::from_str(&pattern).unwrap_or_else(|_| {
                            panic!("invalid domain_pattern rule match pattern: {pattern}")
                        })
                    })
                    .collect::<Vec<_>>(),
                labels: config.out.into_vec(),
                priority: i64::MIN,
                negate: config.negate,
            }),
            InRuleConfig::Fallback(config) => Box::new(FallbackRule {
                labels: config.out.into_vec(),
            }),
        }
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct InGeoIpRuleConfig {
    pub r#match: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub out: OneOrMany<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct InAddressRuleConfig {
    pub match_ip: Option<OneOrMany<String>>,
    pub match_port: Option<OneOrMany<u16>>,
    #[serde(default)]
    pub negate: bool,
    pub out: OneOrMany<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct InDomainRuleConfig {
    pub r#match: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub out: OneOrMany<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct InDomainPatternRuleConfig {
    pub r#match: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub out: OneOrMany<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct InFallbackRuleConfig {
    pub out: OneOrMany<String>,
}
