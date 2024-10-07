use std::str::FromStr as _;

use crate::{
    routing::rule::{DomainPatternRule, DomainRule, DynRuleBox, FallbackRule, GeoIpRule},
    utils::OneOrMany,
};

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum InRuleConfig {
    #[serde(rename = "geoip")]
    GeoIp(InGeoIpRuleConfig),
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
                    .filter_map(|pattern| {
                        regex::Regex::from_str(&pattern)
                            .inspect_err(|_| {
                                log::warn!(
                                    "invalid domain_pattern rule match pattern: {}",
                                    pattern
                                );
                            })
                            .ok()
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
