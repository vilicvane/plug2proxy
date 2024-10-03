use std::str::FromStr;

use crate::tunnel::TunnelId;

use super::config::{InRuleConfig, OutRuleConfig};

#[derive(Clone)]
pub enum Rule {
    GeoIp(GeoIpRule),
    Domain(DomainRule),
}

impl Rule {
    pub fn from_in_rule_config(config: InRuleConfig) -> Self {
        match config {
            InRuleConfig::GeoIp(config) => Rule::GeoIp(GeoIpRule {
                match_: config.match_.into_vec(),
                out: config.out.into_vec(),
                priority: u32::MAX,
                negate: config.negate,
            }),
            InRuleConfig::Domain(config) => Rule::Domain(DomainRule {
                match_: config
                    .match_
                    .into_vec()
                    .into_iter()
                    .filter_map(|pattern| {
                        regex::Regex::from_str(&pattern)
                            .inspect_err(|_| {
                                log::warn!("invalid domain rule match pattern: {}", pattern);
                            })
                            .ok()
                    })
                    .collect::<Vec<_>>(),
                out: config.out.into_vec(),
                priority: u32::MAX,
                negate: config.negate,
            }),
        }
    }

    pub fn from_out_rule_config(
        tunnel_id: TunnelId,
        priority_default: u32,
        config: OutRuleConfig,
    ) -> Self {
        match config {
            OutRuleConfig::GeoIp(config) => Rule::GeoIp(GeoIpRule {
                match_: config.match_.into_vec(),
                out: vec![tunnel_id.to_string()],
                priority: config.priority.unwrap_or(priority_default),
                negate: config.negate,
            }),
            OutRuleConfig::Domain(config) => Rule::Domain(DomainRule {
                match_: config
                    .match_
                    .into_vec()
                    .into_iter()
                    .filter_map(|pattern| {
                        regex::Regex::from_str(&pattern)
                            .inspect_err(|_| {
                                log::warn!("invalid domain rule match pattern: {}", pattern);
                            })
                            .ok()
                    })
                    .collect::<Vec<_>>(),
                out: vec![tunnel_id.to_string()],
                priority: config.priority.unwrap_or(priority_default),
                negate: config.negate,
            }),
        }
    }

    pub fn get_priority(&self) -> u32 {
        match self {
            Rule::GeoIp(rule) => rule.priority,
            Rule::Domain(rule) => rule.priority,
        }
    }

    pub fn get_out_tags(&self) -> Vec<String> {
        match self {
            Rule::GeoIp(rule) => rule.out.clone(),
            Rule::Domain(rule) => rule.out.clone(),
        }
    }
}

#[derive(Clone)]
pub struct GeoIpRule {
    pub match_: Vec<String>,
    pub out: Vec<String>,
    pub priority: u32,
    pub negate: bool,
}

#[derive(Clone)]
pub struct DomainRule {
    pub match_: Vec<regex::Regex>,
    pub out: Vec<String>,
    pub priority: u32,
    pub negate: bool,
}
