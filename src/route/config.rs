use std::sync::Arc;

use crate::{
  out::OutExit,
  route::rule::{AddressRule, DomainPatternRule, DomainRule, FallbackRule, GeoIpRule, Rule},
  utils::serde::{SerdeIpNet, SerdeOneOrMany},
};

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RuleConfig {
  #[serde(rename = "geoip")]
  GeoIp(GeoIpRuleConfig),
  #[serde(rename = "address")]
  Address(AddressRuleConfig),
  #[serde(rename = "domain")]
  Domain(DomainRuleConfig),
  #[serde(rename = "domain_pattern")]
  DomainPattern(DomainPatternRuleConfig),
  #[serde(rename = "fallback")]
  Fallback(FallbackRuleConfig),
}

impl RuleConfig {
  pub fn into_rule(self, default_exits: Vec<OutExit>, priority: i64) -> Arc<dyn Rule> {
    match self {
      RuleConfig::GeoIp(config) => Arc::new(GeoIpRule {
        matches: config.r#match.into(),
        priority: config.priority.unwrap_or(priority),
        negate: config.negate,
        exits: merge_exits(default_exits, config.exit),
      }),
      RuleConfig::Address(config) => Arc::new(AddressRule {
        match_ips: config.match_ip.map(|ip_nets| {
          let ip_nets: Vec<SerdeIpNet> = ip_nets.into();
          ip_nets.into_iter().map(|ip_net| *ip_net).collect()
        }),
        match_ports: config.match_port.map(|match_port| match_port.into()),
        priority: config.priority.unwrap_or(priority),
        negate: config.negate,
        exits: merge_exits(default_exits, config.exit),
      }),
      RuleConfig::Domain(config) => Arc::new(DomainRule {
        matches: config.r#match.into(),
        priority: config.priority.unwrap_or(priority),
        negate: config.negate,
        exits: merge_exits(default_exits, config.exit),
      }),
      RuleConfig::DomainPattern(config) => Arc::new(DomainPatternRule {
        matches: Vec::from(config.r#match)
          .into_iter()
          .map(|pattern| {
            pattern
              .parse()
              .unwrap_or_else(|_| panic!("invalid domain_pattern rule match pattern: {pattern}"))
          })
          .collect(),
        priority: config.priority.unwrap_or(priority),
        negate: config.negate,
        exits: merge_exits(default_exits, config.exit),
      }),
      RuleConfig::Fallback(config) => Arc::new(FallbackRule {
        exits: merge_exits(default_exits, config.exit),
      }),
    }
  }
}

fn merge_exits(default_exits: Vec<OutExit>, exits: SerdeOneOrMany<OutExit>) -> Vec<OutExit> {
  default_exits
    .clone()
    .into_iter()
    .chain::<Vec<OutExit>>(exits.into())
    .collect()
}

#[derive(Clone, serde::Deserialize)]
pub struct GeoIpRuleConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExit>,
}

#[derive(Clone, serde::Deserialize)]
pub struct AddressRuleConfig {
  pub match_ip: Option<SerdeOneOrMany<SerdeIpNet>>,
  pub match_port: Option<SerdeOneOrMany<u16>>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExit>,
}

#[derive(Clone, serde::Deserialize)]
pub struct DomainRuleConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExit>,
}

#[derive(Clone, serde::Deserialize)]
pub struct DomainPatternRuleConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExit>,
}

#[derive(Clone, serde::Deserialize)]
pub struct FallbackRuleConfig {
  pub exit: SerdeOneOrMany<OutExit>,
}
