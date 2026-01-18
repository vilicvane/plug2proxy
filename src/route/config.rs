use std::sync::Arc;

use itertools::Itertools;
use lowkit::SerdeRegex;
use serde::Deserialize;

use crate::{
  out::{OutExit, OutExitConfig},
  route::{
    AnyRule,
    rule::{AddressRule, DomainPatternRule, DomainRule, FallbackRule, GeoIpRule},
  },
  utils::serde::{SerdeIpNet, SerdeOneOrMany},
};

#[derive(Clone, Deserialize)]
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
  pub fn into_rule(self, default_exits: Vec<OutExit>, priority: i64) -> Arc<AnyRule> {
    match self {
      RuleConfig::GeoIp(config) => Arc::new(
        GeoIpRule {
          matches: config.r#match.into(),
          priority: config.priority.unwrap_or(priority),
          negate: config.negate,
          exits: merge_exits(default_exits, config.exit),
        }
        .into(),
      ),
      RuleConfig::Address(config) => Arc::new(
        AddressRule {
          match_ips: config.match_ip.map(|ip_nets| {
            let ip_nets: Vec<SerdeIpNet> = ip_nets.into();
            ip_nets.into_iter().map_into().collect()
          }),
          match_ports: config.match_port.map(|match_port| match_port.into()),
          priority: config.priority.unwrap_or(priority),
          negate: config.negate,
          exits: merge_exits(default_exits, config.exit),
        }
        .into(),
      ),
      RuleConfig::Domain(config) => Arc::new(
        DomainRule {
          matches: config.r#match.into(),
          priority: config.priority.unwrap_or(priority),
          negate: config.negate,
          exits: merge_exits(default_exits, config.exit),
        }
        .into(),
      ),
      RuleConfig::DomainPattern(config) => Arc::new(
        DomainPatternRule {
          matches: config.r#match.into(),
          priority: config.priority.unwrap_or(priority),
          negate: config.negate,
          exits: merge_exits(default_exits, config.exit),
        }
        .into(),
      ),
      RuleConfig::Fallback(config) => Arc::new(
        FallbackRule {
          exits: merge_exits(default_exits, config.exit),
        }
        .into(),
      ),
    }
  }
}

fn merge_exits(default_exits: Vec<OutExit>, exits: SerdeOneOrMany<OutExitConfig>) -> Vec<OutExit> {
  default_exits
    .clone()
    .into_iter()
    .chain(Vec::from(exits).into_iter().map_into())
    .collect()
}

#[derive(Clone, Deserialize)]
pub struct GeoIpRuleConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Deserialize)]
pub struct AddressRuleConfig {
  pub match_ip: Option<SerdeOneOrMany<SerdeIpNet>>,
  pub match_port: Option<SerdeOneOrMany<u16>>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Deserialize)]
pub struct DomainRuleConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Deserialize)]
pub struct DomainPatternRuleConfig {
  pub r#match: SerdeOneOrMany<SerdeRegex>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Deserialize)]
pub struct FallbackRuleConfig {
  pub exit: SerdeOneOrMany<OutExitConfig>,
}
