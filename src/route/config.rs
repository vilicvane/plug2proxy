use lowkit::SerdeRegex;
use serde::Deserialize;

use crate::{
  out::OutExitConfig,
  route::{
    AnyRule,
    rule::{AddressRule, DomainPatternRule, DomainRule, FallbackRule, GeoIpRule},
  },
  utils::serde::{SerdeIpNet, SerdeOneOrMany},
};

#[derive(Clone, Deserialize)]
pub struct RouteConfig {
  pub rules: Vec<RouteRuleConfig>,
  pub priority: Option<i64>,
}

impl From<RouteConfig> for Vec<AnyRule> {
  fn from(RouteConfig { rules, priority }: RouteConfig) -> Self {
    let priority = priority.unwrap_or(i64::MAX);

    rules
      .into_iter()
      .map(|rule| rule.into_rule(priority))
      .collect()
  }
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RouteRuleConfig {
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

impl RouteRuleConfig {
  pub fn into_rule(self, priority_default: i64) -> AnyRule {
    match self {
      RouteRuleConfig::GeoIp(config) => GeoIpRule {
        matches: config.r#match.into(),
        priority: config.priority.unwrap_or(priority_default),
        negate: config.negate,
        exits: config.exit.into(),
      }
      .into(),
      RouteRuleConfig::Address(config) => AddressRule {
        match_ips: config.match_ip.map(|ip_nets| ip_nets.into()),
        match_ports: config.match_port.map(|match_port| match_port.into()),
        priority: config.priority.unwrap_or(priority_default),
        negate: config.negate,
        exits: config.exit.into(),
      }
      .into(),
      RouteRuleConfig::Domain(config) => DomainRule {
        matches: config.r#match.into(),
        priority: config.priority.unwrap_or(priority_default),
        negate: config.negate,
        exits: config.exit.into(),
      }
      .into(),
      RouteRuleConfig::DomainPattern(config) => DomainPatternRule {
        matches: config.r#match.into(),
        priority: config.priority.unwrap_or(priority_default),
        negate: config.negate,
        exits: config.exit.into(),
      }
      .into(),
      RouteRuleConfig::Fallback(config) => FallbackRule {
        exits: config.exit.into(),
      }
      .into(),
    }
  }
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
