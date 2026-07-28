use lowkit::SerdeRegex;
use serde::{Deserialize, Deserializer, de};

use crate::{
  out::OutExitConfig,
  route::{
    AnyRule,
    rule::{AddressRule, AnyDomainMatcher, DomainPatternRule, DomainRule, FallbackRule, GeoIpRule},
  },
  utils::serde::{SerdeIpNet, SerdeOneOrMany},
};

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Deserialize)]
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
        matchers: config.r#match.into(),
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

#[derive(Clone, Debug, Deserialize)]
pub struct GeoIpRuleConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AddressRuleConfig {
  pub match_ip: Option<SerdeOneOrMany<SerdeIpNet>>,
  pub match_port: Option<SerdeOneOrMany<u16>>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DomainRuleConfig {
  pub r#match: SerdeOneOrMany<DomainMatcherConfig>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Debug)]
pub struct DomainMatcherConfig(AnyDomainMatcher);

impl<'de> Deserialize<'de> for DomainMatcherConfig {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    let expression = String::deserialize(deserializer)?;
    AnyDomainMatcher::parse(&expression)
      .map(Self)
      .map_err(de::Error::custom)
  }
}

impl From<DomainMatcherConfig> for AnyDomainMatcher {
  fn from(value: DomainMatcherConfig) -> Self {
    value.0
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DomainPatternRuleConfig {
  pub r#match: SerdeOneOrMany<SerdeRegex>,
  #[serde(default)]
  pub negate: bool,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FallbackRuleConfig {
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::route::AnyDomainMatcher;

  #[test]
  fn domain_rule_accepts_plain_geosite_and_regex_matchers() {
    let config: RouteConfig = serde_json::from_str(
      r#"{
        "rules": [{
          "type": "domain",
          "match": ["okx.com", "geosite:okx", "regex:^api\\.okx\\.com$"],
          "exit": "hk"
        }],
        "priority": 100
      }"#,
    )
    .unwrap();
    let rules: Vec<AnyRule> = config.into();
    let [AnyRule::Domain(rule)] = rules.as_slice() else {
      panic!("expected one domain rule");
    };

    assert!(matches!(
      rule.matchers.as_slice(),
      [
        AnyDomainMatcher::DomainName(_),
        AnyDomainMatcher::Geosite(_),
        AnyDomainMatcher::Regex(_)
      ]
    ));
    assert_eq!(rule.priority, 100);
  }

  #[test]
  fn legacy_domain_pattern_config_preserves_its_wire_rule() {
    let config: RouteConfig = serde_json::from_str(
      r#"{
        "rules": [{
          "type": "domain_pattern",
          "match": ["(?:^|\\.)bitget", "(^|\\.)bitapi\\."],
          "priority": 30,
          "exit": "mo"
        }]
      }"#,
    )
    .unwrap();
    let rules: Vec<AnyRule> = config.into();
    let [AnyRule::DomainPattern(rule)] = rules.as_slice() else {
      panic!("expected legacy config to produce one legacy domain pattern rule");
    };

    assert_eq!(rule.matches.len(), 2);
    assert_eq!(rule.priority, 30);
  }

  #[test]
  fn domain_rule_rejects_invalid_regex_matchers() {
    assert!(
      serde_json::from_str::<RouteConfig>(
        r#"{
          "rules": [{
            "type": "domain",
            "match": "regex:(",
            "exit": "hk"
          }]
        }"#,
      )
      .is_err()
    );
  }
}
