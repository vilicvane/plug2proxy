use serde::{Deserialize, Deserializer, de};

use crate::{
  out::OutExitConfig,
  route::{
    AnyRule,
    rule::{
      AddressRule, AndRule, AnyDomainMatcher, DomainRule, FallbackRule, GeoIpRule, ProtocolRule,
    },
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

/// 用户配置是一层平铺的对象，内部拆成两层：filter（匹配条件与 `negate`）
/// 和 common（`priority` 与 `exit`）。
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum RouteRuleConfig {
  #[serde(rename = "geoip")]
  GeoIp(FullRuleConfig<GeoIpFilterConfig>),
  #[serde(rename = "address")]
  Address(FullRuleConfig<AddressFilterConfig>),
  #[serde(rename = "domain")]
  Domain(FullRuleConfig<DomainFilterConfig>),
  #[serde(rename = "protocol")]
  Protocol(FullRuleConfig<ProtocolFilterConfig>),
  #[serde(rename = "fallback")]
  Fallback(FallbackRuleConfig),
  #[serde(rename = "and")]
  And(AndRuleConfig),
}

impl RouteRuleConfig {
  pub fn into_rule(self, priority_default: i64) -> AnyRule {
    match self {
      RouteRuleConfig::GeoIp(config) => {
        config.into_rule(priority_default, GeoIpFilterConfig::into_rule)
      }
      RouteRuleConfig::Address(config) => {
        config.into_rule(priority_default, AddressFilterConfig::into_rule)
      }
      RouteRuleConfig::Domain(config) => {
        config.into_rule(priority_default, DomainFilterConfig::into_rule)
      }
      RouteRuleConfig::Protocol(config) => {
        config.into_rule(priority_default, ProtocolFilterConfig::into_rule)
      }
      RouteRuleConfig::Fallback(config) => FallbackRule {
        exits: config.exit.into(),
      }
      .into(),
      RouteRuleConfig::And(config) => {
        let priority = config.priority.unwrap_or(priority_default);

        AndRule {
          rules: config
            .r#match
            .into_iter()
            .map(RouteRuleFilterConfig::into_condition_rule)
            .collect(),
          priority,
          exits: config.exit.into(),
        }
        .into()
      }
    }
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct FullRuleConfig<TFilter> {
  #[serde(flatten)]
  pub filter: TFilter,
  #[serde(flatten)]
  pub common: RuleCommonConfig,
}

impl<TFilter> FullRuleConfig<TFilter> {
  fn into_rule(
    self,
    priority_default: i64,
    build_rule: impl FnOnce(TFilter, i64, Vec<crate::primitives::OutExit>) -> AnyRule,
  ) -> AnyRule {
    let priority = self.common.priority.unwrap_or(priority_default);
    build_rule(self.filter, priority, self.common.exit.into())
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuleCommonConfig {
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

/// `type: "and"`：组内所有条件同时命中时才命中。条件只含 filter 层，
/// `priority` 与 `exit` 由组级配置提供。
#[derive(Clone, Debug, Deserialize)]
pub struct AndRuleConfig {
  pub r#match: Vec<RouteRuleFilterConfig>,
  pub priority: Option<i64>,
  pub exit: SerdeOneOrMany<OutExitConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum RouteRuleFilterConfig {
  #[serde(rename = "geoip")]
  GeoIp(GeoIpFilterConfig),
  #[serde(rename = "address")]
  Address(AddressFilterConfig),
  #[serde(rename = "domain")]
  Domain(DomainFilterConfig),
  #[serde(rename = "protocol")]
  Protocol(ProtocolFilterConfig),
}

impl RouteRuleFilterConfig {
  /// 转换为 AND 组内的条件规则：只提供匹配条件，`priority`/`exits`
  /// 不参与求值（由组承担）。
  fn into_condition_rule(self) -> AnyRule {
    match self {
      RouteRuleFilterConfig::GeoIp(filter) => {
        GeoIpFilterConfig::into_rule(filter, i64::MAX, Vec::new())
      }
      RouteRuleFilterConfig::Address(filter) => {
        AddressFilterConfig::into_rule(filter, i64::MAX, Vec::new())
      }
      RouteRuleFilterConfig::Domain(filter) => {
        DomainFilterConfig::into_rule(filter, i64::MAX, Vec::new())
      }
      RouteRuleFilterConfig::Protocol(filter) => {
        ProtocolFilterConfig::into_rule(filter, i64::MAX, Vec::new())
      }
    }
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct GeoIpFilterConfig {
  pub r#match: SerdeOneOrMany<String>,
  #[serde(default)]
  pub negate: bool,
}

impl GeoIpFilterConfig {
  fn into_rule(self, priority: i64, exits: Vec<crate::primitives::OutExit>) -> AnyRule {
    GeoIpRule {
      matches: self.r#match.into(),
      priority,
      negate: self.negate,
      exits,
    }
    .into()
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AddressFilterConfig {
  pub match_ip: Option<SerdeOneOrMany<SerdeIpNet>>,
  pub match_port: Option<SerdeOneOrMany<u16>>,
  #[serde(default)]
  pub negate: bool,
}

impl AddressFilterConfig {
  fn into_rule(self, priority: i64, exits: Vec<crate::primitives::OutExit>) -> AnyRule {
    AddressRule {
      match_ips: self.match_ip.map(|ip_nets| ip_nets.into()),
      match_ports: self.match_port.map(|match_port| match_port.into()),
      priority,
      negate: self.negate,
      exits,
    }
    .into()
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DomainFilterConfig {
  pub r#match: SerdeOneOrMany<DomainMatcherConfig>,
  #[serde(default)]
  pub negate: bool,
  /// 仅在 DNS 阶段生效（不参与连接路由）。AND 组内条件下无意义。
  #[serde(default)]
  pub dns_only: bool,
}

impl DomainFilterConfig {
  fn into_rule(self, priority: i64, exits: Vec<crate::primitives::OutExit>) -> AnyRule {
    DomainRule {
      matchers: self.r#match.into(),
      priority,
      negate: self.negate,
      exits,
      dns_only: self.dns_only,
    }
    .into()
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProtocolFilterConfig {
  pub r#match: SerdeOneOrMany<crate::primitives::SniffedProtocol>,
  #[serde(default)]
  pub negate: bool,
}

impl ProtocolFilterConfig {
  fn into_rule(self, priority: i64, exits: Vec<crate::primitives::OutExit>) -> AnyRule {
    ProtocolRule {
      matches: self.r#match.into(),
      priority,
      negate: self.negate,
      exits,
    }
    .into()
  }
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
  fn and_rule_shares_priority_and_exits_across_conditions() {
    let config: RouteConfig = serde_json::from_str(
      r#"{
        "rules": [{
          "type": "and",
          "match": [
            { "type": "domain", "match": "okx.com" },
            { "type": "address", "match_port": 443, "negate": true },
            { "type": "protocol", "match": "ssh" },
            { "type": "geoip", "match": "JP" }
          ],
          "priority": 10,
          "exit": "hk"
        }]
      }"#,
    )
    .unwrap();
    let rules: Vec<AnyRule> = config.into();
    let [AnyRule::And(rule)] = rules.as_slice() else {
      panic!("expected one AND rule");
    };

    assert_eq!(rule.priority, 10);
    assert_eq!(rule.exits, [crate::primitives::OutExit::from("hk")]);

    let [
      AnyRule::Domain(domain_rule),
      AnyRule::Address(address_rule),
      AnyRule::Protocol(_),
      AnyRule::GeoIp(_),
    ] = rule.rules.as_slice()
    else {
      panic!("expected domain + address + protocol + geoip conditions");
    };
    assert!(!domain_rule.negate);
    assert!(address_rule.negate);
    // 条件只提供匹配，不携带组的 exit。
    assert!(domain_rule.exits.is_empty());
    assert!(address_rule.exits.is_empty());
  }

  #[test]
  fn domain_pattern_rule_is_rejected() {
    assert!(
      serde_json::from_str::<RouteConfig>(
        r#"{
        "rules": [{
          "type": "domain_pattern",
          "match": "(?:^|\\.)bitget",
          "exit": "mo"
        }]
      }"#,
      )
      .is_err()
    );
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

  #[test]
  fn protocol_rule_accepts_lowercase_protocols() {
    let config: RouteConfig = serde_json::from_str(
      r#"{
        "rules": [{
          "type": "protocol",
          "match": ["ssh", "tls"],
          "priority": 5,
          "exit": "DIRECT"
        }]
      }"#,
    )
    .unwrap();
    let rules: Vec<AnyRule> = config.into();
    let [AnyRule::Protocol(rule)] = rules.as_slice() else {
      panic!("expected one protocol rule");
    };

    assert_eq!(
      rule.matches,
      [
        crate::primitives::SniffedProtocol::Ssh,
        crate::primitives::SniffedProtocol::Tls
      ]
    );
    assert_eq!(rule.priority, 5);
  }

  #[test]
  fn protocol_rule_rejects_unknown_or_uppercase_protocols() {
    for protocol in ["smtp", "SSH"] {
      assert!(
        serde_json::from_str::<RouteConfig>(&format!(
          r#"{{
            "rules": [{{
              "type": "protocol",
              "match": "{protocol}",
              "exit": "DIRECT"
            }}]
          }}"#
        ))
        .is_err()
      );
    }
  }
}
