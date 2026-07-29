use std::net::SocketAddr;

use enum_dispatch::enum_dispatch;
use itertools::Itertools as _;
use lowkit::SerdeRegex;
use regex::Regex;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
  primitives::{OutExit, SniffedProtocol},
  route::Geosite,
  utils::serde::SerdeIpNet,
};

#[enum_dispatch(AnyRule)]
pub trait Rule: Serialize + DeserializeOwned + Send + Sync {
  fn priority(&self) -> i64;

  fn exits(&self) -> &[OutExit];

  fn requires_geosite(&self) -> bool {
    false
  }

  /// 返回 `Some(命中原因)` 表示命中；原因由匹配过程产出，复合规则
  /// （AND）的原因来自各子规则的命中结果。
  fn test(
    &self,
    address: &Option<SocketAddr>,
    domain: &Option<String>,
    protocol: &Option<SniffedProtocol>,
    region_codes: &Option<Vec<String>>,
    geosite: &Geosite,
  ) -> Option<Vec<RuleKind>>;
}

#[enum_dispatch]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AnyRule {
  GeoIp(GeoIpRule),
  Address(AddressRule),
  Domain(DomainRule),
  Protocol(ProtocolRule),
  Fallback(FallbackRule),
  // 新增变体必须保持在末尾，保证 postcard 线上兼容。
  And(AndRule),
}

/// 命中原因（按什么种类的条件匹配的）。
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum RuleKind {
  GeoIp,
  Address,
  Domain,
  Protocol,
  Fallback,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoIpRule {
  pub matches: Vec<String>,
  pub priority: i64,
  pub negate: bool,
  pub exits: Vec<OutExit>,
}

impl Rule for GeoIpRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn test(
    &self,
    _address: &Option<SocketAddr>,
    _domain: &Option<String>,
    _protocol: &Option<SniffedProtocol>,
    region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> Option<Vec<RuleKind>> {
    let region_codes = region_codes.as_ref()?;

    let mut condition = self
      .matches
      .iter()
      .any(|match_region| region_codes.iter().any(|region| region == match_region));

    if self.negate {
      condition = !condition;
    }

    condition.then(|| vec![RuleKind::GeoIp])
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressRule {
  pub match_ips: Option<Vec<SerdeIpNet>>,
  pub match_ports: Option<Vec<u16>>,
  pub priority: i64,
  pub negate: bool,
  pub exits: Vec<OutExit>,
}

impl Rule for AddressRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn test(
    &self,
    address: &Option<SocketAddr>,
    _domain: &Option<String>,
    _protocol: &Option<SniffedProtocol>,
    _region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> Option<Vec<RuleKind>> {
    let address = address.as_ref()?;

    if self.match_ips.is_none() && self.match_ports.is_none() {
      return None;
    }

    let port_matched = if let Some(match_ports) = &self.match_ports {
      match_ports.iter().any(|port| *port == address.port())
    } else {
      true
    };

    let ip_matched = if let Some(match_ips) = &self.match_ips {
      match_ips.iter().any(|net| net.contains(&address.ip()))
    } else {
      true
    };

    let mut condition = ip_matched && port_matched;

    if self.negate {
      condition = !condition;
    }

    condition.then(|| vec![RuleKind::Address])
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRule {
  pub matchers: Vec<AnyDomainMatcher>,
  pub priority: i64,
  pub negate: bool,
  pub exits: Vec<OutExit>,
}

impl Rule for DomainRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn requires_geosite(&self) -> bool {
    self.matchers.iter().any(AnyDomainMatcher::requires_geosite)
  }

  fn test(
    &self,
    _address: &Option<SocketAddr>,
    domain: &Option<String>,
    _protocol: &Option<SniffedProtocol>,
    _region_codes: &Option<Vec<String>>,
    geosite: &Geosite,
  ) -> Option<Vec<RuleKind>> {
    let domain = domain.as_ref()?;

    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut condition = self
      .matchers
      .iter()
      .any(|matcher| matcher.matches(&domain, geosite));

    if self.negate {
      condition = !condition;
    }

    condition.then(|| vec![RuleKind::Domain])
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolRule {
  pub matches: Vec<SniffedProtocol>,
  pub priority: i64,
  pub negate: bool,
  pub exits: Vec<OutExit>,
}

impl Rule for ProtocolRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn test(
    &self,
    _address: &Option<SocketAddr>,
    _domain: &Option<String>,
    protocol: &Option<SniffedProtocol>,
    _region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> Option<Vec<RuleKind>> {
    let protocol = protocol.as_ref()?;

    let condition = self.matches.contains(protocol);
    let condition = if self.negate { !condition } else { condition };

    condition.then(|| vec![RuleKind::Protocol])
  }
}

#[enum_dispatch(AnyDomainMatcher)]
pub trait DomainMatcher: Send + Sync {
  fn matches(&self, domain: &str, geosite: &Geosite) -> bool;
}

#[enum_dispatch]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AnyDomainMatcher {
  DomainName(DomainNameMatcher),
  Geosite(GeositeDomainMatcher),
  Regex(DomainRegexMatcher),
}

impl AnyDomainMatcher {
  fn requires_geosite(&self) -> bool {
    matches!(self, AnyDomainMatcher::Geosite(_))
  }

  pub fn parse(expression: &str) -> Result<Self, regex::Error> {
    if expression.starts_with(GeositeDomainMatcher::PREFIX) {
      Ok(AnyDomainMatcher::Geosite(GeositeDomainMatcher::parse(
        expression,
      )))
    } else if expression.starts_with(DomainRegexMatcher::PREFIX) {
      DomainRegexMatcher::parse(expression).map(AnyDomainMatcher::Regex)
    } else {
      Ok(AnyDomainMatcher::DomainName(DomainNameMatcher::new(
        expression.to_owned(),
      )))
    }
  }
}

impl From<String> for AnyDomainMatcher {
  fn from(value: String) -> Self {
    Self::parse(&value).unwrap_or_else(|error| panic!("invalid domain matcher {value:?}: {error}"))
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainNameMatcher {
  domain: String,
}

impl DomainNameMatcher {
  fn new(domain: String) -> Self {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();

    assert!(!domain.is_empty(), "domain matcher must not be empty");

    Self { domain }
  }
}

impl DomainMatcher for DomainNameMatcher {
  fn matches(&self, domain: &str, _geosite: &Geosite) -> bool {
    domain == self.domain
      || domain.ends_with(&self.domain) && domain[..domain.len() - self.domain.len()].ends_with('.')
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GeositeDomainMatcher {
  pub(super) site: String,
  pub(super) attributes: Vec<String>,
}

impl GeositeDomainMatcher {
  const PREFIX: &str = "geosite:";

  pub(super) fn parse(expression: &str) -> Self {
    let selector = expression
      .strip_prefix(Self::PREFIX)
      .expect("Geosite matcher must start with geosite:");
    let mut parts = selector.split('@');
    let site = parts.next().unwrap();

    assert!(!site.is_empty(), "Geosite list name must not be empty");

    let attributes = parts
      .map(|attribute| {
        assert!(!attribute.is_empty(), "Geosite attribute must not be empty");
        attribute.to_ascii_lowercase()
      })
      .collect();

    Self {
      site: site.to_ascii_uppercase(),
      attributes,
    }
  }
}

impl DomainMatcher for GeositeDomainMatcher {
  fn matches(&self, domain: &str, geosite: &Geosite) -> bool {
    geosite.matches(self, domain)
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRegexMatcher {
  pattern: SerdeRegex,
}

impl DomainRegexMatcher {
  const PREFIX: &str = "regex:";

  fn parse(expression: &str) -> Result<Self, regex::Error> {
    let pattern = expression
      .strip_prefix(Self::PREFIX)
      .expect("regex matcher must start with regex:");

    Regex::new(pattern).map(|pattern| Self {
      pattern: pattern.into(),
    })
  }
}

impl DomainMatcher for DomainRegexMatcher {
  fn matches(&self, domain: &str, _geosite: &Geosite) -> bool {
    self.pattern.is_match(domain)
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FallbackRule {
  pub exits: Vec<OutExit>,
}

impl Rule for FallbackRule {
  fn priority(&self) -> i64 {
    i64::MAX
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn test(
    &self,
    _address: &Option<SocketAddr>,
    _domain: &Option<String>,
    _protocol: &Option<SniffedProtocol>,
    _region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> Option<Vec<RuleKind>> {
    Some(vec![RuleKind::Fallback])
  }
}

/// `type: "and"` 规则：组内所有子规则同时命中时该规则才命中。
///
/// 子规则只提供匹配条件（来自配置的 filter 层），命中后累计的是组自身
/// 的 `exits`，排序用的也是组自身的 `priority`。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AndRule {
  pub rules: Vec<AnyRule>,
  pub priority: i64,
  pub exits: Vec<OutExit>,
}

impl Rule for AndRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn requires_geosite(&self) -> bool {
    self.rules.iter().any(Rule::requires_geosite)
  }

  fn test(
    &self,
    address: &Option<SocketAddr>,
    domain: &Option<String>,
    protocol: &Option<SniffedProtocol>,
    region_codes: &Option<Vec<String>>,
    geosite: &Geosite,
  ) -> Option<Vec<RuleKind>> {
    if self.rules.is_empty() {
      return None;
    }

    let kinds = self
      .rules
      .iter()
      .map(|rule| rule.test(address, domain, protocol, region_codes, geosite))
      .collect::<Option<Vec<_>>>()?
      .into_iter()
      .flatten()
      .unique()
      .collect();

    Some(kinds)
  }
}

#[cfg(test)]
mod tests {
  use moka::sync::Cache;

  use super::*;

  #[test]
  fn domain_name_matcher_matches_root_and_subdomains_case_insensitively() {
    let geosite = empty_geosite();
    let matcher = DomainNameMatcher::new("Example.COM.".to_owned());

    assert!(matcher.matches("example.com", &geosite));
    assert!(matcher.matches("www.example.com", &geosite));
    assert!(!matcher.matches("notexample.com", &geosite));
  }

  #[test]
  fn parses_geosite_list_and_attributes() {
    let AnyDomainMatcher::Geosite(matcher) =
      AnyDomainMatcher::from("geosite:geolocation-!cn@cn@ads".to_owned())
    else {
      panic!("expected Geosite matcher");
    };

    assert_eq!(matcher.site, "GEOLOCATION-!CN");
    assert_eq!(matcher.attributes, ["cn", "ads"]);
  }

  #[test]
  fn regex_matcher_matches_normalized_domains() {
    let geosite = empty_geosite();
    let matcher = AnyDomainMatcher::parse(r"regex:(?:^|\.)bitget").unwrap();

    assert!(matcher.matches("bitget.com", &geosite));
    assert!(matcher.matches("api.bitget.com", &geosite));
    assert!(!matcher.matches("notbitget.com", &geosite));
    assert!(AnyDomainMatcher::parse("regex:(").is_err());
  }

  #[test]
  fn domain_matchers_survive_postcard_round_trip() {
    let rule = DomainRule {
      matchers: vec![
        "okx.com".to_owned().into(),
        "geosite:okx".to_owned().into(),
        "regex:^api\\.okx\\.com$".to_owned().into(),
      ],
      priority: 100,
      negate: false,
      exits: vec![OutExit::Direct],
    };
    let encoded = postcard::to_allocvec(&rule).unwrap();
    let decoded: DomainRule = postcard::from_bytes(&encoded).unwrap();

    assert!(matches!(
      decoded.matchers.as_slice(),
      [
        AnyDomainMatcher::DomainName(_),
        AnyDomainMatcher::Geosite(_),
        AnyDomainMatcher::Regex(_)
      ]
    ));
  }

  #[test]
  fn and_rule_matches_only_when_all_sub_rules_match() {
    let geosite = empty_geosite();
    let domain = Some("example.com".to_owned());
    let rule = AndRule {
      rules: vec![
        DomainRule {
          matchers: vec!["example.com".to_owned().into()],
          priority: i64::MAX,
          negate: false,
          exits: vec![],
        }
        .into(),
        AddressRule {
          match_ips: None,
          match_ports: Some(vec![443]),
          priority: i64::MAX,
          negate: false,
          exits: vec![],
        }
        .into(),
      ],
      priority: 10,
      exits: vec![OutExit::Proxy],
    };

    // 命中原因是各子规则命中结果的并集。
    let address = Some("203.0.113.8:443".parse().unwrap());
    assert_eq!(
      rule.test(&address, &domain, &None, &None, &geosite),
      Some(vec![RuleKind::Domain, RuleKind::Address])
    );

    // 任一子规则不命中时整组不命中。
    let address = Some("203.0.113.8:80".parse().unwrap());
    assert_eq!(rule.test(&address, &domain, &None, &None, &geosite), None);
    assert_eq!(rule.test(&None, &domain, &None, &None, &geosite), None);

    // 空组永不命中。
    let empty = AndRule {
      rules: vec![],
      priority: 10,
      exits: vec![OutExit::Proxy],
    };
    assert_eq!(empty.test(&address, &domain, &None, &None, &geosite), None);
  }

  #[test]
  fn and_rule_survives_postcard_round_trip() {
    let rule: AnyRule = AndRule {
      rules: vec![
        ProtocolRule {
          matches: vec![SniffedProtocol::Tls],
          priority: i64::MAX,
          negate: false,
          exits: vec![],
        }
        .into(),
        DomainRule {
          matchers: vec!["example.com".to_owned().into()],
          priority: i64::MAX,
          negate: true,
          exits: vec![],
        }
        .into(),
      ],
      priority: 10,
      exits: vec![OutExit::Proxy],
    }
    .into();
    let encoded = postcard::to_allocvec(&rule).unwrap();
    let decoded: AnyRule = postcard::from_bytes(&encoded).unwrap();

    let AnyRule::And(decoded) = decoded else {
      panic!("expected And rule");
    };
    assert_eq!(decoded.rules.len(), 2);
    assert_eq!(decoded.priority, 10);
    assert_eq!(decoded.exits, [OutExit::Proxy]);
  }

  fn empty_geosite() -> Geosite {
    Geosite::new(
      std::env::temp_dir().join(format!("plug2proxy-{}", uuid::Uuid::new_v4())),
      Cache::new(1),
    )
  }
}
