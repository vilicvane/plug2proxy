use std::net::SocketAddr;

use enum_dispatch::enum_dispatch;
use lowkit::SerdeRegex;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{primitives::OutExit, route::Geosite, utils::serde::SerdeIpNet};

#[enum_dispatch(AnyRule)]
pub trait Rule: Serialize + DeserializeOwned + Send + Sync {
  fn priority(&self) -> i64;

  fn exits(&self) -> &[OutExit];

  fn test(
    &self,
    address: &Option<SocketAddr>,
    domain: &Option<String>,
    region_codes: &Option<Vec<String>>,
    geosite: &Geosite,
  ) -> bool;
}

#[enum_dispatch]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AnyRule {
  GeoIp(GeoIpRule),
  Address(AddressRule),
  Domain(DomainRule),
  DomainPattern(DomainPatternRule),
  Fallback(FallbackRule),
}

impl AnyRule {
  pub(super) fn uses_geosite(&self) -> bool {
    matches!(self, AnyRule::Domain(rule) if rule.uses_geosite())
  }
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
    region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> bool {
    region_codes.as_ref().is_some_and(|region_codes| {
      let mut condition = self
        .matches
        .iter()
        .any(|match_region| region_codes.iter().any(|region| region == match_region));

      if self.negate {
        condition = !condition;
      }

      condition
    })
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
    _region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> bool {
    let Some(address) = address else {
      return false;
    };

    if self.match_ips.is_none() && self.match_ports.is_none() {
      return false;
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

    condition
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRule {
  pub matchers: Vec<AnyDomainMatcher>,
  pub priority: i64,
  pub negate: bool,
  pub exits: Vec<OutExit>,
}

impl DomainRule {
  pub(super) fn uses_geosite(&self) -> bool {
    self.matchers.iter().any(AnyDomainMatcher::uses_geosite)
  }
}

impl Rule for DomainRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn test(
    &self,
    _address: &Option<SocketAddr>,
    domain: &Option<String>,
    _region_codes: &Option<Vec<String>>,
    geosite: &Geosite,
  ) -> bool {
    if let Some(domain) = domain {
      let domain = domain.trim_end_matches('.').to_ascii_lowercase();
      let mut condition = self
        .matchers
        .iter()
        .any(|matcher| matcher.matches(&domain, geosite));

      if self.negate {
        condition = !condition;
      }

      condition
    } else {
      false
    }
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
}

impl AnyDomainMatcher {
  fn uses_geosite(&self) -> bool {
    matches!(self, AnyDomainMatcher::Geosite(_))
  }
}

impl From<String> for AnyDomainMatcher {
  fn from(value: String) -> Self {
    if value.starts_with(GeositeDomainMatcher::PREFIX) {
      AnyDomainMatcher::Geosite(GeositeDomainMatcher::parse(&value))
    } else {
      AnyDomainMatcher::DomainName(DomainNameMatcher::new(value))
    }
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
pub struct DomainPatternRule {
  pub matches: Vec<SerdeRegex>,
  pub priority: i64,
  pub negate: bool,
  pub exits: Vec<OutExit>,
}

impl Rule for DomainPatternRule {
  fn priority(&self) -> i64 {
    self.priority
  }

  fn exits(&self) -> &[OutExit] {
    &self.exits
  }

  fn test(
    &self,
    _address: &Option<SocketAddr>,
    domain: &Option<String>,
    _region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> bool {
    if let Some(domain) = domain {
      let mut condition = self.matches.iter().any(|pattern| pattern.is_match(domain));

      if self.negate {
        condition = !condition;
      }

      condition
    } else {
      false
    }
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
    _region_codes: &Option<Vec<String>>,
    _geosite: &Geosite,
  ) -> bool {
    true
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
  fn domain_matchers_survive_postcard_round_trip() {
    let rule = DomainRule {
      matchers: vec!["okx.com".to_owned().into(), "geosite:okx".to_owned().into()],
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
        AnyDomainMatcher::Geosite(_)
      ]
    ));
  }

  fn empty_geosite() -> Geosite {
    Geosite::new(
      std::env::temp_dir().join(format!("plug2proxy-{}", uuid::Uuid::new_v4())),
      Cache::new(1),
    )
  }
}
