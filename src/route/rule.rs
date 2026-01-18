use std::net::SocketAddr;

use crate::out::OutExit;

pub trait Rule: Send + Sync {
  fn priority(&self) -> i64;

  fn exits(&self) -> &[OutExit];

  fn test(
    &self,
    address: SocketAddr,
    domain: &Option<String>,
    region_codes: &Option<Vec<String>>,
  ) -> bool;
}

#[derive(Clone, Debug)]
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
    _address: SocketAddr,
    _domain: &Option<String>,
    region_codes: &Option<Vec<String>>,
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

#[derive(Clone, Debug)]
pub struct AddressRule {
  pub match_ips: Option<Vec<ipnet::IpNet>>,
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
    address: SocketAddr,
    _domain: &Option<String>,
    _region_codes: &Option<Vec<String>>,
  ) -> bool {
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

#[derive(Clone, Debug)]
pub struct DomainRule {
  pub matches: Vec<String>,
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

  fn test(
    &self,
    _address: SocketAddr,
    domain: &Option<String>,
    _region_codes: &Option<Vec<String>>,
  ) -> bool {
    if let Some(domain) = domain {
      let mut condition = self.matches.iter().any(|match_domain| {
        domain == match_domain
          || domain.ends_with(match_domain)
            && domain[..domain.len() - match_domain.len()].ends_with('.')
      });

      if self.negate {
        condition = !condition;
      }

      condition
    } else {
      false
    }
  }
}

#[derive(Clone, Debug)]
pub struct DomainPatternRule {
  pub matches: Vec<regex::Regex>,
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
    _address: SocketAddr,
    domain: &Option<String>,
    _region_codes: &Option<Vec<String>>,
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

#[derive(Clone, Debug)]
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
    _address: SocketAddr,
    _domain: &Option<String>,
    _region_codes: &Option<Vec<String>>,
  ) -> bool {
    true
  }
}
