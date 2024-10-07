use std::net::SocketAddr;

pub trait Rule: Send + Sync {
    fn priority(&self) -> i64;

    fn r#match(
        &self,
        address: SocketAddr,
        domain: &Option<String>,
        region_codes: &Option<Vec<String>>,
        any_matched: bool,
    ) -> Option<&[String]>;
}

pub type DynRuleBox = Box<dyn Rule>;

#[derive(Clone)]
pub struct GeoIpRule {
    pub matches: Vec<String>,
    pub labels: Vec<String>,
    pub priority: i64,
    pub negate: bool,
}

impl Rule for GeoIpRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn r#match(
        &self,
        _address: SocketAddr,
        _domain: &Option<String>,
        region_codes: &Option<Vec<String>>,
        _any_matched: bool,
    ) -> Option<&[String]> {
        region_codes.as_ref().and_then(|region_codes| {
            let mut condition = self
                .matches
                .iter()
                .any(|match_region| region_codes.iter().any(|region| region == match_region));

            if self.negate {
                condition = !condition;
            }

            if condition {
                Some(self.labels.as_slice())
            } else {
                None
            }
        })
    }
}

#[derive(Clone)]
pub struct AddressRule {
    pub match_ips: Option<Vec<ipnet::IpNet>>,
    pub match_ports: Option<Vec<u16>>,
    pub labels: Vec<String>,
    pub priority: i64,
    pub negate: bool,
}

impl Rule for AddressRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn r#match(
        &self,
        address: SocketAddr,
        _domain: &Option<String>,
        _region_codes: &Option<Vec<String>>,
        _any_matched: bool,
    ) -> Option<&[String]> {
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

        if condition {
            Some(&self.labels)
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct DomainRule {
    pub matches: Vec<String>,
    pub labels: Vec<String>,
    pub priority: i64,
    pub negate: bool,
}

impl Rule for DomainRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn r#match(
        &self,
        _address: SocketAddr,
        domain: &Option<String>,
        _region_codes: &Option<Vec<String>>,
        _any_matched: bool,
    ) -> Option<&[String]> {
        if let Some(domain) = domain {
            let mut condition = self.matches.iter().any(|match_domain| {
                domain == match_domain
                    || domain.ends_with(match_domain)
                        && domain[..domain.len() - match_domain.len()].ends_with('.')
            });

            if self.negate {
                condition = !condition;
            }

            if condition {
                Some(&self.labels)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct DomainPatternRule {
    pub matches: Vec<regex::Regex>,
    pub labels: Vec<String>,
    pub priority: i64,
    pub negate: bool,
}

impl Rule for DomainPatternRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn r#match(
        &self,
        _address: SocketAddr,
        domain: &Option<String>,
        _region_codes: &Option<Vec<String>>,
        _any_matched: bool,
    ) -> Option<&[String]> {
        if let Some(domain) = domain {
            let mut condition = self.matches.iter().any(|pattern| pattern.is_match(domain));

            if self.negate {
                condition = !condition;
            }

            if condition {
                Some(&self.labels)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct FallbackRule {
    pub labels: Vec<String>,
}

impl Rule for FallbackRule {
    fn priority(&self) -> i64 {
        i64::MIN
    }

    fn r#match(
        &self,
        _address: SocketAddr,
        _domain: &Option<String>,
        _region_codes: &Option<Vec<String>>,
        any_matched: bool,
    ) -> Option<&[String]> {
        if any_matched {
            None
        } else {
            Some(&self.labels)
        }
    }
}
