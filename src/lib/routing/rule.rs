use std::net::SocketAddr;

pub trait Rule: Send + Sync {
    fn priority(&self) -> i64;

    fn r#match(
        &self,
        address: SocketAddr,
        domain: &Option<String>,
        region: &Option<String>,
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
        region: &Option<String>,
        _any_matched: bool,
    ) -> Option<&[String]> {
        if let Some(region) = region {
            let mut condition = self
                .matches
                .iter()
                .any(|match_region| match_region == region);

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
        _region: &Option<String>,
        _any_matched: bool,
    ) -> Option<&[String]> {
        if let Some(domain) = domain {
            let mut condition = self.matches.iter().any(|condition_domain| {
                domain == condition_domain
                    || domain.ends_with(condition_domain)
                        && domain[..domain.len() - condition_domain.len()].ends_with('.')
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
        _region: &Option<String>,
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
        _region: &Option<String>,
        any_matched: bool,
    ) -> Option<&[String]> {
        if any_matched {
            None
        } else {
            Some(&self.labels)
        }
    }
}
