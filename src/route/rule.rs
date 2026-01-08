use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Label representing routing destination.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Label {
    BuiltIn(BuiltInLabel),
    Custom(String),
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Label::BuiltIn(label) => write!(f, "{}", label),
            Label::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Built-in routing labels.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BuiltInLabel {
    /// Direct connection (no proxy).
    Direct,
    /// Route through proxy.
    Proxy,
    /// Accept any available route.
    Any,
}

impl fmt::Display for BuiltInLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuiltInLabel::Direct => write!(f, "DIRECT"),
            BuiltInLabel::Proxy => write!(f, "PROXY"),
            BuiltInLabel::Any => write!(f, "ANY"),
        }
    }
}

/// Context for rule matching.
pub struct MatchContext<'a> {
    /// Target socket address.
    pub address: SocketAddr,
    /// Domain name (if available).
    pub domain: Option<&'a str>,
    /// GeoIP region codes (if available).
    pub region_codes: Option<&'a [String]>,
}

/// Trait for routing rules.
pub trait Rule: Send + Sync + fmt::Debug {
    /// Rule priority (lower = higher priority, evaluated first).
    fn priority(&self) -> i64;

    /// Optional tag for this rule.
    fn tag(&self) -> Option<&str>;

    /// Match against the context.
    /// Returns Some(labels) if matched, None otherwise.
    /// `any_matched` indicates if any previous rule in this priority group matched.
    fn match_rule(&self, ctx: &MatchContext, any_matched: bool) -> Option<&[Label]>;
}

pub type DynRuleBox = Box<dyn Rule>;

/// Rule that matches by GeoIP region codes.
#[derive(Clone, Debug)]
pub struct GeoIpRule {
    pub matches: Vec<String>,
    pub labels: Vec<Label>,
    pub priority: i64,
    pub negate: bool,
    pub tag: Option<String>,
}

impl Rule for GeoIpRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    fn match_rule(&self, ctx: &MatchContext, _any_matched: bool) -> Option<&[Label]> {
        ctx.region_codes.and_then(|region_codes| {
            let mut matched = self
                .matches
                .iter()
                .any(|match_region| region_codes.iter().any(|region| region == match_region));

            if self.negate {
                matched = !matched;
            }

            if matched {
                Some(self.labels.as_slice())
            } else {
                None
            }
        })
    }
}

/// Rule that matches by IP address/CIDR and port.
#[derive(Clone, Debug)]
pub struct AddressRule {
    pub match_ips: Option<Vec<ipnet::IpNet>>,
    pub match_ports: Option<Vec<u16>>,
    pub labels: Vec<Label>,
    pub priority: i64,
    pub negate: bool,
    pub tag: Option<String>,
}

impl Rule for AddressRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    fn match_rule(&self, ctx: &MatchContext, _any_matched: bool) -> Option<&[Label]> {
        let port_matched = self
            .match_ports
            .as_ref()
            .map(|ports| ports.iter().any(|&port| port == ctx.address.port()))
            .unwrap_or(true);

        let ip_matched = self
            .match_ips
            .as_ref()
            .map(|nets| nets.iter().any(|net| net.contains(&ctx.address.ip())))
            .unwrap_or(true);

        let mut matched = ip_matched && port_matched;

        if self.negate {
            matched = !matched;
        }

        if matched { Some(&self.labels) } else { None }
    }
}

/// Rule that matches by domain suffix.
#[derive(Clone, Debug)]
pub struct DomainRule {
    pub matches: Vec<String>,
    pub labels: Vec<Label>,
    pub priority: i64,
    pub negate: bool,
    pub tag: Option<String>,
}

impl Rule for DomainRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    fn match_rule(&self, ctx: &MatchContext, _any_matched: bool) -> Option<&[Label]> {
        let domain = ctx.domain?;

        let mut matched = self.matches.iter().any(|match_domain| {
            domain == match_domain
                || (domain.ends_with(match_domain)
                    && domain[..domain.len() - match_domain.len()].ends_with('.'))
        });

        if self.negate {
            matched = !matched;
        }

        if matched { Some(&self.labels) } else { None }
    }
}

/// Rule that matches by domain regex pattern.
#[derive(Debug)]
pub struct DomainPatternRule {
    pub matches: Vec<regex::Regex>,
    pub labels: Vec<Label>,
    pub priority: i64,
    pub negate: bool,
    pub tag: Option<String>,
}

impl Rule for DomainPatternRule {
    fn priority(&self) -> i64 {
        self.priority
    }

    fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    fn match_rule(&self, ctx: &MatchContext, _any_matched: bool) -> Option<&[Label]> {
        let domain = ctx.domain?;

        let mut matched = self.matches.iter().any(|pattern| pattern.is_match(domain));

        if self.negate {
            matched = !matched;
        }

        if matched { Some(&self.labels) } else { None }
    }
}

/// Fallback rule that matches when no other rule matched.
#[derive(Clone, Debug)]
pub struct FallbackRule {
    pub labels: Vec<Label>,
    pub tag: Option<String>,
}

impl Rule for FallbackRule {
    fn priority(&self) -> i64 {
        i64::MAX
    }

    fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    fn match_rule(&self, _ctx: &MatchContext, any_matched: bool) -> Option<&[Label]> {
        if any_matched {
            None
        } else {
            Some(&self.labels)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(ip: &str, port: u16, domain: Option<&str>) -> (SocketAddr, Option<String>) {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        (addr, domain.map(|s| s.to_string()))
    }

    #[test]
    fn test_domain_rule_exact_match() {
        let rule = DomainRule {
            matches: vec!["example.com".to_string()],
            labels: vec![Label::BuiltIn(BuiltInLabel::Proxy)],
            priority: 0,
            negate: false,
            tag: None,
        };

        let (addr, domain) = make_ctx("1.2.3.4", 443, Some("example.com"));
        let ctx = MatchContext {
            address: addr,
            domain: domain.as_deref(),
            region_codes: None,
        };

        assert!(rule.match_rule(&ctx, false).is_some());
    }

    #[test]
    fn test_domain_rule_suffix_match() {
        let rule = DomainRule {
            matches: vec!["example.com".to_string()],
            labels: vec![Label::BuiltIn(BuiltInLabel::Proxy)],
            priority: 0,
            negate: false,
            tag: None,
        };

        let (addr, domain) = make_ctx("1.2.3.4", 443, Some("www.example.com"));
        let ctx = MatchContext {
            address: addr,
            domain: domain.as_deref(),
            region_codes: None,
        };

        assert!(rule.match_rule(&ctx, false).is_some());

        // Should NOT match "notexample.com"
        let (addr, domain) = make_ctx("1.2.3.4", 443, Some("notexample.com"));
        let ctx = MatchContext {
            address: addr,
            domain: domain.as_deref(),
            region_codes: None,
        };

        assert!(rule.match_rule(&ctx, false).is_none());
    }

    #[test]
    fn test_address_rule_ip_match() {
        let rule = AddressRule {
            match_ips: Some(vec!["10.0.0.0/8".parse().unwrap()]),
            match_ports: None,
            labels: vec![Label::BuiltIn(BuiltInLabel::Direct)],
            priority: 0,
            negate: false,
            tag: None,
        };

        let (addr, domain) = make_ctx("10.1.2.3", 80, None);
        let ctx = MatchContext {
            address: addr,
            domain: domain.as_deref(),
            region_codes: None,
        };

        assert!(rule.match_rule(&ctx, false).is_some());

        let (addr, domain) = make_ctx("11.1.2.3", 80, None);
        let ctx = MatchContext {
            address: addr,
            domain: domain.as_deref(),
            region_codes: None,
        };

        assert!(rule.match_rule(&ctx, false).is_none());
    }

    #[test]
    fn test_fallback_rule() {
        let rule = FallbackRule {
            labels: vec![Label::BuiltIn(BuiltInLabel::Direct)],
            tag: None,
        };

        let (addr, domain) = make_ctx("1.2.3.4", 80, None);
        let ctx = MatchContext {
            address: addr,
            domain: domain.as_deref(),
            region_codes: None,
        };

        // Should match when nothing else matched
        assert!(rule.match_rule(&ctx, false).is_some());

        // Should NOT match when something already matched
        assert!(rule.match_rule(&ctx, true).is_none());
    }
}
