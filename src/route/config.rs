use serde::{Deserialize, Serialize};

use super::rule::{
    AddressRule, DomainPatternRule, DomainRule, DynRuleBox, FallbackRule, GeoIpRule, Label,
};

/// Helper type for accepting one or many values in config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v],
            OneOrMany::Many(v) => v,
        }
    }
}

/// Route rule configuration (for IN node).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleConfig {
    /// Match by GeoIP region codes.
    #[serde(rename = "geoip")]
    GeoIp(GeoIpRuleConfig),
    /// Match by IP address/CIDR and port.
    #[serde(rename = "address")]
    Address(AddressRuleConfig),
    /// Match by domain suffix.
    #[serde(rename = "domain")]
    Domain(DomainRuleConfig),
    /// Match by domain regex pattern.
    #[serde(rename = "domain_pattern")]
    DomainPattern(DomainPatternRuleConfig),
    /// Fallback when no other rule matches.
    #[serde(rename = "fallback")]
    Fallback(FallbackRuleConfig),
}

impl RuleConfig {
    /// Convert config into a boxed Rule.
    pub fn into_rule(self) -> DynRuleBox {
        match self {
            RuleConfig::GeoIp(config) => Box::new(GeoIpRule {
                matches: config.r#match.into_vec(),
                labels: config.out.into_vec(),
                priority: config.priority.unwrap_or(i64::MIN),
                negate: config.negate,
                tag: config.tag,
            }),
            RuleConfig::Address(config) => Box::new(AddressRule {
                match_ips: config.match_ip.map(|ips| {
                    ips.into_vec()
                        .into_iter()
                        .filter_map(|ip| {
                            parse_ip_net(&ip)
                                .inspect_err(|e| tracing::error!("invalid IP/CIDR '{}': {}", ip, e))
                                .ok()
                        })
                        .collect()
                }),
                match_ports: config.match_port.map(|ports| ports.into_vec()),
                labels: config.out.into_vec(),
                priority: config.priority.unwrap_or(i64::MIN),
                negate: config.negate,
                tag: config.tag,
            }),
            RuleConfig::Domain(config) => Box::new(DomainRule {
                matches: config.r#match.into_vec(),
                labels: config.out.into_vec(),
                priority: config.priority.unwrap_or(i64::MIN),
                negate: config.negate,
                tag: config.tag,
            }),
            RuleConfig::DomainPattern(config) => Box::new(DomainPatternRule {
                matches: config
                    .r#match
                    .into_vec()
                    .into_iter()
                    .filter_map(|pattern| {
                        regex::Regex::new(&pattern)
                            .inspect_err(|e| {
                                tracing::error!("invalid domain pattern '{}': {}", pattern, e)
                            })
                            .ok()
                    })
                    .collect(),
                labels: config.out.into_vec(),
                priority: config.priority.unwrap_or(i64::MIN),
                negate: config.negate,
                tag: config.tag,
            }),
            RuleConfig::Fallback(config) => Box::new(FallbackRule {
                labels: config.out.into_vec(),
                tag: config.tag,
            }),
        }
    }
}

/// GeoIP rule configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoIpRuleConfig {
    /// Region codes to match (e.g., "CN", "US").
    pub r#match: OneOrMany<String>,
    /// Negate the match condition.
    #[serde(default)]
    pub negate: bool,
    /// Output labels when matched.
    pub out: OneOrMany<Label>,
    /// Rule priority (lower = higher priority).
    pub priority: Option<i64>,
    /// Optional tag for this rule.
    pub tag: Option<String>,
}

/// Address rule configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressRuleConfig {
    /// IP addresses/CIDRs to match.
    pub match_ip: Option<OneOrMany<String>>,
    /// Ports to match.
    pub match_port: Option<OneOrMany<u16>>,
    /// Negate the match condition.
    #[serde(default)]
    pub negate: bool,
    /// Output labels when matched.
    pub out: OneOrMany<Label>,
    /// Rule priority (lower = higher priority).
    pub priority: Option<i64>,
    /// Optional tag for this rule.
    pub tag: Option<String>,
}

/// Domain rule configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRuleConfig {
    /// Domain suffixes to match.
    pub r#match: OneOrMany<String>,
    /// Negate the match condition.
    #[serde(default)]
    pub negate: bool,
    /// Output labels when matched.
    pub out: OneOrMany<Label>,
    /// Rule priority (lower = higher priority).
    pub priority: Option<i64>,
    /// Optional tag for this rule.
    pub tag: Option<String>,
}

/// Domain pattern rule configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainPatternRuleConfig {
    /// Regex patterns to match domain.
    pub r#match: OneOrMany<String>,
    /// Negate the match condition.
    #[serde(default)]
    pub negate: bool,
    /// Output labels when matched.
    pub out: OneOrMany<Label>,
    /// Rule priority (lower = higher priority).
    pub priority: Option<i64>,
    /// Optional tag for this rule.
    pub tag: Option<String>,
}

/// Fallback rule configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FallbackRuleConfig {
    /// Output labels when no other rule matches.
    pub out: OneOrMany<Label>,
    /// Optional tag for this rule.
    pub tag: Option<String>,
}

/// Parse IP address or CIDR notation.
fn parse_ip_net(s: &str) -> Result<ipnet::IpNet, ipnet::AddrParseError> {
    // If no prefix, treat as single host
    if s.contains('/') {
        s.parse()
    } else {
        // Single IP - convert to /32 or /128
        let ip: std::net::IpAddr = s.parse().map_err(|_| {
            // Return a dummy error since ipnet::AddrParseError is not constructible
            "0.0.0.0/33".parse::<ipnet::IpNet>().unwrap_err()
        })?;
        match ip {
            std::net::IpAddr::V4(v4) => Ok(ipnet::IpNet::V4(
                ipnet::Ipv4Net::new(v4, 32).expect("valid prefix"),
            )),
            std::net::IpAddr::V6(v6) => Ok(ipnet::IpNet::V6(
                ipnet::Ipv6Net::new(v6, 128).expect("valid prefix"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_rule_config() {
        let yaml = r#"
type: domain
match: example.com
out: PROXY
"#;
        let config: RuleConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = config.into_rule();
        assert_eq!(rule.priority(), i64::MIN);
    }

    #[test]
    fn test_parse_address_rule_config() {
        let yaml = r#"
type: address
match_ip:
  - 10.0.0.0/8
  - 192.168.0.0/16
match_port: 443
out: DIRECT
priority: -100
"#;
        let config: RuleConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = config.into_rule();
        assert_eq!(rule.priority(), -100);
    }

    #[test]
    fn test_parse_fallback_rule_config() {
        let yaml = r#"
type: fallback
out: DIRECT
"#;
        let config: RuleConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = config.into_rule();
        assert_eq!(rule.priority(), i64::MAX);
    }

    #[test]
    fn test_one_or_many() {
        let single: OneOrMany<String> = serde_yaml::from_str("\"hello\"").unwrap();
        assert_eq!(single.into_vec(), vec!["hello".to_string()]);

        let many: OneOrMany<String> = serde_yaml::from_str("[\"a\", \"b\"]").unwrap();
        assert_eq!(many.into_vec(), vec!["a".to_string(), "b".to_string()]);
    }
}
