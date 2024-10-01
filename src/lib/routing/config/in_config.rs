use crate::utils::OneOrMany;

#[derive(Clone, serde::Deserialize)]
pub struct InConfig {
    pub rules: Vec<InRuleConfig>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum InRuleConfig {
    #[serde(rename = "geoip")]
    GeoIp(InGeoIpRuleConfig),
    #[serde(rename = "domain")]
    Domain(InDomainRuleConfig),
}

#[derive(Clone, serde::Deserialize)]
pub struct InGeoIpRuleConfig {
    #[serde(rename = "match")]
    pub match_: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub out: OneOrMany<String>,
}

#[derive(Clone, serde::Deserialize)]
pub struct InDomainRuleConfig {
    #[serde(rename = "match")]
    pub match_: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub out: OneOrMany<String>,
}
