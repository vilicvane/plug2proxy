use crate::utils::OneOrMany;

#[derive(serde::Deserialize)]
pub struct OutConfig {
    pub tag: Option<String>,
    #[serde(default)]
    pub priority: u32,
    pub rules: Vec<OutRuleConfig>,
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
pub enum OutRuleConfig {
    #[serde(rename = "geoip")]
    GeoIp(OutGeoIpRuleConfig),
    #[serde(rename = "domain")]
    Domain(OutDomainRuleConfig),
}

#[derive(serde::Deserialize)]
pub struct OutGeoIpRuleConfig {
    #[serde(rename = "match")]
    pub match_: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub priority: Option<u32>,
}

#[derive(serde::Deserialize)]
pub struct OutDomainRuleConfig {
    #[serde(rename = "match")]
    pub match_: OneOrMany<String>,
    #[serde(default)]
    pub negate: bool,
    pub priority: Option<u32>,
}
