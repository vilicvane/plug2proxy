mod config;
mod geolite2;
mod router;
mod rule;

pub use config::{
    AddressRuleConfig, DomainPatternRuleConfig, DomainRuleConfig, FallbackRuleConfig,
    GeoIpRuleConfig, OneOrMany, RuleConfig,
};
pub use geolite2::GeoLite2;
pub use router::{MatchResult, Router};
pub use rule::{
    AddressRule, BuiltInLabel, DomainPatternRule, DomainRule, DynRuleBox, FallbackRule, GeoIpRule,
    Label, MatchContext, Rule,
};
