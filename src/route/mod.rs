mod config;
mod router;
mod rule;

pub use config::{
    AddressRuleConfig, DomainPatternRuleConfig, DomainRuleConfig, FallbackRuleConfig,
    GeoIpRuleConfig, OneOrMany, RuleConfig,
};
pub use router::{MatchResult, Router};
pub use rule::{
    AddressRule, BuiltInLabel, DomainPatternRule, DomainRule, DynRuleBox, FallbackRule, GeoIpRule,
    Label, MatchContext, Rule,
};
