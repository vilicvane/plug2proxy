use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use super::config::RuleConfig;
use super::rule::{DynRuleBox, Label, MatchContext, Rule};

/// Result of a route match.
#[derive(Clone, Debug)]
pub struct MatchResult {
    /// The matched label.
    pub label: Label,
    /// The rule's tag (if any).
    pub tag: Option<String>,
}

/// Router for matching targets to labels.
pub struct Router {
    /// Base rules (from IN config).
    base_rules: Vec<Arc<DynRuleBox>>,
    /// Rules from OUT nodes, keyed by OUT ID.
    out_rules: RwLock<HashMap<String, (Vec<Arc<DynRuleBox>>, HashSet<String>)>>,
    /// Cached combined rules, grouped by priority.
    rules_cache: RwLock<Vec<Vec<Arc<DynRuleBox>>>>,
}

impl Router {
    /// Create a new router with base rules.
    pub fn new(rules: Vec<RuleConfig>) -> Self {
        let base_rules: Vec<Arc<DynRuleBox>> = rules
            .into_iter()
            .map(|config| Arc::new(config.into_rule()))
            .collect();

        let rules_cache = Self::build_rules_cache(&base_rules, &HashMap::new());

        Self {
            base_rules,
            out_rules: RwLock::new(HashMap::new()),
            rules_cache: RwLock::new(rules_cache),
        }
    }

    /// Match a target and return matching labels grouped by priority.
    ///
    /// Returns groups of (Label, Option<rule_tag>) pairs.
    /// Each group contains matches from rules with the same priority.
    pub async fn match_target(&self, ctx: &MatchContext<'_>) -> Vec<Vec<MatchResult>> {
        let rules_cache = self.rules_cache.read().await;

        let mut result_groups: Vec<Vec<MatchResult>> = Vec::new();

        for rules in rules_cache.iter() {
            let any_previous_matched = !result_groups.is_empty();

            let mut group_results: Vec<MatchResult> = Vec::new();

            for rule in rules.iter() {
                let any_matched = any_previous_matched || !group_results.is_empty();

                if let Some(labels) = rule.match_rule(ctx, any_matched) {
                    for label in labels {
                        group_results.push(MatchResult {
                            label: label.clone(),
                            tag: rule.tag().map(|s| s.to_string()),
                        });
                    }
                }
            }

            if !group_results.is_empty() {
                result_groups.push(group_results);
            }
        }

        // Deduplicate groups
        let mut seen = HashSet::new();
        result_groups.retain(|group| {
            let key: Vec<_> = group
                .iter()
                .map(|r| (r.label.clone(), r.tag.clone()))
                .collect();
            seen.insert(key)
        });

        result_groups
    }

    /// Register rules from an OUT node.
    pub async fn register_out(
        &self,
        out_id: &str,
        tunnel_id: &str,
        rules: Vec<RuleConfig>,
        priority: i64,
    ) {
        let new_rules: Vec<Arc<DynRuleBox>> = rules
            .into_iter()
            .map(|config| {
                // Override priority and set label to out_id
                let rule = config.into_rule();
                let override_rule: DynRuleBox = Box::new(OverrideRule::new(
                    rule,
                    Some(priority),
                    Some(Label::Custom(out_id.to_string())),
                ));
                Arc::new(override_rule)
            })
            .collect();

        {
            let mut out_rules = self.out_rules.write().await;

            let (rules, tunnel_ids) = out_rules
                .entry(out_id.to_string())
                .or_insert_with(|| (Vec::new(), HashSet::new()));

            *rules = new_rules;
            tunnel_ids.insert(tunnel_id.to_string());
        }

        self.update_cache().await;
    }

    /// Unregister a tunnel from an OUT node.
    pub async fn unregister_tunnel(&self, out_id: &str, tunnel_id: &str) {
        let should_update = {
            let mut out_rules = self.out_rules.write().await;

            let all_removed = out_rules.get_mut(out_id).is_some_and(|(_, tunnel_ids)| {
                tunnel_ids.remove(tunnel_id);
                tunnel_ids.is_empty()
            });

            if all_removed {
                out_rules.remove(out_id);
            }

            all_removed
        };

        if should_update {
            self.update_cache().await;
        }
    }

    /// Update the rules cache after changes.
    async fn update_cache(&self) {
        let out_rules = self.out_rules.read().await;
        let cache = Self::build_rules_cache(&self.base_rules, &out_rules);
        *self.rules_cache.write().await = cache;
    }

    /// Build the rules cache from base and OUT rules.
    fn build_rules_cache(
        base_rules: &[Arc<DynRuleBox>],
        out_rules: &HashMap<String, (Vec<Arc<DynRuleBox>>, HashSet<String>)>,
    ) -> Vec<Vec<Arc<DynRuleBox>>> {
        // Collect all rules
        let mut all_rules: Vec<Arc<DynRuleBox>> = base_rules.to_vec();

        for (rules, _) in out_rules.values() {
            all_rules.extend(rules.iter().cloned());
        }

        // Sort by priority
        all_rules.sort_by_key(|rule| rule.priority());

        // Group by priority
        let mut groups: Vec<Vec<Arc<DynRuleBox>>> = Vec::new();
        let mut current_priority: Option<i64> = None;

        for rule in all_rules {
            let priority = rule.priority();

            if current_priority == Some(priority) {
                groups.last_mut().unwrap().push(rule);
            } else {
                current_priority = Some(priority);
                groups.push(vec![rule]);
            }
        }

        groups
    }
}

/// Wrapper rule that overrides priority and/or labels.
#[derive(Debug)]
struct OverrideRule {
    inner: DynRuleBox,
    priority_override: Option<i64>,
    label_override: Option<Label>,
    labels_cache: Vec<Label>,
}

impl OverrideRule {
    fn new(
        inner: DynRuleBox,
        priority_override: Option<i64>,
        label_override: Option<Label>,
    ) -> Self {
        let labels_cache = label_override
            .as_ref()
            .map(|l| vec![l.clone()])
            .unwrap_or_default();

        Self {
            inner,
            priority_override,
            label_override,
            labels_cache,
        }
    }
}

impl Rule for OverrideRule {
    fn priority(&self) -> i64 {
        self.priority_override
            .unwrap_or_else(|| self.inner.priority())
    }

    fn tag(&self) -> Option<&str> {
        self.inner.tag()
    }

    fn match_rule(&self, ctx: &MatchContext, any_matched: bool) -> Option<&[Label]> {
        if self.inner.match_rule(ctx, any_matched).is_some() {
            if self.label_override.is_some() {
                Some(&self.labels_cache)
            } else {
                self.inner.match_rule(ctx, any_matched)
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::rule::BuiltInLabel;

    #[tokio::test]
    async fn test_router_basic_match() {
        let rules = vec![
            RuleConfig::Domain(super::super::config::DomainRuleConfig {
                r#match: super::super::config::OneOrMany::One("example.com".to_string()),
                negate: false,
                out: super::super::config::OneOrMany::One(Label::BuiltIn(BuiltInLabel::Proxy)),
                priority: Some(0),
                tag: None,
            }),
            RuleConfig::Fallback(super::super::config::FallbackRuleConfig {
                out: super::super::config::OneOrMany::One(Label::BuiltIn(BuiltInLabel::Direct)),
                tag: None,
            }),
        ];

        let router = Router::new(rules);

        // Should match domain rule
        let addr = "1.2.3.4:443".parse().unwrap();
        let domain = Some("www.example.com");
        let ctx = MatchContext {
            address: addr,
            domain,
            region_codes: None,
        };

        let results = router.match_target(&ctx).await;
        assert!(!results.is_empty());
        assert_eq!(results[0][0].label, Label::BuiltIn(BuiltInLabel::Proxy));
    }

    #[tokio::test]
    async fn test_router_fallback() {
        let rules = vec![
            RuleConfig::Domain(super::super::config::DomainRuleConfig {
                r#match: super::super::config::OneOrMany::One("example.com".to_string()),
                negate: false,
                out: super::super::config::OneOrMany::One(Label::BuiltIn(BuiltInLabel::Proxy)),
                priority: Some(0),
                tag: None,
            }),
            RuleConfig::Fallback(super::super::config::FallbackRuleConfig {
                out: super::super::config::OneOrMany::One(Label::BuiltIn(BuiltInLabel::Direct)),
                tag: None,
            }),
        ];

        let router = Router::new(rules);

        // Should fall back to DIRECT
        let addr = "1.2.3.4:443".parse().unwrap();
        let domain = Some("other.org");
        let ctx = MatchContext {
            address: addr,
            domain,
            region_codes: None,
        };

        let results = router.match_target(&ctx).await;
        assert!(!results.is_empty());
        assert_eq!(results[0][0].label, Label::BuiltIn(BuiltInLabel::Direct));
    }
}
