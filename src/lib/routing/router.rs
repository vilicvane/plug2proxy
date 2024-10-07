use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use itertools::Itertools as _;

use crate::tunnel::TunnelId;

use super::{
    config::{InRuleConfig, OutRuleConfig},
    rule::DynRuleBox,
};

pub struct Router {
    in_rules: Vec<Arc<DynRuleBox>>,
    out_rules_map: tokio::sync::Mutex<HashMap<TunnelId, Vec<Arc<DynRuleBox>>>>,
    rules_groups_cache: tokio::sync::Mutex<Vec<Vec<Arc<DynRuleBox>>>>,
}

impl Router {
    pub fn new(rules: Vec<InRuleConfig>) -> Self {
        let rules = rules
            .into_iter()
            .map(|config| Arc::new(config.into_rule()))
            .collect_vec();

        Self {
            in_rules: rules.clone(),
            out_rules_map: tokio::sync::Mutex::new(HashMap::new()),
            rules_groups_cache: tokio::sync::Mutex::new(vec![rules]),
        }
    }

    pub async fn r#match(
        &self,
        address: SocketAddr,
        domain: Option<String>,
        region: Option<String>,
    ) -> Vec<Vec<String>> {
        let rules_groups = self.rules_groups_cache.lock().await;

        rules_groups
            .iter()
            .fold(Vec::new(), |mut labels_groups, rules| {
                let already_matched = !labels_groups.is_empty();

                let labels = rules.iter().fold(Vec::new(), |mut labels, rule| {
                    if let Some(matching_labels) = rule.r#match(
                        address,
                        &domain,
                        &region,
                        already_matched || !labels.is_empty(),
                    ) {
                        labels.extend_from_slice(matching_labels);
                    }

                    labels
                });

                if !labels.is_empty() {
                    labels_groups.push(labels);
                }

                labels_groups
            })
            .iter()
            .unique()
            .cloned()
            .collect_vec()
    }

    pub async fn register_tunnel(&self, id: TunnelId, rules: Vec<OutRuleConfig>, priority: i64) {
        self.out_rules_map.lock().await.insert(
            id,
            rules
                .into_iter()
                .map(|config| Arc::new(config.into_rule(id, priority)))
                .collect_vec(),
        );

        self.update_rules_cache().await;
    }

    pub async fn unregister_tunnel(&self, id: TunnelId) {
        self.out_rules_map.lock().await.remove(&id);

        self.update_rules_cache().await;
    }

    async fn update_rules_cache(&self) {
        let rules_map = self.out_rules_map.lock().await;

        let mut rules = rules_map
            .values()
            .flatten()
            .chain(self.in_rules.iter())
            .cloned()
            .collect_vec();

        rules.sort_by_key(|rule| rule.priority());

        let mut rules_groups = Vec::<Vec<_>>::new();

        let mut priority_cursor = None;

        for rule in rules {
            let priority = rule.priority();

            if priority_cursor.is_some_and(|cursor| cursor == priority) {
                rules_groups.last_mut().unwrap().push(rule);
            } else {
                priority_cursor = Some(priority);
                rules_groups.push(vec![rule]);
            }
        }

        *self.rules_groups_cache.lock().await = rules_groups;
    }
}
