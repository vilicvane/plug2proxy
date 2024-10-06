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
    rules_cache: tokio::sync::Mutex<Vec<Arc<DynRuleBox>>>,
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
            rules_cache: tokio::sync::Mutex::new(rules),
        }
    }

    pub async fn r#match(
        &self,
        address: SocketAddr,
        domain: Option<String>,
        region: Option<String>,
    ) -> Vec<String> {
        let rules = self.rules_cache.lock().await;

        rules
            .iter()
            .fold(Vec::new(), |mut labels, rule| {
                if let Some(matching_labels) =
                    rule.r#match(address, &domain, &region, !labels.is_empty())
                {
                    labels.extend_from_slice(matching_labels);
                }

                labels
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

        let mut rules_cache = rules_map
            .values()
            .flatten()
            .chain(self.in_rules.iter())
            .cloned()
            .collect_vec();

        rules_cache.sort_by_key(|rule| rule.priority());

        *self.rules_cache.lock().await = rules_cache;
    }
}
