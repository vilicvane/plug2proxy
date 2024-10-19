use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use itertools::Itertools as _;

use crate::{match_server::MatchOutId, tunnel::TunnelId};

use super::{
    config::{InRuleConfig, OutRuleConfig},
    rule::{DynRuleBox, Label},
};

pub struct Router {
    in_rules: Vec<Arc<DynRuleBox>>,
    out_rules_map: Mutex<HashMap<MatchOutId, (Vec<Arc<DynRuleBox>>, HashSet<TunnelId>)>>,
    rules_groups_cache: Mutex<Vec<Vec<Arc<DynRuleBox>>>>,
}

impl Router {
    pub fn new(rules: Vec<InRuleConfig>) -> Self {
        let rules = rules
            .into_iter()
            .map(|config| Arc::new(config.into_rule()))
            .collect_vec();

        Self {
            in_rules: rules.clone(),
            out_rules_map: Mutex::new(HashMap::new()),
            rules_groups_cache: Mutex::new(vec![rules]),
        }
    }

    pub fn r#match(
        &self,
        address: SocketAddr,
        domain: &Option<String>,
        region_codes: &Option<Vec<String>>,
    ) -> Vec<Vec<(Label, Option<String>)>> {
        let rules_groups = self.rules_groups_cache.lock().unwrap();

        rules_groups
            .iter()
            .fold(Vec::new(), |mut labels_groups, rules| {
                let already_matched = !labels_groups.is_empty();

                let labels = rules.iter().fold(Vec::new(), |mut labels, rule| {
                    if let Some(matching_labels) = rule.r#match(
                        address,
                        domain,
                        region_codes,
                        already_matched || !labels.is_empty(),
                    ) {
                        labels.extend_from_slice(
                            &matching_labels
                                .iter()
                                .map(|label| (label.clone(), rule.tag().map(|tag| tag.to_owned())))
                                .collect_vec(),
                        );
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

    pub fn register_tunnel(
        &self,
        out_id: MatchOutId,
        tunnel_id: TunnelId,
        rules: Vec<OutRuleConfig>,
        priority: i64,
    ) {
        {
            let mut out_rules_map = self.out_rules_map.lock().unwrap();

            let (_, tunnel_id_set) = out_rules_map.entry(out_id).or_insert_with(|| {
                (
                    rules
                        .into_iter()
                        .map(|config| Arc::new(config.into_rule(out_id, priority)))
                        .collect_vec(),
                    HashSet::new(),
                )
            });

            tunnel_id_set.insert(tunnel_id);
        }

        self.update_rules_cache();
    }

    pub fn unregister_tunnel(&self, out_id: MatchOutId, tunnel_id: TunnelId) {
        {
            let mut out_rules_map = self.out_rules_map.lock().unwrap();

            let all_tunnel_removed =
                out_rules_map
                    .get_mut(&out_id)
                    .is_some_and(|(_, tunnel_id_set)| {
                        tunnel_id_set.remove(&tunnel_id);
                        tunnel_id_set.is_empty()
                    });

            if all_tunnel_removed {
                out_rules_map.remove(&out_id);
            }
        }

        self.update_rules_cache();
    }

    fn update_rules_cache(&self) {
        let mut rules = {
            let out_rules_map = self.out_rules_map.lock().unwrap();

            out_rules_map
                .values()
                .flat_map(|(rules, _)| rules)
                .chain(self.in_rules.iter())
                .cloned()
                .collect_vec()
        };

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

        log::debug!("{:#?}", rules_groups);

        *self.rules_groups_cache.lock().unwrap() = rules_groups;
    }
}
