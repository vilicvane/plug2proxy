use std::{collections::HashMap, net::SocketAddr};

use itertools::Itertools as _;

use crate::tunnel::TunnelId;

use super::{
    config::{InConfig, OutConfig},
    rule::Rule,
};

pub struct Router {
    db: maxminddb::Reader<Vec<u8>>,
    in_rules: Vec<Rule>,
    out_rules_map: tokio::sync::Mutex<HashMap<TunnelId, Vec<Rule>>>,
    rules_cache: tokio::sync::Mutex<Vec<Rule>>,
}

impl Router {
    pub fn new(db: maxminddb::Reader<Vec<u8>>, InConfig { rules }: InConfig) -> Self {
        let rules = rules
            .into_iter()
            .map(Rule::from_in_rule_config)
            .collect::<Vec<_>>();

        Self {
            db,
            in_rules: rules.clone(),
            out_rules_map: tokio::sync::Mutex::new(HashMap::new()),
            rules_cache: tokio::sync::Mutex::new(rules),
        }
    }

    pub async fn get_matched_out_tags(
        &self,
        address: SocketAddr,
        domain: Option<&str>,
    ) -> Vec<String> {
        let rules = self.rules_cache.lock().await;

        let region = if let Result::<maxminddb::geoip2::Country, _>::Ok(result) =
            self.db.lookup(address.ip())
        {
            result.country.and_then(|country| country.iso_code)
        } else {
            None
        };

        let tags = rules
            .iter()
            .filter(|rule| match rule {
                Rule::GeoIp(rule) => {
                    if let Some(region) = region {
                        let mut condition = rule
                            .match_
                            .iter()
                            .any(|match_region| match_region == region);

                        if rule.negate {
                            condition = !condition;
                        }

                        condition
                    } else {
                        false
                    }
                }
                Rule::Domain(rule) => {
                    if let Some(domain) = domain {
                        let mut condition =
                            rule.match_.iter().any(|pattern| pattern.is_match(domain));

                        if rule.negate {
                            condition = !condition;
                        }

                        condition
                    } else {
                        false
                    }
                }
            })
            .flat_map(|rule| rule.get_out_tags())
            .unique()
            .collect_vec();

        tags
    }

    pub async fn register_tunnel(
        &self,
        id: TunnelId,
        OutConfig {
            priority, rules, ..
        }: OutConfig,
    ) {
        self.out_rules_map.lock().await.insert(
            id,
            rules
                .into_iter()
                .map(|config| Rule::from_out_rule_config(id, priority, config))
                .collect::<Vec<_>>(),
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
            .collect::<Vec<_>>();

        rules_cache.sort_by_key(|rule| rule.get_priority());

        *self.rules_cache.lock().await = rules_cache;
    }
}
