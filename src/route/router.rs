use std::{
  collections::HashMap,
  path::Path,
  sync::{Arc, Mutex},
};

use itertools::Itertools as _;
use lits::duration;
use lowkit::SelfWrapExt;
use moka::sync::Cache;

use crate::{
  node::NodeId,
  primitives::{OutExit, SocketDestination},
  route::{FallbackRule, GeoLite2, Geosite},
};

use super::{rule::AnyRule, rule::Rule};

pub struct Router {
  geolite2: GeoLite2,
  geosite: Geosite,
  rules_map: Mutex<HashMap<RulesKey, Vec<Arc<AnyRule>>>>,
  merged_rules_cache: Mutex<Vec<Arc<AnyRule>>>,
  cache: Cache<SocketDestination, Vec<OutExit>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, derive_more::From)]
enum RulesKey {
  Node(NodeId),
  Local,
}

impl Router {
  pub fn new(dir: impl AsRef<Path>) -> Self {
    let dir = dir.as_ref();
    let cache = Cache::builder().time_to_live(duration!("1h")).build();
    let geolite2 = GeoLite2::new(dir);
    let geosite = Geosite::new(dir, cache.clone());

    Self {
      geolite2,
      geosite,
      rules_map: HashMap::new().mutex(),
      merged_rules_cache: Vec::new().mutex(),
      cache,
    }
  }

  pub fn build_rules(&self) -> Vec<AnyRule> {
    self
      .merged_rules_cache
      .lock()
      .unwrap()
      .iter()
      .map(|rule| rule.as_ref().clone())
      .filter(|rule| !matches!(rule, AnyRule::Fallback(_)))
      .collect()
  }

  pub async fn match_exits(&self, socket_destination: &SocketDestination) -> Vec<OutExit> {
    if let Some(exits) = self.cache.get(socket_destination) {
      return exits;
    }

    let address = socket_destination
      .resolve()
      .await
      .ok()
      .map(|addresses| addresses[0]);

    let domain = socket_destination.routing_domain();

    let rules = self.merged_rules_cache.lock().unwrap();

    let region_codes = if let Some(address) = address {
      self.geolite2.lookup(address.ip())
    } else {
      None
    };

    let exits = rules
      .iter()
      .filter(|rule| rule.test(&address, &domain, &region_codes, &self.geosite))
      .fold(Vec::new(), |mut exits, rule| {
        if matches!(**rule, AnyRule::Fallback(_)) && !exits.is_empty() {
          return exits;
        }

        exits.extend(rule.exits().iter().cloned());
        exits
      })
      .into_iter()
      .unique()
      .collect_vec();

    self.cache.insert(socket_destination.clone(), exits.clone());

    exits
  }

  pub fn register_local_rules(&self, rules: Vec<AnyRule>) {
    self.register_rules(RulesKey::Local, rules);
  }

  pub fn register_node_rules(&self, node_id: NodeId, rules: Vec<AnyRule>) {
    self.register_rules(node_id.into(), rules);
  }

  fn register_rules(&self, key: RulesKey, rules: Vec<AnyRule>) {
    if rules.iter().any(AnyRule::uses_geosite) {
      self.geosite.ensure_updating();
    }

    self
      .rules_map
      .lock()
      .unwrap()
      .entry(key)
      .insert_entry(rules.into_iter().map(|rule| rule.arc()).collect());

    self.update_rules_cache();
  }

  pub fn unregister_node_rules(&self, node_id: NodeId) {
    self.rules_map.lock().unwrap().remove(&node_id.into());

    self.update_rules_cache();
  }

  fn update_rules_cache(&self) {
    let mut rules = self
      .rules_map
      .lock()
      .unwrap()
      .values()
      .flatten()
      .cloned()
      .collect_vec();

    rules.sort_by_key(|rule| rule.priority());

    if !rules
      .iter()
      .any(|rule| matches!(**rule, AnyRule::Fallback(_)))
    {
      rules.push(Arc::new(
        FallbackRule {
          exits: vec![OutExit::Direct],
        }
        .into(),
      ));
    }

    *self.merged_rules_cache.lock().unwrap() = rules;

    self.cache.invalidate_all();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    primitives::{SocketDestination, SocketDestinationHost},
    route::DomainRule,
    test::test_dir,
  };

  #[tokio::test]
  async fn rule_updates_invalidate_cached_destination_matches() {
    let router = Router::new(test_dir());
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("127.0.0.1".parse().unwrap()),
      port: 80,
      routing_domain: None,
    };

    router.register_local_rules(vec![
      FallbackRule {
        exits: vec![OutExit::Direct],
      }
      .into(),
    ]);

    assert_eq!(
      router.match_exits(&destination).await,
      vec![OutExit::Direct]
    );

    router.register_local_rules(vec![
      FallbackRule {
        exits: vec![OutExit::Proxy],
      }
      .into(),
    ]);

    assert_eq!(router.match_exits(&destination).await, vec![OutExit::Proxy]);
  }

  #[tokio::test]
  async fn sniffed_domain_routes_without_changing_the_resolved_ip() {
    let router = Router::new(test_dir());
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("182.140.143.139".parse().unwrap()),
      port: 443,
      routing_domain: Some("c2c.cdn.weixin.qq.com".to_owned()),
    };
    router.register_local_rules(vec![
      DomainRule {
        matchers: vec!["weixin.qq.com".to_owned().into()],
        priority: 0,
        negate: false,
        exits: vec![OutExit::Proxy],
      }
      .into(),
      FallbackRule {
        exits: vec![OutExit::Direct],
      }
      .into(),
    ]);

    assert_eq!(
      destination.resolve().await.unwrap(),
      vec!["182.140.143.139:443".parse().unwrap()]
    );
    assert_eq!(router.match_exits(&destination).await, vec![OutExit::Proxy]);
  }
}
