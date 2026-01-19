use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use itertools::Itertools as _;
use lowkit::SelfWrapExt;

use crate::{
  node::NodeId,
  primitives::{OutExit, SocketDestination},
  route::GeoLite2,
};

use super::{rule::AnyRule, rule::Rule};

pub struct Router {
  geolite2: GeoLite2,
  rules_map: Mutex<HashMap<RulesKey, Vec<Arc<AnyRule>>>>,
  merged_rules_cache: Mutex<Vec<Arc<AnyRule>>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, derive_more::From)]
enum RulesKey {
  Node(NodeId),
  Local,
}

impl Router {
  pub fn new(geolite2: GeoLite2) -> Self {
    Self {
      geolite2,
      rules_map: HashMap::new().mutex(),
      merged_rules_cache: Vec::new().mutex(),
    }
  }

  pub async fn match_exits(&self, socket_destination: &SocketDestination) -> Vec<OutExit> {
    let address = socket_destination
      .resolve()
      .await
      .ok()
      .map(|addresses| addresses[0]);

    let domain = socket_destination.host.as_domain_name();

    let rules = self.merged_rules_cache.lock().unwrap();

    let region_codes = if let Some(address) = address {
      self.geolite2.lookup(address.ip())
    } else {
      None
    };

    rules
      .iter()
      .filter(|rule| rule.test(&address, &domain, &region_codes))
      .flat_map(|rule| rule.exits())
      .unique()
      .cloned()
      .collect_vec()
  }

  pub fn register_local_rules(&self, rules: Vec<AnyRule>) {
    self.register_rules(RulesKey::Local, rules);
  }

  pub fn register_node_rules(&self, node_id: NodeId, rules: Vec<AnyRule>) {
    self.register_rules(node_id.into(), rules);
  }

  fn register_rules(&self, key: RulesKey, rules: Vec<AnyRule>) {
    self
      .rules_map
      .lock()
      .unwrap()
      .entry(key)
      .insert_entry(rules.into_iter().map(|rule| rule.arc()).collect());

    self.update_rules_cache();
  }

  pub fn unregister_rules(&self, node_id: NodeId) {
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

    *self.merged_rules_cache.lock().unwrap() = rules;
  }
}
