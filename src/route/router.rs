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
  remote_rules_map: Mutex<HashMap<NodeId, Vec<Arc<AnyRule>>>>,
  merged_rules_cache: Mutex<Vec<Arc<AnyRule>>>,
}

impl Router {
  pub fn new(geolite2: GeoLite2) -> Self {
    Self {
      geolite2,
      remote_rules_map: HashMap::new().mutex(),
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

  pub fn register_rules(&self, node_id: NodeId, rules: Vec<Arc<AnyRule>>) {
    self
      .remote_rules_map
      .lock()
      .unwrap()
      .entry(node_id)
      .insert_entry(rules);

    self.update_rules_cache();
  }

  pub fn unregister_rules(&self, node_id: NodeId) {
    self.remote_rules_map.lock().unwrap().remove(&node_id);

    self.update_rules_cache();
  }

  fn update_rules_cache(&self) {
    let mut rules = self
      .remote_rules_map
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
