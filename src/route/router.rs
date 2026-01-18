use std::{
  collections::HashMap,
  net::SocketAddr,
  sync::{Arc, Mutex},
};

use itertools::Itertools as _;
use lowkit::SelfWrapExt;

use crate::{node::NodeId, out::OutExit};

use super::rule::Rule;

pub struct Router {
  local_rules: Vec<Arc<dyn Rule>>,
  remote_rules_map: Mutex<HashMap<NodeId, Vec<Arc<dyn Rule>>>>,
  merged_rules_cache: Mutex<Vec<Arc<dyn Rule>>>,
}

impl Router {
  pub fn new(rules: Vec<Arc<dyn Rule>>) -> Self {
    Self {
      local_rules: rules.clone(),
      remote_rules_map: HashMap::new().mutex(),
      merged_rules_cache: rules.mutex(),
    }
  }

  pub fn match_exits(
    &self,
    address: SocketAddr,
    domain: &Option<String>,
    region_codes: &Option<Vec<String>>,
  ) -> Vec<OutExit> {
    let rules = self.merged_rules_cache.lock().unwrap();

    rules
      .iter()
      .filter(|rule| rule.test(address, domain, region_codes))
      .flat_map(|rule| rule.exits())
      .unique()
      .cloned()
      .collect_vec()
  }

  pub fn register_rules(&self, node_id: NodeId, rules: Vec<Arc<dyn Rule>>) {
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
      .local_rules
      .iter()
      .chain(self.remote_rules_map.lock().unwrap().values().flatten())
      .cloned()
      .collect_vec();

    rules.sort_by_key(|rule| rule.priority());

    *self.merged_rules_cache.lock().unwrap() = rules;
  }
}
