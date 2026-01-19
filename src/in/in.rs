use std::sync::Arc;

use crate::node::Node;
use crate::node::NodeId;
use crate::node::OutDispatcher;

pub struct In {
  id: NodeId,
}

impl In {
  pub fn new() -> Self {
    Self { id: NodeId::new() }
  }
}

impl Default for In {
  fn default() -> Self {
    Self::new()
  }
}

impl Node for In {
  fn id(&self) -> NodeId {
    self.id
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    todo!()
  }
}
