use crate::{
  node::{Node, NodeId},
  out::OutLike,
};

pub struct Out {
  id: NodeId,
}

impl Out {
  pub fn new() -> Self {
    Self { id: NodeId::new() }
  }
}

impl Default for Out {
  fn default() -> Self {
    Self::new()
  }
}

impl Node for Out {
  fn id(&self) -> NodeId {
    self.id
  }
}

impl OutLike for Out {}
