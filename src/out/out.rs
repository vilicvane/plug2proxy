use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{
  node::{Node, NodeId},
  out::{OutExitTag, OutLike},
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

#[derive(Serialize, Deserialize)]
pub struct DirectOut {
  pub tags: Vec<OutExitTag>,
  pub address: SocketAddr,
}
