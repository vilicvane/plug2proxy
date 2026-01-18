use std::{net::SocketAddr, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::{
  r#in::out_dispatcher::OutDispatcher,
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

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    todo!()
  }
}

impl OutLike for Out {}

#[derive(Serialize, Deserialize)]
pub struct DirectOut {
  pub tags: Vec<OutExitTag>,
  pub address: SocketAddr,
}
