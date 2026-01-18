use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
  r#in::out_dispatcher::OutDispatcher,
  out::{DirectOut, OutExit, OutExitTag},
  primitives::SocketDestination,
  route::{self, AnyRule},
};

pub trait Node {
  fn id(&self) -> NodeId;

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>>;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(#[serde(with = "uuid::serde::compact")] pub Uuid);

impl NodeId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }
}

impl Default for NodeId {
  fn default() -> Self {
    Self::new()
  }
}

#[derive(Serialize, Deserialize)]
pub enum NodeHello {
  In,
  Out(Option<DirectOut>),
}

#[derive(Serialize, Deserialize)]
pub enum NodeInMessage {
  Connect((OutExit, SocketDestination)),
  Associate((OutExit, SocketDestination)),
}

#[derive(Serialize, Deserialize)]
pub enum NodeHubMessage {
  RouteRules(Vec<AnyRule>),
  DirectOuts(Vec<DirectOut>),
}
