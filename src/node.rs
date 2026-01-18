use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
  out::DirectOut,
  route::{self, AnyRule},
};

pub trait Node {
  fn id(&self) -> NodeId;
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
pub enum NodeMessage {
  InHello,
  OutHello(Option<DirectOut>),
  RouteRules(Vec<AnyRule>),
  DirectOuts(Vec<DirectOut>),
}
