use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
