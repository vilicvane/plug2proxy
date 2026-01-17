use serde::{Deserialize, Serialize};
use uuid::{Uuid, serde::compact};

#[derive(Clone, Debug, derive_more::Display, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(transparent)]
pub struct TunnelId(#[serde(with = "compact")] Uuid);

impl TunnelId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }
}

impl Default for TunnelId {
  fn default() -> Self {
    Self::new()
  }
}
