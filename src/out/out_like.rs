use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::node::Node;

#[async_trait]
pub trait OutLike: Node {
  async fn run_out(&self) {}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutExit {
  Direct,
  Tag(OutExitTag),
  Proxy,
  Any,
}

impl From<String> for OutExit {
  fn from(value: String) -> Self {
    match value.as_str() {
      "DIRECT" => OutExit::Direct,
      "PROXY" => OutExit::Proxy,
      "ANY" => OutExit::Any,
      _ => OutExit::Tag(OutExitTag(value)),
    }
  }
}

// impl OutExit {
//   /// Lower the number, higher the priority.
//   pub fn priority(&self) -> u8 {
//     match self {
//       OutExit::Direct => 0,
//       OutExit::Tag(_) => 1,
//       OutExit::Proxy => 2,
//       OutExit::Any => 3,
//     }
//   }
// }

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct OutExitTag(pub String);
