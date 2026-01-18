use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::From)]
pub enum OutExit {
  Direct,
  Tag(#[from] OutExitTag),
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

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct OutExitTag(pub String);
