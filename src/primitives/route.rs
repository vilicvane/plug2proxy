use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::From)]
pub enum OutExit {
  Direct,
  Tag(#[from] OutExitTag),
  Proxy,
  Any,
}

impl<T> From<T> for OutExit
where
  T: AsRef<str>,
{
  fn from(value: T) -> Self {
    let value = value.as_ref();

    match value {
      "DIRECT" => OutExit::Direct,
      "PROXY" => OutExit::Proxy,
      "ANY" => OutExit::Any,
      _ => OutExit::Tag(OutExitTag(value.to_owned())),
    }
  }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct OutExitTag(pub String);

impl<T> From<T> for OutExitTag
where
  T: AsRef<str>,
{
  fn from(value: T) -> Self {
    OutExitTag(value.as_ref().to_owned())
  }
}
