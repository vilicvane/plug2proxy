use serde::{Deserialize, Serialize};

#[derive(
  Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::From, derive_more::Display,
)]
pub enum OutExit {
  #[display("DIRECT")]
  Direct,
  Tag(#[from] OutExitTag),
  #[display("PROXY")]
  Proxy,
  #[display("ANY")]
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

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq, derive_more::Display)]
pub struct OutExitTag(pub String);

impl<T> From<T> for OutExitTag
where
  T: AsRef<str>,
{
  fn from(value: T) -> Self {
    OutExitTag(value.as_ref().to_owned())
  }
}
