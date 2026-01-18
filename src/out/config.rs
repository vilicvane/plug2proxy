use lowkit::SelfWrapExt;
use serde::{Deserialize, Deserializer};

use crate::primitives::{OutExit, OutExitTag};

#[derive(Clone, Debug)]
pub struct OutExitConfig(pub OutExit);

impl<'de> Deserialize<'de> for OutExitConfig {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    let value = String::deserialize(deserializer)?;

    let out_exit = match value.as_str() {
      "DIRECT" => OutExit::Direct,
      "PROXY" => OutExit::Proxy,
      "ANY" => OutExit::Any,
      _ => OutExit::Tag(OutExitTag(value)),
    };

    OutExitConfig(out_exit).wrap_ok()
  }
}

impl From<OutExitConfig> for OutExit {
  fn from(value: OutExitConfig) -> Self {
    value.0
  }
}
