use lowkit::{SelfWrapExt, SerdeSocketAddress};
use serde::Deserialize;

use crate::{
  inbound::{AnyInbound, Socks5Inbound, Socks5InboundOptions},
  utils::serde::deserialize_listen_socket_address,
};

#[derive(Clone, Debug, Deserialize)]
pub struct InboundsConfig {
  pub socks5: Option<Socks5InboundConfig>,
}

impl InboundsConfig {
  pub async fn into_inbounds(self) -> anyhow::Result<Vec<AnyInbound>> {
    let mut inbounds = vec![];

    if let Some(socks5) = self.socks5 {
      inbounds.push(Socks5Inbound::new(socks5.into()).await?.into());
    }

    inbounds.wrap_ok()
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Socks5InboundConfig {
  #[serde(deserialize_with = "deserialize_listen_socket_address")]
  pub listen: SerdeSocketAddress,
  #[serde(default = "default_sniff")]
  pub sniff: bool,
}

impl From<Socks5InboundConfig> for Socks5InboundOptions {
  fn from(Socks5InboundConfig { listen, sniff }: Socks5InboundConfig) -> Self {
    Socks5InboundOptions {
      listen: listen.into(),
      sniff,
    }
  }
}

fn default_sniff() -> bool {
  true
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn socks_sniff_defaults_to_enabled_and_can_be_disabled() {
    let default: InboundsConfig =
      serde_json::from_str(r#"{"socks5":{"listen":"127.0.0.1:1080"}}"#).unwrap();
    assert!(default.socks5.unwrap().sniff);

    let disabled: InboundsConfig =
      serde_json::from_str(r#"{"socks5":{"listen":"127.0.0.1:1080","sniff":false}}"#).unwrap();
    assert!(!disabled.socks5.unwrap().sniff);
  }

  #[test]
  fn rejects_zero_listen_port() {
    let error =
      serde_json::from_str::<InboundsConfig>(r#"{"socks5":{"listen":"127.0.0.1:0"}}"#).unwrap_err();

    assert!(error.to_string().contains("listen port must be non-zero"));
  }
}
