use lowkit::{SelfWrapExt, SerdeSocketAddress};
use serde::Deserialize;

use crate::inbound::{AnyInbound, Socks5Inbound, Socks5InboundOptions};

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
  pub listen: SerdeSocketAddress,
}

impl From<Socks5InboundConfig> for Socks5InboundOptions {
  fn from(Socks5InboundConfig { listen }: Socks5InboundConfig) -> Self {
    Socks5InboundOptions {
      listen: listen.into(),
    }
  }
}
