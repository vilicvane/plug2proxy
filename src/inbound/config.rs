use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::inbound::Socks5InboundOptions;

#[derive(Clone, Debug, Deserialize)]
pub struct InboundsConfig {
  pub socks5: Option<Socks5InboundConfig>,
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
