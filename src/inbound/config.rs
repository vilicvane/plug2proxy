use std::net::SocketAddr;

use lowkit::{SelfWrapExt, SerdeSocketAddress};
use serde::Deserialize;

use crate::{
  inbound::{
    AnyInbound, Socks5Inbound, Socks5InboundOptions, TPROXY_BYPASS_MARK, TproxyInbound,
    TproxyInboundOptions, resolve_bypass_user,
  },
  utils::serde::{SerdeIpNet, deserialize_listen_socket_address},
};

#[derive(Clone, Debug, Deserialize)]
pub struct InboundsConfig {
  pub socks5: Option<Socks5InboundConfig>,
  pub tproxy: Option<TproxyInboundConfig>,
}

impl InboundsConfig {
  pub async fn into_inbounds(
    self,
    dns_hijack: Option<SocketAddr>,
  ) -> anyhow::Result<Vec<AnyInbound>> {
    let mut inbounds = vec![];

    if let Some(socks5) = self.socks5 {
      inbounds.push(Socks5Inbound::new(socks5.into()).await?.into());
    }
    if let Some(tproxy) = self.tproxy {
      let bypass_uid = resolve_bypass_user(&tproxy.network.bypass_user).await?;
      let dns_hijack = tproxy.hijack_dns.then_some(dns_hijack).flatten();
      inbounds.push(
        TproxyInbound::new(tproxy.into_options(bypass_uid, dns_hijack))
          .await?
          .into(),
      );
    }

    inbounds.wrap_ok()
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TproxyInboundConfig {
  #[serde(deserialize_with = "deserialize_listen_socket_address")]
  pub listen: SerdeSocketAddress,
  #[serde(default = "default_sniff")]
  pub sniff: bool,
  /// Force every transparently intercepted TCP/UDP port 53 flow through the
  /// local Plug2Proxy DNS server. Disabled by default so a client can select
  /// its own resolver; exit-node default DNS is configured at the host
  /// resolver layer instead.
  #[serde(default)]
  pub hijack_dns: bool,
  #[serde(default)]
  pub network: TproxyNetworkConfig,
}

impl TproxyInboundConfig {
  fn into_options(self, bypass_uid: u32, dns_hijack: Option<SocketAddr>) -> TproxyInboundOptions {
    let TproxyInboundConfig {
      listen,
      sniff,
      hijack_dns: _,
      // Network policy is consumed by the privileged `network` helper. The
      // long-running inbound only receives data-plane options.
      network: _,
    } = self;
    TproxyInboundOptions {
      listen: listen.into(),
      sniff,
      bypass_mark: TPROXY_BYPASS_MARK,
      bypass_uid,
      dns_hijack,
    }
  }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct TproxyNetworkConfig {
  pub bypass_user: String,
  pub exclude_ipv4: Vec<SerdeIpNet>,
}

impl Default for TproxyNetworkConfig {
  fn default() -> Self {
    Self {
      bypass_user: "plug2proxy".to_owned(),
      exclude_ipv4: vec![],
    }
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
  fn tproxy_sniff_defaults_to_enabled_and_can_be_disabled() {
    let default: InboundsConfig =
      serde_json::from_str(r#"{"tproxy":{"listen":"127.0.0.1:12345"}}"#).unwrap();
    assert!(default.tproxy.unwrap().sniff);

    let disabled: InboundsConfig =
      serde_json::from_str(r#"{"tproxy":{"listen":"127.0.0.1:12345","sniff":false}}"#).unwrap();
    assert!(!disabled.tproxy.unwrap().sniff);
  }

  #[test]
  fn tproxy_dns_hijack_defaults_to_disabled_and_can_be_enabled() {
    let default: InboundsConfig =
      serde_json::from_str(r#"{"tproxy":{"listen":"127.0.0.1:12345"}}"#).unwrap();
    assert!(!default.tproxy.unwrap().hijack_dns);

    let enabled: InboundsConfig =
      serde_json::from_str(r#"{"tproxy":{"listen":"127.0.0.1:12345","hijack_dns":true}}"#).unwrap();
    assert!(enabled.tproxy.unwrap().hijack_dns);
  }

  #[test]
  fn tproxy_network_defaults_require_no_rule_configuration() {
    let config: InboundsConfig =
      serde_json::from_str(r#"{"tproxy":{"listen":"127.0.0.1:12345"}}"#).unwrap();
    let network = config.tproxy.unwrap().network;
    assert_eq!(network.bypass_user, "plug2proxy");
    assert!(network.exclude_ipv4.is_empty());
  }

  #[test]
  fn rejects_zero_listen_port() {
    let error =
      serde_json::from_str::<InboundsConfig>(r#"{"socks5":{"listen":"127.0.0.1:0"}}"#).unwrap_err();

    assert!(error.to_string().contains("listen port must be non-zero"));

    let error =
      serde_json::from_str::<InboundsConfig>(r#"{"tproxy":{"listen":"127.0.0.1:0"}}"#).unwrap_err();
    assert!(error.to_string().contains("listen port must be non-zero"));
  }
}
