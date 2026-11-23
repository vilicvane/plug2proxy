use std::net::SocketAddr;

use lowkit::{SelfWrapExt, SerdeSocketAddress};
use serde::Deserialize;

use crate::{
  inbound::{
    AnyInbound, Socks5Inbound, Socks5InboundOptions, TproxyInbound, TproxyInboundOptions,
    resolve_bypass_user,
  },
  utils::serde::{SerdeIpNet, deserialize_listen_socket_address, deserialize_u32_or_hex},
};

const DEFAULT_TPROXY_MARK: u32 = 0x0000_0070;
const DEFAULT_TPROXY_MARK_MASK: u32 = 0x0000_00ff;

#[derive(Clone, Debug, Deserialize)]
pub struct InboundsConfig {
  /// Reject inbound UDP port 443 (HTTP/3) packets across all configured
  /// inbounds unless overridden per inbound, prompting clients to use native
  /// TCP/HTTP2 instead. Disabled by default.
  #[serde(default)]
  pub reject_http3: bool,
  pub socks5: Option<Socks5InboundConfig>,
  pub tproxy: Option<TproxyInboundConfig>,
}

impl InboundsConfig {
  pub async fn into_inbounds(
    self,
    dns_hijack: Option<SocketAddr>,
  ) -> anyhow::Result<Vec<AnyInbound>> {
    let mut inbounds = vec![];
    let default_reject_http3 = self.reject_http3;

    if let Some(socks5) = self.socks5 {
      inbounds.push(
        Socks5Inbound::new(socks5.into_options(default_reject_http3))
          .await?
          .into(),
      );
    }
    if let Some(tproxy) = self.tproxy {
      let bypass_uid = resolve_bypass_user(&tproxy.network.bypass_user).await?;
      let dns_hijack = tproxy.hijack_dns.then_some(dns_hijack).flatten();
      inbounds.push(
        TproxyInbound::new(tproxy.into_options(bypass_uid, dns_hijack, default_reject_http3))
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
  /// Reject transparently intercepted UDP port 443 (HTTP/3) packets with ICMP
  /// Port Unreachable so browsers immediately fall back to TCP/HTTP2. Inherits
  /// `inbounds.reject_http3` (`false` by default) when omitted.
  #[serde(default)]
  pub reject_http3: Option<bool>,
  #[serde(default)]
  pub network: TproxyNetworkConfig,
}

impl TproxyInboundConfig {
  fn into_options(
    self,
    bypass_uid: u32,
    dns_hijack: Option<SocketAddr>,
    default_reject_http3: bool,
  ) -> TproxyInboundOptions {
    let TproxyInboundConfig {
      listen,
      sniff,
      hijack_dns: _,
      reject_http3,
      // Network policy is consumed by the privileged `network` helper. The
      // long-running inbound only receives data-plane options.
      network: _,
    } = self;
    TproxyInboundOptions {
      listen: listen.into(),
      sniff,
      bypass_uid,
      dns_hijack,
      reject_http3: reject_http3.unwrap_or(default_reject_http3),
    }
  }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct TproxyNetworkConfig {
  pub bypass_user: String,
  pub exclude_ipv4: Vec<SerdeIpNet>,
  /// Base packet/conntrack mark for locally originated OUTPUT traffic. The
  /// lowest selected bit in `mark_mask` is reserved for the PREROUTING role.
  #[serde(
    default = "default_tproxy_mark",
    deserialize_with = "deserialize_u32_or_hex"
  )]
  pub mark: u32,
  /// Bits owned by Plug2Proxy when matching and updating packet/conntrack
  /// marks. Bits outside this mask are preserved.
  #[serde(
    default = "default_tproxy_mark_mask",
    deserialize_with = "deserialize_u32_or_hex"
  )]
  pub mark_mask: u32,
}

impl Default for TproxyNetworkConfig {
  fn default() -> Self {
    Self {
      bypass_user: "plug2proxy".to_owned(),
      exclude_ipv4: vec![],
      mark: default_tproxy_mark(),
      mark_mask: default_tproxy_mark_mask(),
    }
  }
}

fn default_tproxy_mark() -> u32 {
  DEFAULT_TPROXY_MARK
}

fn default_tproxy_mark_mask() -> u32 {
  DEFAULT_TPROXY_MARK_MASK
}

#[derive(Clone, Debug, Deserialize)]
pub struct Socks5InboundConfig {
  #[serde(deserialize_with = "deserialize_listen_socket_address")]
  pub listen: SerdeSocketAddress,
  #[serde(default = "default_sniff")]
  pub sniff: bool,
  /// Drop SOCKS5 UDP port 443 (HTTP/3) packets so clients fall back to
  /// TCP/HTTP2. Inherits `inbounds.reject_http3` (`false` by default) when
  /// omitted.
  #[serde(default)]
  pub reject_http3: Option<bool>,
}

impl Socks5InboundConfig {
  fn into_options(self, default_reject_http3: bool) -> Socks5InboundOptions {
    let Socks5InboundConfig {
      listen,
      sniff,
      reject_http3,
    } = self;
    Socks5InboundOptions {
      listen: listen.into(),
      sniff,
      reject_http3: reject_http3.unwrap_or(default_reject_http3),
    }
  }
}

impl From<Socks5InboundConfig> for Socks5InboundOptions {
  fn from(config: Socks5InboundConfig) -> Self {
    config.into_options(false)
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
  fn reject_http3_defaults_to_disabled_inherits_inbounds_and_allows_override() {
    let default: InboundsConfig = serde_json::from_str(
      r#"{"socks5":{"listen":"127.0.0.1:1080"},"tproxy":{"listen":"127.0.0.1:12345"}}"#,
    )
    .unwrap();
    assert!(!default.reject_http3);
    assert!(
      !default
        .socks5
        .unwrap()
        .into_options(default.reject_http3)
        .reject_http3
    );
    assert!(
      !default
        .tproxy
        .unwrap()
        .into_options(1000, None, default.reject_http3)
        .reject_http3
    );

    let inherited: InboundsConfig = serde_json::from_str(
      r#"{"reject_http3":true,"socks5":{"listen":"127.0.0.1:1080","reject_http3":false},"tproxy":{"listen":"127.0.0.1:12345"}}"#,
    )
    .unwrap();
    assert!(inherited.reject_http3);
    assert!(
      !inherited
        .socks5
        .unwrap()
        .into_options(inherited.reject_http3)
        .reject_http3
    );
    assert!(
      inherited
        .tproxy
        .unwrap()
        .into_options(1000, None, inherited.reject_http3)
        .reject_http3
    );
  }

  #[test]
  fn tproxy_network_defaults_require_no_rule_configuration() {
    let config: InboundsConfig =
      serde_json::from_str(r#"{"tproxy":{"listen":"127.0.0.1:12345"}}"#).unwrap();
    let network = config.tproxy.unwrap().network;
    assert_eq!(network.bypass_user, "plug2proxy");
    assert!(network.exclude_ipv4.is_empty());
    assert_eq!(network.mark, 0x0000_0070);
    assert_eq!(network.mark_mask, 0x0000_00ff);
  }

  #[test]
  fn tproxy_network_marks_accept_numeric_values() {
    let config: InboundsConfig = serde_json::from_str(
      r#"{"tproxy":{"listen":"127.0.0.1:12345","network":{"mark":112,"mark_mask":255}}}"#,
    )
    .unwrap();
    let network = config.tproxy.unwrap().network;
    assert_eq!(network.mark, 0x0000_0070);
    assert_eq!(network.mark_mask, 0x0000_00ff);
  }

  #[test]
  fn tproxy_network_marks_accept_padded_hex_strings() {
    let config: InboundsConfig = serde_json::from_str(
      r#"{"tproxy":{"listen":"127.0.0.1:12345","network":{"mark":"0x00000070","mark_mask":"0x000000ff"}}}"#,
    )
    .unwrap();
    let network = config.tproxy.unwrap().network;
    assert_eq!(network.mark, 0x0000_0070);
    assert_eq!(network.mark_mask, 0x0000_00ff);
  }

  #[test]
  fn tproxy_network_marks_reject_invalid_hex_strings() {
    let error = serde_json::from_str::<InboundsConfig>(
      r#"{"tproxy":{"listen":"127.0.0.1:12345","network":{"mark":"0xnot-hex"}}}"#,
    )
    .unwrap_err();

    assert!(
      error
        .to_string()
        .contains("invalid hexadecimal u32 value: 0xnot-hex")
    );
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
