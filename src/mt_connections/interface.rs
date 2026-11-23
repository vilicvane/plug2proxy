use std::{
  collections::HashSet,
  fmt,
  net::{IpAddr, SocketAddr},
  sync::{Arc, Mutex},
  time::{Duration, Instant},
};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{mt_connections::MtConnectionsId, utils::net::validate_interface_name};

const DEFAULT_BURST_WINDOW_MILLIS: u128 = 150;
const MIN_BURST_BYTES: u128 = 8 * 1024;
const MAX_BURST_BYTES: u128 = 512 * 1024;
const MAX_DEBT_BYTES: i64 = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bandwidth(u64);

impl Bandwidth {
  pub fn from_bytes_per_second(bytes_per_second: u64) -> Option<Self> {
    (bytes_per_second > 0).then_some(Self(bytes_per_second))
  }

  pub fn bytes_per_second(self) -> u64 {
    self.0
  }

  pub fn parse(input: &str) -> Result<Self, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
      return Err("bandwidth must not be empty".to_owned());
    }

    let unit_start = trimmed
      .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
      .ok_or_else(|| format!("bandwidth {input:?} is missing a unit (e.g. 850kbps, 1Mbps)"))?;
    let (number_part, unit_part) = trimmed.split_at(unit_start);
    let number_part = number_part.trim();
    let unit_part = unit_part.trim();

    if number_part.is_empty() || number_part.starts_with('-') {
      return Err(format!("invalid bandwidth value {input:?}"));
    }

    enum UnitKind {
      Bits(u128),
      Bytes(u128),
    }

    let unit = match unit_part {
      "bps" => UnitKind::Bits(1),
      "kbps" | "Kbps" => UnitKind::Bits(1_000),
      "mbps" | "Mbps" => UnitKind::Bits(1_000_000),
      "gbps" | "Gbps" => UnitKind::Bits(1_000_000_000),
      "B/s" => UnitKind::Bytes(1),
      "KB/s" => UnitKind::Bytes(1_000),
      "MB/s" => UnitKind::Bytes(1_000_000),
      "GB/s" => UnitKind::Bytes(1_000_000_000),
      "KiB/s" => UnitKind::Bytes(1_024),
      "MiB/s" => UnitKind::Bytes(1_024 * 1_024),
      "GiB/s" => UnitKind::Bytes(1_024 * 1_024 * 1_024),
      _ => return Err(format!("unsupported bandwidth unit {unit_part:?}")),
    };

    let multiplier = match unit {
      UnitKind::Bits(factor) | UnitKind::Bytes(factor) => factor,
    };

    let total_units = parse_scaled_decimal(number_part, multiplier)
      .ok_or_else(|| format!("invalid bandwidth number {number_part:?}"))?;

    let bytes_per_second = match unit {
      UnitKind::Bits(_) => total_units.div_ceil(8),
      UnitKind::Bytes(_) => total_units,
    };

    if bytes_per_second == 0 || bytes_per_second > u64::MAX as u128 {
      return Err(format!("bandwidth {input:?} is out of range"));
    }

    Ok(Self(bytes_per_second as u64))
  }
}

fn parse_scaled_decimal(number: &str, multiplier: u128) -> Option<u128> {
  if let Some((whole, frac)) = number.split_once('.') {
    if whole.is_empty()
      || frac.is_empty()
      || frac.len() > 9
      || !whole.bytes().all(|byte| byte.is_ascii_digit())
      || !frac.bytes().all(|byte| byte.is_ascii_digit())
    {
      return None;
    }

    let whole_value = whole.parse::<u128>().ok()?;
    let frac_value = frac.parse::<u128>().ok()?;
    let scale = 10_u128.pow(frac.len() as u32);
    let whole_scaled = whole_value.checked_mul(multiplier)?;
    let frac_scaled = frac_value.checked_mul(multiplier)? / scale;

    whole_scaled.checked_add(frac_scaled)
  } else {
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
      return None;
    }

    number.parse::<u128>().ok()?.checked_mul(multiplier)
  }
}

impl<'de> Deserialize<'de> for Bandwidth {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    struct BandwidthVisitor;

    impl<'de> de::Visitor<'de> for BandwidthVisitor {
      type Value = Bandwidth;

      fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bandwidth string such as \"850kbps\" or \"1MB/s\"")
      }

      fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Bandwidth::parse(value).map_err(E::custom)
      }
    }

    deserializer.deserialize_str(BandwidthVisitor)
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandwidthConfig {
  pub r#in: Option<Bandwidth>,
  pub out: Option<Bandwidth>,
}

impl<'de> Deserialize<'de> for BandwidthConfig {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    struct BandwidthConfigVisitor;

    impl<'de> de::Visitor<'de> for BandwidthConfigVisitor {
      type Value = BandwidthConfig;

      fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bandwidth string or an object with `in`/`out` bandwidth strings")
      }

      fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        let bandwidth = Bandwidth::parse(value).map_err(E::custom)?;
        Ok(BandwidthConfig {
          r#in: Some(bandwidth),
          out: Some(bandwidth),
        })
      }

      fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
      where
        M: de::MapAccess<'de>,
      {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
          In,
          Out,
        }

        let mut r#in = None;
        let mut out = None;

        while let Some(key) = map.next_key::<Field>()? {
          match key {
            Field::In => {
              if r#in.is_some() {
                return Err(de::Error::duplicate_field("in"));
              }
              r#in = Some(map.next_value::<Bandwidth>()?);
            }
            Field::Out => {
              if out.is_some() {
                return Err(de::Error::duplicate_field("out"));
              }
              out = Some(map.next_value::<Bandwidth>()?);
            }
          }
        }

        if r#in.is_none() && out.is_none() {
          return Err(de::Error::custom(
            "bandwidth object must specify at least one of `in` or `out`",
          ));
        }

        Ok(BandwidthConfig { r#in, out })
      }
    }

    deserializer.deserialize_any(BandwidthConfigVisitor)
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertiseAddress {
  Ip(IpAddr),
  Socket(SocketAddr),
}

impl AdvertiseAddress {
  pub fn resolve(self, default_port: u16) -> SocketAddr {
    match self {
      Self::Ip(ip) => SocketAddr::new(ip, default_port),
      Self::Socket(address) => address,
    }
  }
}

impl<'de> Deserialize<'de> for AdvertiseAddress {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    let raw = String::deserialize(deserializer)?;

    if let Ok(address) = raw.parse::<SocketAddr>() {
      if address.port() == 0 {
        return Err(de::Error::custom("advertise port must be non-zero"));
      }
      return Ok(Self::Socket(address));
    }

    if let Ok(ip) = raw.parse::<IpAddr>() {
      return Ok(Self::Ip(ip));
    }

    Err(de::Error::custom(format!(
      "invalid advertise address {raw:?}; expected IP or IP:port"
    )))
  }
}

fn default_udp() -> bool {
  true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelInterfaceConfig {
  pub interface: Option<String>,
  pub address: Option<IpAddr>,
  pub advertise: Option<AdvertiseAddress>,
  pub bandwidth: Option<BandwidthConfig>,
  #[serde(default)]
  pub metered: bool,
  pub connections_limit: Option<usize>,
  #[serde(default = "default_udp")]
  pub udp: bool,
}

#[derive(Debug)]
struct TokenBucketState {
  tokens: i64,
  last_refill: Instant,
  remainder_byte_nanos: u128,
}

#[derive(Debug)]
pub struct TokenBucket {
  rate_bytes_per_sec: u64,
  burst_bytes: i64,
  max_debt_bytes: i64,
  state: Mutex<TokenBucketState>,
}

impl TokenBucket {
  pub fn new(rate_bytes_per_sec: u64) -> Self {
    assert!(rate_bytes_per_sec > 0, "token bucket rate must be positive");

    let burst_bytes = ((rate_bytes_per_sec as u128).saturating_mul(DEFAULT_BURST_WINDOW_MILLIS)
      / 1_000)
      .clamp(MIN_BURST_BYTES, MAX_BURST_BYTES) as i64;

    Self {
      rate_bytes_per_sec,
      burst_bytes,
      max_debt_bytes: MAX_DEBT_BYTES,
      state: Mutex::new(TokenBucketState {
        tokens: burst_bytes,
        last_refill: Instant::now(),
        remainder_byte_nanos: 0,
      }),
    }
  }

  pub fn rate_bytes_per_second(&self) -> u64 {
    self.rate_bytes_per_sec
  }

  fn refill(&self, state: &mut TokenBucketState, now: Instant) {
    if now <= state.last_refill {
      return;
    }

    let elapsed_nanos = now.duration_since(state.last_refill).as_nanos();
    state.last_refill = now;

    let total = elapsed_nanos
      .saturating_mul(self.rate_bytes_per_sec as u128)
      .saturating_add(state.remainder_byte_nanos);
    let added = total / 1_000_000_000;
    state.remainder_byte_nanos = total % 1_000_000_000;

    let updated = (state.tokens as i128).saturating_add(added.min(i64::MAX as u128) as i128);
    if updated >= self.burst_bytes as i128 {
      state.tokens = self.burst_bytes;
      state.remainder_byte_nanos = 0;
    } else {
      state.tokens = updated as i64;
    }
  }

  fn next_ready_at(&self, state: &TokenBucketState, now: Instant) -> Instant {
    debug_assert!(state.tokens <= 0);
    let deficit_bytes = (1_i128 - state.tokens as i128) as u128;
    let needed_byte_nanos = deficit_bytes
      .saturating_mul(1_000_000_000)
      .saturating_sub(state.remainder_byte_nanos);
    let wait_nanos = needed_byte_nanos.div_ceil(self.rate_bytes_per_sec as u128);

    now + Duration::from_nanos(wait_nanos.min(u64::MAX as u128) as u64)
  }

  pub fn has_budget(&self, now: Instant) -> bool {
    let mut state = self.state.lock().unwrap();
    self.refill(&mut state, now);
    state.tokens > 0
  }

  pub fn next_ready(&self, now: Instant) -> Option<Instant> {
    let mut state = self.state.lock().unwrap();
    self.refill(&mut state, now);
    (state.tokens <= 0).then(|| self.next_ready_at(&state, now))
  }

  pub fn try_take(&self, bytes: u64, now: Instant) -> Result<(), Instant> {
    let mut state = self.state.lock().unwrap();
    self.refill(&mut state, now);

    if state.tokens > 0 {
      state.tokens = (state.tokens as i128)
        .saturating_sub(bytes as i128)
        .max(-(self.max_debt_bytes as i128)) as i64;
      Ok(())
    } else {
      Err(self.next_ready_at(&state, now))
    }
  }

  pub fn refund(&self, bytes: u64) {
    let mut state = self.state.lock().unwrap();
    state.tokens = (state.tokens as i128)
      .saturating_add(bytes as i128)
      .min(self.burst_bytes as i128) as i64;
  }

  pub fn debit(&self, bytes: u64, now: Instant) {
    let mut state = self.state.lock().unwrap();
    self.refill(&mut state, now);
    state.tokens = (state.tokens as i128)
      .saturating_sub(bytes as i128)
      .max(-(self.max_debt_bytes as i128)) as i64;
  }
}

pub fn has_pair_budget(a: Option<&TokenBucket>, b: Option<&TokenBucket>, now: Instant) -> bool {
  a.is_none_or(|bucket| bucket.has_budget(now)) && b.is_none_or(|bucket| bucket.has_budget(now))
}

pub fn pair_next_ready(
  a: Option<&TokenBucket>,
  b: Option<&TokenBucket>,
  now: Instant,
) -> Option<Instant> {
  match (
    a.and_then(|bucket| bucket.next_ready(now)),
    b.and_then(|bucket| bucket.next_ready(now)),
  ) {
    (Some(ready_a), Some(ready_b)) => Some(ready_a.max(ready_b)),
    (Some(ready), None) | (None, Some(ready)) => Some(ready),
    (None, None) => None,
  }
}

pub fn try_take_pair(
  a: Option<&TokenBucket>,
  b: Option<&TokenBucket>,
  bytes: u64,
  now: Instant,
) -> Result<(), Instant> {
  if let Some(a) = a
    && let Err(ready_a) = a.try_take(bytes, now)
  {
    let ready_b = b.and_then(|bucket| bucket.next_ready(now));
    return Err(ready_b.map_or(ready_a, |ready_b| ready_a.max(ready_b)));
  }

  if let Some(b) = b
    && let Err(ready_b) = b.try_take(bytes, now)
  {
    if let Some(a) = a {
      a.refund(bytes);
    }
    return Err(ready_b);
  }

  Ok(())
}

pub fn debit_pair(a: Option<&TokenBucket>, b: Option<&TokenBucket>, bytes: u64, now: Instant) {
  if let Some(a) = a {
    a.debit(bytes, now);
  }

  if let Some(b) = b {
    b.debit(bytes, now);
  }
}

pub fn refund_pair(a: Option<&TokenBucket>, b: Option<&TokenBucket>, bytes: u64) {
  if let Some(a) = a {
    a.refund(bytes);
  }

  if let Some(b) = b {
    b.refund(bytes);
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpFamily {
  Any,
  V4,
  V6,
}

impl IpFamily {
  pub fn from_ip(ip: IpAddr) -> Self {
    match ip.to_canonical() {
      IpAddr::V4(_) => Self::V4,
      IpAddr::V6(_) => Self::V6,
    }
  }

  pub fn matches(self, other: Self) -> bool {
    matches!(
      (self, other),
      (Self::Any, _) | (_, Self::Any) | (Self::V4, Self::V4) | (Self::V6, Self::V6)
    )
  }
}

#[derive(Debug)]
pub struct LocalInterface {
  pub id: u16,
  pub interface: Option<String>,
  pub address: Option<IpAddr>,
  pub advertise: Option<SocketAddr>,
  pub listen_address: Option<SocketAddr>,
  pub metered: bool,
  pub bandwidth_in_bps: Option<u64>,
  pub out_limiter: Option<Arc<TokenBucket>>,
  pub connections_limit: Option<usize>,
  pub udp: bool,
}

impl LocalInterface {
  pub fn default_implicit() -> Arc<Self> {
    Arc::new(Self {
      id: 0,
      interface: None,
      address: None,
      advertise: None,
      listen_address: None,
      metered: false,
      bandwidth_in_bps: None,
      out_limiter: None,
      connections_limit: None,
      udp: true,
    })
  }

  pub fn family(&self) -> IpFamily {
    self.address.map_or(IpFamily::Any, IpFamily::from_ip)
  }

  pub fn bandwidth_out_bps(&self) -> Option<u64> {
    self
      .out_limiter
      .as_ref()
      .map(|limiter| limiter.rate_bytes_per_second())
  }

  pub fn with_resolved_port(self: &Arc<Self>, actual_port: u16) -> Arc<Self> {
    let resolve_port = |addr: SocketAddr| {
      if addr.port() == 0 {
        SocketAddr::new(addr.ip(), actual_port)
      } else {
        addr
      }
    };

    if self.listen_address.is_none_or(|addr| addr.port() != 0)
      && self.advertise.is_none_or(|addr| addr.port() != 0)
    {
      return Arc::clone(self);
    }

    Arc::new(Self {
      id: self.id,
      interface: self.interface.clone(),
      address: self.address,
      advertise: self.advertise.map(resolve_port),
      listen_address: self.listen_address.map(resolve_port),
      metered: self.metered,
      bandwidth_in_bps: self.bandwidth_in_bps,
      out_limiter: self.out_limiter.clone(),
      connections_limit: self.connections_limit,
      udp: self.udp,
    })
  }

  pub fn to_client_desc(&self) -> ClientInterfaceDesc {
    ClientInterfaceDesc {
      id: self.id,
      family: self.family(),
      metered: self.metered,
      bandwidth_in_bps: self.bandwidth_in_bps,
      connections_limit: self.connections_limit,
      udp: self.udp,
    }
  }

  pub fn to_server_desc(
    &self,
    is_bootstrap: bool,
    bootstrap_peer_family: IpFamily,
  ) -> ServerInterfaceDesc {
    let endpoint = self
      .advertise
      .or_else(|| (!is_bootstrap).then_some(self.listen_address).flatten());
    let family = match endpoint {
      Some(address) => IpFamily::from_ip(address.ip()),
      None => bootstrap_peer_family,
    };

    ServerInterfaceDesc {
      id: self.id,
      endpoint,
      family,
      metered: self.metered,
      bandwidth_in_bps: self.bandwidth_in_bps,
      connections_limit: self.connections_limit,
      udp: self.udp,
    }
  }
}

fn is_private_non_loopback_ip(ip: IpAddr) -> bool {
  match ip.to_canonical() {
    IpAddr::V4(ipv4) => {
      !ipv4.is_loopback()
        && (ipv4.is_private()
          || ipv4.is_link_local()
          || matches!(ipv4.octets(), [100, second, _, _] if (second & 0xc0) == 64))
    }
    IpAddr::V6(ipv6) => {
      !ipv6.is_loopback() && (ipv6.is_unique_local() || ipv6.is_unicast_link_local())
    }
  }
}

pub fn warn_missing_vpc_advertise(
  role: &str,
  local_interface: &LocalInterface,
  listen_address: SocketAddr,
) {
  if local_interface.advertise.is_none() && is_private_non_loopback_ip(listen_address.ip()) {
    log::warn!(
      "{role} multi-interface listener entry #{} bound private address {listen_address} without \
       `advertise`; behind 1:1 VPC NAT set `interfaces[].advertise` to its public EIP",
      local_interface.id,
    );
  }
}

pub fn build_local_interfaces(
  configs: Vec<TunnelInterfaceConfig>,
  listen: Option<SocketAddr>,
) -> anyhow::Result<Vec<Arc<LocalInterface>>> {
  if configs.is_empty() {
    return Ok(vec![LocalInterface::default_implicit()]);
  }

  anyhow::ensure!(
    configs.len() <= u16::MAX as usize,
    "too many configured tunnel interfaces ({})",
    configs.len()
  );

  let mut unmetered = Vec::new();
  let mut metered = Vec::new();
  let mut seen_bindings = HashSet::new();
  let mut seen_addresses = HashSet::new();
  let mut seen_listen_addresses = HashSet::new();

  for config in configs {
    anyhow::ensure!(
      config.interface.is_some() || config.address.is_some(),
      "each interface entry must specify `interface`, `address`, or both"
    );

    if let Some(interface) = &config.interface {
      validate_interface_name(interface)?;
    }

    anyhow::ensure!(
      config.connections_limit != Some(0),
      "interface `connections_limit` must be at least 1"
    );

    if let Some(ip) = config.address {
      anyhow::ensure!(
        !ip.is_unspecified(),
        "interface `address` must be a specific non-unspecified IP, got {ip}"
      );
      anyhow::ensure!(
        seen_addresses.insert(ip.to_canonical()),
        "duplicate interface `address` {ip}"
      );
    }

    anyhow::ensure!(
      seen_bindings.insert((config.interface.clone(), config.address)),
      "duplicate interface entry ({:?}, {:?})",
      config.interface,
      config.address
    );

    let (listen_address, advertise) = if let Some(listen_addr) = listen {
      let ip = config.address.ok_or_else(|| {
        anyhow::anyhow!("listening nodes require an explicit `address` on every interface entry")
      })?;
      let bind_addr = SocketAddr::new(ip, listen_addr.port());

      anyhow::ensure!(
        seen_listen_addresses.insert(bind_addr),
        "duplicate listener address {bind_addr} across interfaces"
      );

      let advertise = if let Some(advertise) = config.advertise {
        let resolved = advertise.resolve(listen_addr.port());
        anyhow::ensure!(
          !resolved.ip().is_unspecified(),
          "interface `advertise` IP must not be unspecified ({resolved})"
        );
        Some(resolved)
      } else {
        None
      };

      (Some(bind_addr), advertise)
    } else {
      anyhow::ensure!(
        config.advertise.is_none(),
        "interface `advertise` requires a peer listener"
      );

      (None, None)
    };

    let bandwidth_in_bps = config
      .bandwidth
      .as_ref()
      .and_then(|bandwidth| bandwidth.r#in)
      .map(Bandwidth::bytes_per_second);
    let out_limiter = config
      .bandwidth
      .as_ref()
      .and_then(|bandwidth| bandwidth.out)
      .map(|bandwidth| Arc::new(TokenBucket::new(bandwidth.bytes_per_second())));

    let built = (
      config.interface,
      config.address,
      advertise,
      listen_address,
      config.metered,
      bandwidth_in_bps,
      out_limiter,
      config.connections_limit,
      config.udp,
    );

    if config.metered {
      metered.push(built);
    } else {
      unmetered.push(built);
    }
  }

  let interfaces = unmetered
    .into_iter()
    .chain(metered)
    .enumerate()
    .map(
      |(
        index,
        (
          interface,
          address,
          advertise,
          listen_address,
          metered,
          bandwidth_in_bps,
          out_limiter,
          connections_limit,
          udp,
        ),
      )| {
        Arc::new(LocalInterface {
          id: index as u16,
          interface,
          address,
          advertise,
          listen_address,
          metered,
          bandwidth_in_bps,
          out_limiter,
          connections_limit,
          udp,
        })
      },
    )
    .collect();

  Ok(interfaces)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInterfaceDesc {
  pub id: u16,
  pub family: IpFamily,
  pub metered: bool,
  pub bandwidth_in_bps: Option<u64>,
  pub connections_limit: Option<usize>,
  pub udp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInterfaceDesc {
  pub id: u16,
  pub endpoint: Option<SocketAddr>,
  pub family: IpFamily,
  pub metered: bool,
  pub bandwidth_in_bps: Option<u64>,
  pub connections_limit: Option<usize>,
  pub udp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedPair {
  pub pair_id: u16,
  pub client_if_id: u16,
  pub server_if_id: u16,
  pub metered: bool,
  pub udp_channel_id: Option<MtConnectionsId>,
}

pub fn pair_interfaces(
  client_ifs: &[ClientInterfaceDesc],
  server_ifs: &[ServerInterfaceDesc],
  server_udp_enabled: &[bool],
) -> Vec<NegotiatedPair> {
  let c_unmetered = client_ifs
    .iter()
    .filter(|iface| !iface.metered)
    .collect::<Vec<_>>();
  let c_metered = client_ifs
    .iter()
    .filter(|iface| iface.metered)
    .collect::<Vec<_>>();
  let s_unmetered = server_ifs
    .iter()
    .filter(|iface| !iface.metered)
    .collect::<Vec<_>>();
  let s_metered = server_ifs
    .iter()
    .filter(|iface| iface.metered)
    .collect::<Vec<_>>();

  let mut raw_pairs: Vec<(&ClientInterfaceDesc, &ServerInterfaceDesc, bool)> = Vec::new();

  fn push_cross<'a>(
    raw_pairs: &mut Vec<(&'a ClientInterfaceDesc, &'a ServerInterfaceDesc, bool)>,
    clients: &[&'a ClientInterfaceDesc],
    servers: &[&'a ServerInterfaceDesc],
    metered: bool,
  ) {
    for &client in clients {
      for &server in servers {
        if client.family.matches(server.family) {
          raw_pairs.push((client, server, metered));
        }
      }
    }
  }

  if !c_unmetered.is_empty() && !s_unmetered.is_empty() {
    push_cross(&mut raw_pairs, &c_unmetered, &s_unmetered, false);

    if !c_metered.is_empty() && !s_metered.is_empty() {
      push_cross(&mut raw_pairs, &c_metered, &s_metered, true);
    } else if !c_metered.is_empty() {
      push_cross(&mut raw_pairs, &c_metered, &s_unmetered, true);
    } else if !s_metered.is_empty() {
      push_cross(&mut raw_pairs, &c_unmetered, &s_metered, true);
    }
  } else {
    push_cross(&mut raw_pairs, &c_unmetered, &s_metered, false);
    push_cross(&mut raw_pairs, &c_metered, &s_unmetered, false);
    push_cross(&mut raw_pairs, &c_metered, &s_metered, true);
  }

  raw_pairs
    .into_iter()
    .enumerate()
    .map(|(index, (client, server, metered))| {
      let udp_enabled = client.udp
        && server.udp
        && server_udp_enabled
          .get(server.id as usize)
          .copied()
          .unwrap_or(false);

      NegotiatedPair {
        pair_id: index as u16,
        client_if_id: client.id,
        server_if_id: server.id,
        metered,
        udp_channel_id: udp_enabled.then(MtConnectionsId::new),
      }
    })
    .collect()
}

pub fn effective_pair_connections(
  requested: usize,
  client_limit: Option<usize>,
  server_limit: Option<usize>,
) -> (usize, bool) {
  let effective = [Some(requested.max(1)), client_limit, server_limit]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(1)
    .max(1);
  let allow_rotation = client_limit != Some(1) && server_limit != Some(1);

  (effective, allow_rotation)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_bandwidth_units_and_rejects_invalid() {
    assert_eq!(Bandwidth::parse("800bps").unwrap().bytes_per_second(), 100);
    assert_eq!(
      Bandwidth::parse("850kbps").unwrap().bytes_per_second(),
      106_250
    );
    assert_eq!(
      Bandwidth::parse("850Kbps").unwrap().bytes_per_second(),
      106_250
    );
    assert_eq!(
      Bandwidth::parse("1.5Mbps").unwrap().bytes_per_second(),
      187_500
    );
    assert_eq!(
      Bandwidth::parse("2gbps").unwrap().bytes_per_second(),
      250_000_000
    );
    assert_eq!(
      Bandwidth::parse("10Gbps").unwrap().bytes_per_second(),
      1_250_000_000
    );
    assert_eq!(Bandwidth::parse("512B/s").unwrap().bytes_per_second(), 512);
    assert_eq!(
      Bandwidth::parse("200KB/s").unwrap().bytes_per_second(),
      200_000
    );
    assert_eq!(
      Bandwidth::parse("2.5MB/s").unwrap().bytes_per_second(),
      2_500_000
    );
    assert_eq!(
      Bandwidth::parse("1GB/s").unwrap().bytes_per_second(),
      1_000_000_000
    );
    assert_eq!(
      Bandwidth::parse("64KiB/s").unwrap().bytes_per_second(),
      65_536
    );
    assert_eq!(
      Bandwidth::parse("2MiB/s").unwrap().bytes_per_second(),
      2 * 1024 * 1024
    );
    assert_eq!(
      Bandwidth::parse("1GiB/s").unwrap().bytes_per_second(),
      1024 * 1024 * 1024
    );

    for invalid in [
      "", "   ", "100", "0kbps", "0B/s", "-10kbps", "10foo", ".5Mbps",
    ] {
      assert!(
        Bandwidth::parse(invalid).is_err(),
        "{invalid:?} should fail"
      );
    }
  }

  #[test]
  fn parses_bandwidth_config_shorthand_and_maps() {
    let shorthand: BandwidthConfig = serde_json::from_str(r#""850kbps""#).unwrap();
    assert_eq!(shorthand.r#in, shorthand.out);
    assert_eq!(shorthand.r#in.unwrap().bytes_per_second(), 106_250);

    let asymmetric: BandwidthConfig =
      serde_json::from_str(r#"{"in":"1Mbps","out":"500kbps"}"#).unwrap();
    assert_eq!(asymmetric.r#in.unwrap().bytes_per_second(), 125_000);
    assert_eq!(asymmetric.out.unwrap().bytes_per_second(), 62_500);

    let out_only: BandwidthConfig = serde_json::from_str(r#"{"out":"100KB/s"}"#).unwrap();
    assert_eq!(out_only.r#in, None);
    assert_eq!(out_only.out.unwrap().bytes_per_second(), 100_000);

    assert!(serde_json::from_str::<BandwidthConfig>(r#"{}"#).is_err());
    assert!(serde_json::from_str::<BandwidthConfig>(r#""100""#).is_err());
  }

  #[test]
  fn builds_local_interfaces_with_ordering_and_validation() {
    let implicit = build_local_interfaces(vec![], None).unwrap();
    assert_eq!(implicit.len(), 1);
    assert_eq!(implicit[0].id, 0);
    assert!(implicit[0].udp);

    let configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address":"127.0.0.2","metered":true,"udp":false,"connections_limit":2},
        {"address":"127.0.0.1","bandwidth":"1Mbps"},
        {"address":"::1","advertise":"[::1]:4433","metered":false}
      ]"#,
    )
    .unwrap();
    let built = build_local_interfaces(configs, Some("0.0.0.0:1122".parse().unwrap())).unwrap();
    assert_eq!(built.len(), 3);
    assert!(!built[0].metered);
    assert_eq!(built[0].address, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(built[0].id, 0);
    assert_eq!(
      built[0].listen_address,
      Some("127.0.0.1:1122".parse().unwrap())
    );
    assert!(!built[1].metered);
    assert_eq!(built[1].id, 1);
    assert_eq!(built[1].advertise, Some("[::1]:4433".parse().unwrap()));
    assert!(built[2].metered);
    assert_eq!(built[2].id, 2);
    assert!(!built[2].udp);
    assert_eq!(built[2].connections_limit, Some(2));

    let missing_binding: Vec<TunnelInterfaceConfig> = serde_json::from_str(r#"[{}]"#).unwrap();
    assert!(build_local_interfaces(missing_binding, None).is_err());

    let zero_limit: Vec<TunnelInterfaceConfig> =
      serde_json::from_str(r#"[{"address":"127.0.0.1","connections_limit":0}]"#).unwrap();
    assert!(build_local_interfaces(zero_limit, None).is_err());

    let unspecified: Vec<TunnelInterfaceConfig> =
      serde_json::from_str(r#"[{"address":"0.0.0.0"}]"#).unwrap();
    assert!(build_local_interfaces(unspecified, None).is_err());

    let duplicate: Vec<TunnelInterfaceConfig> =
      serde_json::from_str(r#"[{"address":"127.0.0.1"},{"address":"127.0.0.1","metered":true}]"#)
        .unwrap();
    assert!(build_local_interfaces(duplicate, None).is_err());

    let missing_listen_ip: Vec<TunnelInterfaceConfig> =
      serde_json::from_str(r#"[{"interface":"eth0"}]"#).unwrap();
    assert!(
      build_local_interfaces(missing_listen_ip, Some("0.0.0.0:1122".parse().unwrap())).is_err()
    );

    let advertise_without_listen: Vec<TunnelInterfaceConfig> =
      serde_json::from_str(r#"[{"address":"127.0.0.1","advertise":"203.0.113.1"}]"#).unwrap();
    assert!(build_local_interfaces(advertise_without_listen, None).is_err());
  }

  #[test]
  fn token_bucket_refill_debt_and_pair_refund() {
    let bucket = TokenBucket::new(100_000);
    let t0 = Instant::now();

    assert!(bucket.has_budget(t0));
    // First take consumes burst (15_000 bytes for 100 KB/s @ 150ms) and enters small debt.
    assert!(bucket.try_take(20_000, t0).is_ok());
    assert!(!bucket.has_budget(t0));
    assert!(bucket.next_ready(t0).is_some());

    // After 50ms (+5_000 bytes), balance returns to 0, which still lacks positive budget.
    let t1 = t0 + Duration::from_millis(50);
    assert!(!bucket.has_budget(t1));

    // After another 1ms (+100 bytes), positive tokens allow the next send.
    let t2 = t1 + Duration::from_millis(1);
    assert!(bucket.has_budget(t2));
    assert!(bucket.try_take(1_000, t2).is_ok());

    // Unbounded bursty debits are clamped at -MAX_DEBT_BYTES.
    bucket.debit(1_000_000, t2);
    let ready_after_debt = bucket.next_ready(t2).unwrap();
    let expected_recovery = Duration::from_millis(328);
    assert!(ready_after_debt.duration_since(t2) >= expected_recovery - Duration::from_millis(2));
    assert!(ready_after_debt.duration_since(t2) <= expected_recovery + Duration::from_millis(5));

    // try_take_pair must refund `a` when `b` rejects.
    let primary = TokenBucket::new(100_000);
    let congested = TokenBucket::new(100_000);
    let start = Instant::now();
    assert!(congested.try_take(20_000, start).is_ok());
    assert!(try_take_pair(Some(&primary), Some(&congested), 15_000, start).is_err());
    assert!(primary.has_budget(start));
    assert!(primary.try_take(15_000, start).is_ok());
  }

  #[test]
  fn pair_interfaces_priority_family_udp_and_connection_limits() {
    let fixed_v4 = ClientInterfaceDesc {
      id: 0,
      family: IpFamily::V4,
      metered: false,
      bandwidth_in_bps: Some(100_000),
      connections_limit: None,
      udp: true,
    };
    let metered_v4 = ClientInterfaceDesc {
      id: 1,
      family: IpFamily::V4,
      metered: true,
      bandwidth_in_bps: None,
      connections_limit: Some(1),
      udp: false,
    };
    let fixed_v6 = ClientInterfaceDesc {
      id: 2,
      family: IpFamily::V6,
      metered: false,
      bandwidth_in_bps: None,
      connections_limit: None,
      udp: true,
    };

    let s_fixed_v4 = ServerInterfaceDesc {
      id: 0,
      endpoint: Some("127.0.0.1:1122".parse().unwrap()),
      family: IpFamily::V4,
      metered: false,
      bandwidth_in_bps: None,
      connections_limit: Some(2),
      udp: true,
    };
    let s_metered_v4 = ServerInterfaceDesc {
      id: 1,
      endpoint: Some("127.0.0.2:1122".parse().unwrap()),
      family: IpFamily::V4,
      metered: true,
      bandwidth_in_bps: None,
      connections_limit: None,
      udp: true,
    };

    let pairs = pair_interfaces(
      &[fixed_v4.clone(), metered_v4.clone(), fixed_v6],
      &[s_fixed_v4.clone(), s_metered_v4.clone()],
      &[true, false],
    );
    assert_eq!(pairs.len(), 2);
    assert_eq!(
      (
        pairs[0].client_if_id,
        pairs[0].server_if_id,
        pairs[0].metered
      ),
      (0, 0, false)
    );
    assert!(pairs[0].udp_channel_id.is_some());
    assert_eq!(
      (
        pairs[1].client_if_id,
        pairs[1].server_if_id,
        pairs[1].metered
      ),
      (1, 1, true)
    );
    assert!(pairs[1].udp_channel_id.is_none());

    // Single unmetered client against mixed server adds unmetered then metered spillover.
    let single_client_pairs =
      pair_interfaces(&[fixed_v4], &[s_fixed_v4, s_metered_v4], &[true, true]);
    assert_eq!(single_client_pairs.len(), 2);
    assert!(!single_client_pairs[0].metered);
    assert!(single_client_pairs[1].metered);

    assert_eq!(effective_pair_connections(4, None, Some(2)), (2, true));
    assert_eq!(effective_pair_connections(4, Some(1), None), (1, false));
    assert_eq!(effective_pair_connections(1, None, None), (1, true));
  }

  #[test]
  fn explicit_advertise_canonical_ip_family_and_duplicate_address_validation() {
    assert_eq!(
      IpFamily::from_ip("::ffff:127.0.0.1".parse().unwrap()),
      IpFamily::V4
    );

    let duplicate_client_ip: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"interface": "eth0", "address": "192.0.2.10"},
        {"address": "192.0.2.10", "metered": true}
      ]"#,
    )
    .unwrap();
    assert!(build_local_interfaces(duplicate_client_ip, None).is_err());

    let configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "172.21.184.40"},
        {"address": "172.21.184.41", "advertise": "203.0.113.20:2122", "metered": true}
      ]"#,
    )
    .unwrap();
    let ifaces = build_local_interfaces(configs, Some("0.0.0.0:1122".parse().unwrap())).unwrap();
    assert_eq!(ifaces[0].advertise, None);
    assert_eq!(
      ifaces[0].listen_address,
      Some("172.21.184.40:1122".parse().unwrap())
    );
    assert_eq!(
      ifaces[0].to_server_desc(true, IpFamily::V4),
      ServerInterfaceDesc {
        id: 0,
        endpoint: None,
        family: IpFamily::V4,
        metered: false,
        bandwidth_in_bps: None,
        connections_limit: None,
        udp: true,
      }
    );
    assert_eq!(
      ifaces[0].to_server_desc(false, IpFamily::V6).endpoint,
      Some("172.21.184.40:1122".parse().unwrap())
    );
    assert_eq!(
      ifaces[1].to_server_desc(true, IpFamily::V4).endpoint,
      Some("203.0.113.20:2122".parse().unwrap())
    );

    let implicit = LocalInterface::default_implicit();
    assert_eq!(
      implicit.to_server_desc(true, IpFamily::V4).family,
      IpFamily::V4
    );
  }
}
