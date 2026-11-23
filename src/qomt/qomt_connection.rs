use std::{
  collections::{HashMap, HashSet},
  net::SocketAddr,
  ops::Deref,
  sync::{Arc, Mutex, atomic::AtomicU64},
  time::Duration,
};

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  sync::mpsc,
  task::JoinSet,
  time::{Instant, MissedTickBehavior, interval_at, sleep, timeout, timeout_at},
};

use crate::{
  mt_connections::{
    ClientInterfaceDesc, IpFamily, LocalInterface, MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MtConnections,
    MtConnectionsId, MtConnectionsPacket, MtConnectionsSideUdpDuplex, MtConnectionsUdpPacket,
    MtDialTarget, MtExtendPairPlan, MtExtendPlan, NegotiatedPair, PathGroupSpec,
    ServerInterfaceDesc, TokenBucket, UdpBandwidthAccountant, UdpDuplexSlot,
    effective_pair_connections, mt_connections_connect_multi, pair_interfaces,
  },
  qomt::QomtStream,
  quic_connection::{
    MAX_DATAGRAM_SIZE, QOMT_UDP_STREAM_ALPN, QuicBytesPacket, QuicConnection, QuicConnectionError,
    State,
  },
};

#[cfg(test)]
use crate::mt_connections::MtConnectionsUnderlayMetrics;

use super::{
  DatagramTierConfig, QomtDatagramRegistration, QomtDatagramRouter, QomtDatagramSendOutcome,
  QomtDatagramStats,
};

pub const MAX_PENDING_QOMT_HANDSHAKES: usize = 64;
const MAX_QOMT_CONTROL_HELLO_BYTES: u64 = 64 * 1024;
const MAX_CLIENT_TARGET_CONNECTIONS: usize = 64;

async fn read_control_hello<T: DeserializeOwned>(
  stream: &mut (impl AsyncRead + Unpin + Send),
) -> anyhow::Result<T> {
  let mut data = Vec::new();
  stream
    .take(MAX_QOMT_CONTROL_HELLO_BYTES + 1)
    .read_to_end(&mut data)
    .await?;

  anyhow::ensure!(
    data.len() <= MAX_QOMT_CONTROL_HELLO_BYTES as usize,
    "QomT control hello exceeded {} bytes",
    MAX_QOMT_CONTROL_HELLO_BYTES
  );

  Ok(postcard::from_bytes(&data)?)
}

/// UDP 旁路的握手超时：旁路是增强，不能拖慢 TCP 主路径——正常场景
/// UDP 握手与 TCP 握手并行、亚秒级完成；失败或对端未启用 UDP 时
/// 快速放弃（旁路静默缺席），而不是等满 mTCP 握手超时。
const QOMT_UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

const QOMT_UDP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const QOMT_MAIN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const QOMT_UDP_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const QOMT_UDP_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub struct QomtUdpReconnectPolicy {
  pub keepalive_interval: Duration,
  pub reconnect_initial_delay: Duration,
  pub reconnect_max_delay: Duration,
}

impl Default for QomtUdpReconnectPolicy {
  fn default() -> Self {
    Self {
      keepalive_interval: QOMT_UDP_KEEPALIVE_INTERVAL,
      reconnect_initial_delay: QOMT_UDP_RECONNECT_INITIAL_DELAY,
      reconnect_max_delay: QOMT_UDP_RECONNECT_MAX_DELAY,
    }
  }
}

/// 未认证 UDP route 上允许丢弃的非法首包数量。除了绝对 deadline，
/// 再设包数预算，避免攻击者靠持续填满队列长时间占用 worker。
const QOMT_MAX_REJECTED_UDP_INITIAL_PACKETS: usize = 64;

impl MtConnectionsUdpPacket for QuicBytesPacket {
  fn as_bytes(&self) -> &[u8] {
    &self[..]
  }

  fn from_bytes(bytes: Vec<u8>) -> Self {
    bytes.into()
  }
}

impl MtConnectionsPacket for QuicBytesPacket {
  fn is_express(&self) -> bool {
    self.express
  }

  fn has_reliable_delivery(&self) -> bool {
    self.delivery.is_some()
  }

  fn bind_reliable_transport(&self, transport: quiche::ReliableTransport) -> bool {
    if let Some(delivery) = &self.delivery {
      assert!(delivery.bind(transport), "QUIC datagram assigned twice");
      true
    } else {
      false
    }
  }

  fn set_reliable_recv(&mut self, recv: quiche::ReliableRecv) {
    self.recv_order = Some(recv);
  }

  fn len(&self) -> usize {
    self.deref().len()
  }

  async fn read_next_packet(
    stream: &mut (dyn AsyncRead + Unpin + Send),
  ) -> Result<Option<Self>, std::io::Error> {
    let mut length_bytes = [0; size_of::<u32>()];

    // 只有在帧头尚未开始时遇到 EOF 才是干净关闭；半个长度字段或半个
    // payload 都是协议截断，必须向上报告 UnexpectedEof。
    if stream.read(&mut length_bytes[..1]).await? == 0 {
      return Ok(None);
    }
    stream.read_exact(&mut length_bytes[1..]).await?;

    let length = u32::from_be_bytes(length_bytes) as usize;

    if length > MAX_DATAGRAM_SIZE {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("QUIC packet length {length} exceeds maximum"),
      ));
    }

    let mut buffer = vec![0; length];
    stream.read_exact(&mut buffer).await?;

    Ok(Some(buffer.into()))
  }

  async fn write_packet(
    stream: &mut (dyn AsyncWrite + Unpin + Send),
    packet: Self,
  ) -> Result<(), std::io::Error> {
    if packet.len() > MAX_DATAGRAM_SIZE {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("QUIC packet length {} exceeds maximum", packet.len()),
      ));
    }

    stream.write_u32(packet.len() as u32).await?;
    stream.write_all(packet.deref()).await?;
    Ok(())
  }
}

/// QomT connection owner: the main QUIC-over-mTCP connection, the optional
/// QUIC-over-UDP bypass, and the connection-level DATAGRAM router. Byte
/// streams use [`QomtStream`]; association-scoped packet delivery is exposed
/// by `QomtPacketStream` without transferring either QUIC connection out of
/// this owner.
pub struct QomtConnection {
  inner: QuicConnection,
  udp: Arc<Mutex<Vec<Arc<Mutex<QomtUdpConnection>>>>>,
  udp_stream_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<QomtStream>>,
  datagram_router: Arc<QomtDatagramRouter>,
  #[cfg(test)]
  pub(crate) underlay_metrics: Option<Arc<MtConnectionsUnderlayMetrics>>,
  // UDP supervisor runs independently from the main handshake, but stops on
  // main QUIC Closed; owner drop aborts it as a final fallback.
  _join_set: JoinSet<()>,
}

enum QomtUdpConnection {
  Connecting,
  Established(Arc<QuicConnection>),
  Reconnecting,
  Closed,
}

impl QomtUdpConnection {
  fn state(&self) -> QomtUdpState {
    match self {
      Self::Connecting => QomtUdpState::Connecting,
      Self::Established(connection) => match connection.state() {
        State::Established => QomtUdpState::Established,
        State::Initial => QomtUdpState::Connecting,
        State::Draining | State::Closed => QomtUdpState::Closed,
      },
      Self::Reconnecting => QomtUdpState::Reconnecting,
      Self::Closed => QomtUdpState::Closed,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QomtUdpState {
  Disabled,
  Connecting,
  Established,
  Reconnecting,
  Closed,
}

#[derive(Serialize, Deserialize)]
struct QomtClientControlHello {
  interfaces: Vec<ClientInterfaceDesc>,
  bootstrap_client_if_id: u16,
  target_connections: usize,
}

#[derive(Serialize, Deserialize)]
struct QomtServerControlHello {
  interfaces: Vec<ServerInterfaceDesc>,
  bootstrap_server_if_id: u16,
  extend_token: [u8; 32],
  pairs: Vec<NegotiatedPair>,
}

impl QomtConnection {
  pub fn new(inner: QuicConnection) -> Self {
    let datagram_router = QomtDatagramRouter::new();
    let join_set = main_keepalive_tasks(&inner, QOMT_MAIN_KEEPALIVE_INTERVAL);
    let (_udp_stream_sender, udp_stream_receiver) = mpsc::unbounded_channel();

    Self {
      inner,
      udp: Arc::new(Mutex::new(Vec::new())),
      udp_stream_receiver: tokio::sync::Mutex::new(udp_stream_receiver),
      datagram_router,
      #[cfg(test)]
      underlay_metrics: None,
      _join_set: join_set,
    }
  }

  fn with_udp_supervisors<TSupervisor>(
    inner: QuicConnection,
    datagram_router: Arc<QomtDatagramRouter>,
    udp_slots: Vec<Arc<Mutex<QomtUdpConnection>>>,
    supervisor: impl FnOnce(
      Vec<Arc<Mutex<QomtUdpConnection>>>,
      Arc<QomtDatagramRouter>,
      mpsc::UnboundedSender<QomtStream>,
    ) -> TSupervisor
    + Send
    + 'static,
  ) -> Self
  where
    TSupervisor: std::future::Future<Output = ()> + Send + 'static,
  {
    let udp = Arc::new(Mutex::new(udp_slots.clone()));
    let (udp_stream_sender, udp_stream_receiver) = mpsc::unbounded_channel();
    let mut join_set = main_keepalive_tasks(&inner, QOMT_MAIN_KEEPALIVE_INTERVAL);
    let main_closed = inner.closed_future();
    let supervisor_datagram_router = datagram_router.clone();
    let cleanup_udp = udp.clone();
    let cleanup_datagram_router = datagram_router.clone();

    join_set.spawn(async move {
      tokio::select! {
        _ = main_closed => {}
        _ = supervisor(udp_slots, supervisor_datagram_router, udp_stream_sender) => {}
      }

      // Drop the losing future first, then remove every reference to its last
      // UDP generation. The main connection is the lifetime authority for the
      // bypass; a terminal main path must never leave a reconnect loop alive.
      cleanup_datagram_router.deactivate();
      for slot in cleanup_udp.lock().unwrap().iter() {
        *slot.lock().unwrap() = QomtUdpConnection::Closed;
      }
    });

    Self {
      inner,
      udp,
      udp_stream_receiver: tokio::sync::Mutex::new(udp_stream_receiver),
      datagram_router,
      #[cfg(test)]
      underlay_metrics: None,
      _join_set: join_set,
    }
  }

  pub async fn established(&self) -> Result<(), QuicConnectionError> {
    self.inner.established().await
  }

  pub fn open_stream(&self) -> QomtStream {
    QomtStream::new(self.inner.open_stream())
  }

  pub fn try_open_udp_stream(&self) -> Option<(QomtStream, Option<Duration>)> {
    let now = std::time::Instant::now();
    let slots = self.udp.lock().unwrap();
    let mut best: Option<(Option<Duration>, usize, Arc<QuicConnection>)> = None;

    for (index, slot) in slots.iter().enumerate() {
      let guard = slot.lock().unwrap();
      let QomtUdpConnection::Established(connection) = &*guard else {
        continue;
      };
      if connection.state() != State::Established
        || connection.application_proto() != QOMT_UDP_STREAM_ALPN
        || self.datagram_router.is_tier_bottlenecked(index as u16, now)
      {
        continue;
      }

      let rtt = connection
        .datagram_socket()
        .path_metrics()
        .map(|metrics| metrics.rtt);
      let sort_rtt = rtt.unwrap_or(Duration::from_millis(250));
      let should_pick = match &best {
        None => true,
        Some((prev_rtt, prev_idx, _)) => {
          let prev_sort = prev_rtt.unwrap_or(Duration::from_millis(250));
          (sort_rtt, index) < (prev_sort, *prev_idx)
        }
      };

      if should_pick {
        best = Some((rtt, index, connection.clone()));
      }
    }
    drop(slots);

    best.map(|(rtt, _, connection)| (QomtStream::new_udp_bypass(connection.open_stream()), rtt))
  }

  pub async fn accept_stream(&self) -> Result<Option<QomtStream>, QuicConnectionError> {
    let mut udp_receiver = self.udp_stream_receiver.lock().await;

    tokio::select! {
      biased;
      Some(stream) = udp_receiver.recv() => Ok(Some(stream)),
      result = self.inner.accept_stream() => {
        result.map(|stream| stream.map(QomtStream::new))
      }
    }
  }

  pub fn state(&self) -> State {
    self.inner.state()
  }

  pub fn id(&self) -> &quiche::ConnectionId<'static> {
    self.inner.id()
  }

  pub fn diagnostic_id(&self) -> String {
    self.inner.diagnostic_id()
  }

  pub fn udp_state(&self) -> QomtUdpState {
    let slots = self.udp.lock().unwrap();
    if slots.is_empty() {
      return QomtUdpState::Disabled;
    }

    let mut any_established = false;
    let mut any_reconnecting = false;
    let mut any_connecting = false;
    let mut all_closed = true;

    for slot in slots.iter() {
      let state = slot.lock().unwrap().state();

      if state != QomtUdpState::Closed {
        all_closed = false;
      }

      match state {
        QomtUdpState::Established => any_established = true,
        QomtUdpState::Reconnecting => any_reconnecting = true,
        QomtUdpState::Connecting => any_connecting = true,
        QomtUdpState::Disabled | QomtUdpState::Closed => {}
      }
    }

    if any_established {
      QomtUdpState::Established
    } else if all_closed {
      QomtUdpState::Closed
    } else if any_reconnecting {
      QomtUdpState::Reconnecting
    } else if any_connecting {
      QomtUdpState::Connecting
    } else {
      QomtUdpState::Disabled
    }
  }

  pub fn diagnostics(&self) -> String {
    let mut diagnostics = self.inner.diagnostics();

    let slots = self.udp.lock().unwrap();
    if slots.is_empty() {
      diagnostics.push_str(" udp=disabled");
    } else if slots.len() == 1 {
      match &*slots[0].lock().unwrap() {
        QomtUdpConnection::Connecting => diagnostics.push_str(" udp=connecting"),
        QomtUdpConnection::Established(connection) => {
          diagnostics.push_str(&format!(" udp=[{}]", connection.diagnostics()));
        }
        QomtUdpConnection::Reconnecting => diagnostics.push_str(" udp=reconnecting"),
        QomtUdpConnection::Closed => diagnostics.push_str(" udp=closed"),
      }
    } else {
      for (index, slot) in slots.iter().enumerate() {
        match &*slot.lock().unwrap() {
          QomtUdpConnection::Connecting => {
            diagnostics.push_str(&format!(" udp[{index}]=connecting"))
          }
          QomtUdpConnection::Established(connection) => {
            diagnostics.push_str(&format!(" udp[{index}]=[{}]", connection.diagnostics()));
          }
          QomtUdpConnection::Reconnecting => {
            diagnostics.push_str(&format!(" udp[{index}]=reconnecting"));
          }
          QomtUdpConnection::Closed => diagnostics.push_str(&format!(" udp[{index}]=closed")),
        }
      }
    }
    drop(slots);

    let datagram = self.datagram_router.stats();
    diagnostics.push_str(&format!(
      " qomt_dgram=[sent={} recv={} offloaded={} send_full={} unknown={} recv_full={} malformed={}]",
      datagram.sent,
      datagram.received,
      datagram.offloaded_bottlenecked,
      datagram.dropped_send_queue_full,
      datagram.dropped_unknown_association,
      datagram.dropped_receive_queue_full,
      datagram.dropped_malformed,
    ));

    diagnostics
  }

  pub fn udp_datagram_stats(&self) -> QomtDatagramStats {
    self.datagram_router.stats()
  }

  pub(crate) fn register_datagram_association(
    &self,
    association_id: u64,
  ) -> std::io::Result<(
    QomtDatagramRegistration,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
  )> {
    self.datagram_router.register(association_id)
  }

  pub(crate) fn try_send_association_datagram(
    &self,
    association_id: u64,
    payload: &[u8],
  ) -> QomtDatagramSendOutcome {
    self.datagram_router.try_send(association_id, payload)
  }

  #[cfg(test)]
  pub(crate) fn max_association_datagram_payload_len(&self) -> Option<usize> {
    self.datagram_router.max_payload_len()
  }

  #[cfg(test)]
  pub(crate) fn datagram_route_count(&self) -> usize {
    self.datagram_router.route_count()
  }

  #[cfg(test)]
  pub(crate) fn active_udp_tier_count(&self) -> usize {
    self.datagram_router.active_tier_count()
  }

  #[cfg(test)]
  pub(crate) fn underlay_group_enqueued_bytes(&self, group_id: u16) -> u64 {
    self
      .underlay_metrics
      .as_ref()
      .map_or(0, |metrics| metrics.group_enqueued_bytes(group_id))
  }

  #[cfg(test)]
  pub(crate) fn udp_connection_id(&self) -> Option<Vec<u8>> {
    for slot in self.udp.lock().unwrap().iter() {
      if let QomtUdpConnection::Established(connection) = &*slot.lock().unwrap() {
        return Some(connection.id().to_vec());
      }
    }

    None
  }
}

async fn run_established_udp_generation(
  pair_id: u16,
  connection: QuicConnection,
  udp: &Arc<Mutex<QomtUdpConnection>>,
  datagram_router: &Arc<QomtDatagramRouter>,
  udp_stream_sender: &mpsc::UnboundedSender<QomtStream>,
  keepalive_interval: Option<Duration>,
) -> Duration {
  let established_at = Instant::now();
  let supports_streams = connection.application_proto() == QOMT_UDP_STREAM_ALPN;
  let connection = Arc::new(connection);
  let diagnostic_id = connection.diagnostic_id();
  let socket = connection.datagram_socket();
  *udp.lock().unwrap() = QomtUdpConnection::Established(connection.clone());

  let mut router_run = Box::pin(datagram_router.clone().run_tier(pair_id, socket));
  let terminal = connection.wait_closed();
  tokio::pin!(terminal);

  let mut keepalive = keepalive_interval.map(|period| {
    let mut interval = interval_at(Instant::now() + period, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
  });
  let mut router_finished = false;
  let mut accept_finished = !supports_streams;

  loop {
    tokio::select! {
      _ = &mut terminal => break,
      result = connection.accept_stream(), if !accept_finished => {
        match result {
          Ok(Some(stream)) => {
            if udp_stream_sender
              .send(QomtStream::new_udp_bypass(stream))
              .is_err()
            {
              accept_finished = true;
            }
          }
          Ok(None) | Err(_) => {
            accept_finished = true;
          }
        }
      }
      _ = &mut router_run, if !router_finished => {
        // DATAGRAM becomes unavailable as soon as QUIC starts draining, but
        // wait for quiche to reach Closed before creating the next generation.
        router_finished = true;
        keepalive = None;
      }
      _ = async {
        match keepalive.as_mut() {
          Some(interval) => {
            interval.tick().await;
          }
          None => std::future::pending().await,
        }
      } => {
        if let Err(error) = connection.send_ack_eliciting() {
          log::trace!("UDP QUIC keepalive for {diagnostic_id} was not scheduled: {error}");
        }
      }
    }
  }

  if !router_finished {
    router_run.await;
  }

  log::warn!(
    "UDP QUIC connection {diagnostic_id} closed; preparing a replacement: {}",
    connection.diagnostics(),
  );
  *udp.lock().unwrap() = QomtUdpConnection::Reconnecting;

  established_at.elapsed()
}

fn reconnect_delay_with_jitter(delay: Duration, maximum: Duration) -> Duration {
  let jitter_max_millis = (delay.as_millis() / 5).min(u64::MAX as u128) as u64;
  let minimum = delay.saturating_sub(Duration::from_millis(jitter_max_millis));
  let maximum = delay
    .saturating_add(Duration::from_millis(jitter_max_millis))
    .min(maximum);

  if minimum >= maximum {
    return maximum;
  }

  rand::rng().random_range(minimum..=maximum)
}

async fn supervise_connect_side_udp(
  pair_id: u16,
  udp_quiche_config: Arc<Mutex<quiche::Config>>,
  address: SocketAddr,
  local_interface: Arc<LocalInterface>,
  udp_channel_id: MtConnectionsId,
  accountant: UdpBandwidthAccountant,
  policy: QomtUdpReconnectPolicy,
  udp: Arc<Mutex<QomtUdpConnection>>,
  datagram_router: Arc<QomtDatagramRouter>,
  udp_stream_sender: mpsc::UnboundedSender<QomtStream>,
) {
  let mut retry_delay = policy.reconnect_initial_delay;
  let mut generation = 0u64;

  loop {
    *udp.lock().unwrap() = if generation == 0 {
      QomtUdpConnection::Connecting
    } else {
      QomtUdpConnection::Reconnecting
    };

    let connection = match MtConnectionsSideUdpDuplex::connect_side_bound(
      address,
      udp_channel_id,
      local_interface.address,
      local_interface.interface.as_deref(),
      Some(accountant.clone()),
    )
    .await
    {
      Ok(udp_duplex) => {
        let udp_connection_id = QuicConnection::generate_connection_id();
        let udp_connection = {
          let mut config = udp_quiche_config.lock().unwrap();
          QuicConnection::connect(&udp_connection_id, &mut config, udp_duplex)
        };
        establish_connect_side_udp_connection(udp_connection).await
      }
      Err(error) => {
        log::warn!("error creating UDP side channel to {address} (pair {pair_id}): {error}");
        None
      }
    };

    if let Some(connection) = connection {
      generation = generation.saturating_add(1);
      log::info!(
        "QomT UDP generation {generation} (pair {pair_id}) to {address} established (alpn={})",
        String::from_utf8_lossy(&connection.application_proto()),
      );
      let lifetime = run_established_udp_generation(
        pair_id,
        connection,
        &udp,
        &datagram_router,
        &udp_stream_sender,
        Some(policy.keepalive_interval),
      )
      .await;

      // A handshake alone does not prove recovery. Preserve exponential
      // backoff across short-lived/flapping generations and reset it only
      // after the branch has stayed healthy for one maximum-backoff window.
      if lifetime >= policy.reconnect_max_delay {
        retry_delay = policy.reconnect_initial_delay;
      }
    } else {
      *udp.lock().unwrap() = QomtUdpConnection::Reconnecting;
    }

    let actual_delay = reconnect_delay_with_jitter(retry_delay, policy.reconnect_max_delay);
    log::debug!("retrying QomT UDP connection (pair {pair_id}) to {address} in {actual_delay:?}");
    sleep(actual_delay).await;
    retry_delay = retry_delay
      .saturating_mul(2)
      .min(policy.reconnect_max_delay);
  }
}

async fn supervise_accept_side_udp(
  pair_id: u16,
  udp_quiche_config: Arc<Mutex<quiche::Config>>,
  udp_duplex_slot: Arc<UdpDuplexSlot<QuicBytesPacket>>,
  udp: Arc<Mutex<QomtUdpConnection>>,
  datagram_router: Arc<QomtDatagramRouter>,
  udp_stream_sender: mpsc::UnboundedSender<QomtStream>,
) {
  let mut generation = 0u64;

  loop {
    *udp.lock().unwrap() = if generation == 0 {
      QomtUdpConnection::Connecting
    } else {
      QomtUdpConnection::Reconnecting
    };

    let Some(udp_duplex) = udp_duplex_slot.wait().await else {
      return;
    };

    let Some(connection) =
      establish_accept_side_udp_connection(&udp_quiche_config, udp_duplex).await
    else {
      *udp.lock().unwrap() = QomtUdpConnection::Reconnecting;
      continue;
    };

    generation = generation.saturating_add(1);
    log::info!(
      "accepted QomT UDP generation {generation} (pair {pair_id}, alpn={})",
      String::from_utf8_lossy(&connection.application_proto()),
    );
    run_established_udp_generation(
      pair_id,
      connection,
      &udp,
      &datagram_router,
      &udp_stream_sender,
      None,
    )
    .await;
  }
}

async fn establish_connect_side_udp_connection(
  udp_connection: QuicConnection,
) -> Option<QuicConnection> {
  let diagnostic_id = udp_connection.diagnostic_id();
  log::debug!("starting client UDP QUIC handshake {diagnostic_id}");

  match timeout(QOMT_UDP_HANDSHAKE_TIMEOUT, udp_connection.established()).await {
    Ok(Ok(())) => {
      log::debug!("client UDP QUIC handshake {diagnostic_id} established");
      Some(udp_connection)
    }
    Ok(Err(error)) => {
      log::warn!("UDP side QUIC connection failed: {error}");
      None
    }
    Err(_) => {
      log::warn!(
        "timed out establishing client UDP QUIC connection {diagnostic_id}: {}",
        udp_connection.diagnostics(),
      );
      None
    }
  }
}

async fn establish_accept_side_udp_connection(
  udp_quiche_config: &Arc<Mutex<quiche::Config>>,
  mut udp_duplex: MtConnectionsSideUdpDuplex<QuicBytesPacket>,
) -> Option<QuicConnection> {
  let deadline = Instant::now() + QOMT_UDP_HANDSHAKE_TIMEOUT;
  let result = timeout_at(deadline, async {
    let mut rejected_packets = 0;
    let (udp_connection_id, first_packet) = loop {
      let mut packet = udp_duplex
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("UDP side channel closed before Initial"))?;

      let connection_id = quiche::Header::from_slice(&mut packet[..], quiche::MAX_CONN_ID_LEN)
        .ok()
        .filter(|header| {
          header.ty == quiche::Type::Initial
            && quiche::version_is_supported(header.version)
            && !header.dcid.as_ref().is_empty()
            && header.dcid.as_ref().len() <= quiche::MAX_CONN_ID_LEN
        })
        .map(|header| quiche::ConnectionId::from_vec(header.dcid.to_vec()));

      if let Some(connection_id) = connection_id {
        break (connection_id, packet);
      }

      rejected_packets += 1;
      anyhow::ensure!(
        rejected_packets < QOMT_MAX_REJECTED_UDP_INITIAL_PACKETS,
        "too many invalid UDP packets before QUIC Initial",
      );
      anyhow::ensure!(Instant::now() < deadline, "UDP Initial deadline elapsed");

      // flume 队列持续非空时 next() 可以一直 Ready；显式让出才能让
      // timeout driver 和其他任务获得调度。
      tokio::task::yield_now().await;
    };

    let udp_connection = {
      let mut config = udp_quiche_config.lock().unwrap();
      QuicConnection::accept_with_first_packet(
        &udp_connection_id,
        &mut config,
        first_packet,
        udp_duplex,
      )
    };
    let diagnostic_id = udp_connection.diagnostic_id();
    log::debug!("starting server UDP QUIC handshake {diagnostic_id}");

    udp_connection
      .established()
      .await
      .context("UDP side QUIC connection failed")?;

    anyhow::Ok((diagnostic_id, udp_connection))
  })
  .await;

  match result {
    Ok(Ok((diagnostic_id, connection))) => {
      log::debug!("server UDP QUIC handshake {diagnostic_id} established");
      Some(connection)
    }
    Ok(Err(error)) => {
      log::warn!("{error:#}");
      None
    }
    Err(_) => {
      log::warn!("timed out establishing UDP side QUIC connection");
      None
    }
  }
}

struct ConnectUdpSpec {
  pair_id: u16,
  udp_channel_id: MtConnectionsId,
  address: SocketAddr,
  local_interface: Arc<LocalInterface>,
  accountant: UdpBandwidthAccountant,
}

pub async fn qomt_connect(
  quiche_config: &mut quiche::Config,
  udp_quiche_config: Option<quiche::Config>,
  address: SocketAddr,
  connections: usize,
) -> anyhow::Result<QomtConnection> {
  qomt_connect_with_options(
    quiche_config,
    udp_quiche_config,
    &[address],
    &[LocalInterface::default_implicit()],
    connections,
    QomtUdpReconnectPolicy::default(),
  )
  .await
}

#[cfg(test)]
pub(crate) async fn qomt_connect_with_udp_policy(
  quiche_config: &mut quiche::Config,
  udp_quiche_config: Option<quiche::Config>,
  address: SocketAddr,
  connections: usize,
  udp_policy: QomtUdpReconnectPolicy,
) -> anyhow::Result<QomtConnection> {
  qomt_connect_with_options(
    quiche_config,
    udp_quiche_config,
    &[address],
    &[LocalInterface::default_implicit()],
    connections,
    udp_policy,
  )
  .await
}

pub async fn qomt_connect_with_options(
  quiche_config: &mut quiche::Config,
  udp_quiche_config: Option<quiche::Config>,
  bootstrap_addresses: &[SocketAddr],
  local_interfaces: &[Arc<LocalInterface>],
  connections: usize,
  udp_policy: QomtUdpReconnectPolicy,
) -> anyhow::Result<QomtConnection> {
  let default_interfaces;
  let local_interfaces = if local_interfaces.is_empty() {
    default_interfaces = [LocalInterface::default_implicit()];
    &default_interfaces[..]
  } else {
    local_interfaces
  };

  let mut bootstrap_targets = Vec::new();
  let mut seen_targets = HashSet::new();
  for index in 0..local_interfaces.len().min(bootstrap_addresses.len()) {
    let local_interface = &local_interfaces[index];
    let remote_address = bootstrap_addresses[index];
    if local_interface
      .family()
      .matches(IpFamily::from_ip(remote_address.ip()))
      && seen_targets.insert((local_interface.id, remote_address))
    {
      bootstrap_targets.push(MtDialTarget {
        local_interface: local_interface.clone(),
        remote_address,
      });
    }
  }

  for metered_pass in [false, true] {
    for local_interface in local_interfaces
      .iter()
      .filter(|iface| iface.metered == metered_pass)
    {
      for &remote_address in bootstrap_addresses {
        if local_interface
          .family()
          .matches(IpFamily::from_ip(remote_address.ip()))
          && seen_targets.insert((local_interface.id, remote_address))
        {
          bootstrap_targets.push(MtDialTarget {
            local_interface: local_interface.clone(),
            remote_address,
          });
        }
      }
    }
  }

  anyhow::ensure!(
    !bootstrap_targets.is_empty(),
    "no IP-family compatible bootstrap target address for QomT connect"
  );

  let (mut mt_connections, extend_plan_sender, bootstrap_client_if_id, bootstrap_remote_address) =
    mt_connections_connect_multi::<QuicBytesPacket>(bootstrap_targets)
      .await
      .context("failed to create mTCP connections.")?;
  let underlay_metrics = mt_connections.underlay_metrics();

  let connection_id = QuicConnection::generate_connection_id();
  let mut cid_packet: QuicBytesPacket = connection_id.to_vec().into();
  cid_packet.express = true;
  mt_connections.send(cid_packet).await?;

  quiche_config.set_reliable_transport(cfg!(target_os = "linux"));
  let mut inner = QuicConnection::connect(&connection_id, quiche_config, mt_connections);
  inner.attach_reliable_underlay_metrics(underlay_metrics.clone());

  timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, inner.established())
    .await
    .context("timed out establishing QUIC connection")??;

  let requested_connections = connections.max(1);
  let client_udp_enabled = udp_quiche_config.is_some();
  let server_hello = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
    let mut control_stream = inner.open_stream();
    let hello = QomtClientControlHello {
      interfaces: local_interfaces
        .iter()
        .map(|iface| {
          let mut desc = iface.to_client_desc();
          desc.udp &= client_udp_enabled;
          desc
        })
        .collect(),
      bootstrap_client_if_id,
      target_connections: requested_connections,
    };

    control_stream
      .write_all(&postcard::to_allocvec(&hello).unwrap())
      .await?;
    control_stream.shutdown().await?;

    read_control_hello::<QomtServerControlHello>(&mut control_stream).await
  })
  .await
  .context("timed out exchanging QomT interface metadata")??;

  anyhow::ensure!(
    !server_hello.pairs.is_empty(),
    "QomT server returned no compatible interface pairs"
  );

  let client_by_id: HashMap<u16, &Arc<LocalInterface>> = local_interfaces
    .iter()
    .map(|iface| (iface.id, iface))
    .collect();
  let mut server_by_id = HashMap::new();
  let mut peer_in_limiters = HashMap::new();

  for server_if in &server_hello.interfaces {
    anyhow::ensure!(
      server_by_id.insert(server_if.id, server_if).is_none(),
      "QomT server reported duplicate interface id {}",
      server_if.id
    );
    let peer_in = server_if
      .bandwidth_in_bps
      .and_then(|bps| (bps > 0).then(|| Arc::new(TokenBucket::new(bps))));
    peer_in_limiters.insert(server_if.id, peer_in);
  }

  let mut group_specs = Vec::with_capacity(server_hello.pairs.len());
  let mut extend_pairs = Vec::with_capacity(server_hello.pairs.len());
  let mut datagram_tiers = Vec::new();
  let mut udp_specs = Vec::new();
  let mut seen_pair_ids = HashSet::new();
  let mut bootstrap_pair_id = None;

  for pair in &server_hello.pairs {
    anyhow::ensure!(
      seen_pair_ids.insert(pair.pair_id),
      "QomT server returned duplicate pair id {}",
      pair.pair_id
    );

    let local_if = *client_by_id
      .get(&pair.client_if_id)
      .ok_or_else(|| anyhow::anyhow!("unknown client interface id {}", pair.client_if_id))?;
    let server_if = *server_by_id
      .get(&pair.server_if_id)
      .ok_or_else(|| anyhow::anyhow!("unknown server interface id {}", pair.server_if_id))?;

    if pair.client_if_id == bootstrap_client_if_id
      && pair.server_if_id == server_hello.bootstrap_server_if_id
    {
      bootstrap_pair_id = Some(pair.pair_id);
    }

    let peer_in = peer_in_limiters.get(&pair.server_if_id).cloned().flatten();
    let remote_address = server_if.endpoint.unwrap_or(bootstrap_remote_address);
    anyhow::ensure!(
      local_if
        .family()
        .matches(IpFamily::from_ip(remote_address.ip())),
      "incompatible address family between local interface {} ({:?}) and remote endpoint {remote_address}",
      local_if.id,
      local_if.family(),
    );
    let (target_connections, allow_rotation) = effective_pair_connections(
      requested_connections,
      local_if.connections_limit,
      server_if.connections_limit,
    );

    group_specs.push(PathGroupSpec {
      id: pair.pair_id,
      local_out: local_if.out_limiter.clone(),
      peer_in: peer_in.clone(),
    });
    extend_pairs.push(MtExtendPairPlan {
      pair_id: pair.pair_id,
      local_interface: local_if.clone(),
      remote_address,
      target_connections,
      allow_rotation,
    });

    if let Some(udp_channel_id) = pair.udp_channel_id
      && udp_quiche_config.is_some()
    {
      let precharged_bytes = Arc::new(AtomicU64::new(0));
      datagram_tiers.push(DatagramTierConfig {
        pair_id: pair.pair_id,
        local_out: local_if.out_limiter.clone(),
        peer_in: peer_in.clone(),
        precharged_bytes: precharged_bytes.clone(),
      });
      udp_specs.push(ConnectUdpSpec {
        pair_id: pair.pair_id,
        udp_channel_id,
        address: remote_address,
        local_interface: local_if.clone(),
        accountant: UdpBandwidthAccountant {
          local_out: local_if.out_limiter.clone(),
          peer_in,
          precharged_bytes,
        },
      });
    }
  }

  let fallback_limits = bootstrap_pair_id.is_none().then(|| {
    let local_out = client_by_id
      .get(&bootstrap_client_if_id)
      .and_then(|iface| iface.out_limiter.clone());
    let peer_in = peer_in_limiters
      .get(&server_hello.bootstrap_server_if_id)
      .cloned()
      .flatten();
    (local_out, peer_in)
  });

  underlay_metrics.configure_groups(group_specs, bootstrap_pair_id, fallback_limits);
  let _ = extend_plan_sender.send(MtExtendPlan {
    token: server_hello.extend_token,
    bootstrap_pair_id,
    pairs: extend_pairs,
  });

  #[cfg_attr(not(test), allow(unused_mut))]
  let mut qomt_connection = match (udp_quiche_config, udp_specs.is_empty()) {
    (Some(udp_quiche_config), false) => {
      let datagram_router = QomtDatagramRouter::new();
      datagram_router.configure_tiers(datagram_tiers);

      let udp_slots = (0..udp_specs.len())
        .map(|_| Arc::new(Mutex::new(QomtUdpConnection::Connecting)))
        .collect();
      let udp_quiche_config = Arc::new(Mutex::new(udp_quiche_config));

      QomtConnection::with_udp_supervisors(
        inner,
        datagram_router,
        udp_slots,
        move |udp_slots, datagram_router, udp_stream_sender| async move {
          let mut tasks = JoinSet::new();
          for (spec, udp_slot) in udp_specs.into_iter().zip(udp_slots) {
            tasks.spawn(supervise_connect_side_udp(
              spec.pair_id,
              udp_quiche_config.clone(),
              spec.address,
              spec.local_interface,
              spec.udp_channel_id,
              spec.accountant,
              udp_policy,
              udp_slot,
              datagram_router.clone(),
              udp_stream_sender.clone(),
            ));
          }
          while tasks.join_next().await.is_some() {}
        },
      )
    }
    _ => QomtConnection::new(inner),
  };

  #[cfg(test)]
  {
    qomt_connection.underlay_metrics = Some(underlay_metrics);
  }

  Ok(qomt_connection)
}

pub async fn qomt_accept(
  quiche_config: &mut quiche::Config,
  udp_quiche_config: Option<quiche::Config>,
  mut mt_connections: MtConnections<QuicBytesPacket>,
) -> anyhow::Result<QomtConnection> {
  let first_packet = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, mt_connections.next())
    .await
    .context("timed out waiting for QUIC connection ID")?
    .ok_or_else(|| anyhow::anyhow!("missing first packet (QUIC connection ID)"))?;

  anyhow::ensure!(
    first_packet.len() == quiche::MAX_CONN_ID_LEN,
    "invalid QUIC connection ID length: expected {}, got {}",
    quiche::MAX_CONN_ID_LEN,
    first_packet.len()
  );

  let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());
  let listener_handle = mt_connections.take_listener_handle();
  let underlay_metrics = mt_connections.underlay_metrics();
  let bootstrap_peer_family = IpFamily::from_ip(mt_connections.peer_address().ip());

  quiche_config.set_reliable_transport(cfg!(target_os = "linux"));
  let mut inner = QuicConnection::accept(&connection_id, quiche_config, mt_connections);
  inner.attach_reliable_underlay_metrics(underlay_metrics.clone());

  timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, inner.established())
    .await
    .context("timed out establishing QUIC connection")??;

  let (mut control_stream, client_hello) = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
    let mut control_stream = inner
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing QomT control stream"))?;
    anyhow::ensure!(
      control_stream.id() == 0,
      "expected QomT control stream 0, got {}",
      control_stream.id()
    );
    let client_hello = read_control_hello::<QomtClientControlHello>(&mut control_stream).await?;
    anyhow::Ok((control_stream, client_hello))
  })
  .await
  .context("timed out waiting for QomT client interface metadata")??;

  anyhow::ensure!(
    !client_hello.interfaces.is_empty(),
    "QomT client declared no interfaces"
  );

  let mut client_by_id = HashMap::new();
  let mut peer_in_limiters = HashMap::new();
  for client_if in &client_hello.interfaces {
    anyhow::ensure!(
      client_by_id.insert(client_if.id, client_if).is_none(),
      "QomT client declared duplicate interface id {}",
      client_if.id
    );
    let peer_in = client_if
      .bandwidth_in_bps
      .and_then(|bps| (bps > 0).then(|| Arc::new(TokenBucket::new(bps))));
    peer_in_limiters.insert(client_if.id, peer_in);
  }
  anyhow::ensure!(
    client_by_id.contains_key(&client_hello.bootstrap_client_if_id),
    "unknown bootstrap client interface id {}",
    client_hello.bootstrap_client_if_id
  );

  let server_udp_available = udp_quiche_config.is_some();
  let fallback_interfaces = [LocalInterface::default_implicit()];
  let fallback_udp_enabled = [false];
  let (server_interfaces, server_udp_enabled, bootstrap_server_if_id) = match &listener_handle {
    Some(handle) => (
      handle.server_interfaces(),
      handle.server_udp_enabled(),
      handle.bootstrap_server_if_id(),
    ),
    None => (&fallback_interfaces[..], &fallback_udp_enabled[..], 0),
  };

  let effective_server_udp_enabled: Vec<bool> = server_udp_enabled
    .iter()
    .map(|&enabled| enabled && server_udp_available)
    .collect();
  let server_descs: Vec<ServerInterfaceDesc> = server_interfaces
    .iter()
    .map(|iface| {
      let mut desc =
        iface.to_server_desc(iface.id == bootstrap_server_if_id, bootstrap_peer_family);
      desc.udp &= server_udp_available;
      desc
    })
    .collect();
  let server_by_id: HashMap<u16, &Arc<LocalInterface>> = server_interfaces
    .iter()
    .map(|iface| (iface.id, iface))
    .collect();

  let pairs = pair_interfaces(
    &client_hello.interfaces,
    &server_descs,
    &effective_server_udp_enabled,
  );
  anyhow::ensure!(!pairs.is_empty(), "no compatible interface pairs");

  let extend_token: [u8; 32] = rand::random();
  let capped_requested = client_hello
    .target_connections
    .clamp(1, MAX_CLIENT_TARGET_CONNECTIONS);
  let mut pair_to_server_if = HashMap::with_capacity(pairs.len());
  let mut pair_max_paths = HashMap::with_capacity(pairs.len());
  let mut group_specs = Vec::with_capacity(pairs.len());
  let mut datagram_tiers = Vec::new();
  let mut udp_channel_requests = Vec::new();
  let mut bootstrap_pair_id = None;

  for pair in &pairs {
    pair_to_server_if.insert(pair.pair_id, pair.server_if_id);

    if pair.client_if_id == client_hello.bootstrap_client_if_id
      && pair.server_if_id == bootstrap_server_if_id
    {
      bootstrap_pair_id = Some(pair.pair_id);
    }

    let client_if = client_by_id[&pair.client_if_id];
    let local_if = server_by_id[&pair.server_if_id];
    let peer_in = peer_in_limiters.get(&pair.client_if_id).cloned().flatten();
    let (effective_connections, _) = effective_pair_connections(
      capped_requested,
      client_if.connections_limit,
      local_if.connections_limit,
    );
    pair_max_paths.insert(pair.pair_id, effective_connections.saturating_add(2));

    group_specs.push(PathGroupSpec {
      id: pair.pair_id,
      local_out: local_if.out_limiter.clone(),
      peer_in: peer_in.clone(),
    });

    if let Some(udp_channel_id) = pair.udp_channel_id
      && server_udp_available
    {
      let precharged_bytes = Arc::new(AtomicU64::new(0));
      datagram_tiers.push(DatagramTierConfig {
        pair_id: pair.pair_id,
        local_out: local_if.out_limiter.clone(),
        peer_in: peer_in.clone(),
        precharged_bytes: precharged_bytes.clone(),
      });
      udp_channel_requests.push((
        pair.pair_id,
        pair.server_if_id,
        udp_channel_id,
        UdpBandwidthAccountant {
          local_out: local_if.out_limiter.clone(),
          peer_in,
          precharged_bytes,
        },
      ));
    }
  }

  let fallback_limits = bootstrap_pair_id.is_none().then(|| {
    let local_out = server_by_id
      .get(&bootstrap_server_if_id)
      .and_then(|iface| iface.out_limiter.clone());
    let peer_in = peer_in_limiters
      .get(&client_hello.bootstrap_client_if_id)
      .cloned()
      .flatten();
    (local_out, peer_in)
  });

  if let Some(handle) = &listener_handle {
    handle.install_extend_plan(
      extend_token,
      pair_to_server_if,
      pair_max_paths,
      &underlay_metrics,
    );
  }
  underlay_metrics.configure_groups(group_specs, bootstrap_pair_id, fallback_limits);

  let udp_slots_with_pair = match (
    &listener_handle,
    udp_quiche_config.is_some(),
    udp_channel_requests.is_empty(),
  ) {
    (Some(handle), true, false) => {
      let channel_inputs: Vec<(u16, MtConnectionsId, Option<UdpBandwidthAccountant>)> =
        udp_channel_requests
          .iter()
          .map(|(_, server_if_id, channel_id, accountant)| {
            (*server_if_id, *channel_id, Some(accountant.clone()))
          })
          .collect();
      let registered = handle.replace_udp_channels(channel_inputs);
      let slot_by_channel: HashMap<MtConnectionsId, Arc<UdpDuplexSlot<QuicBytesPacket>>> =
        registered.into_iter().collect();

      udp_channel_requests
        .iter()
        .filter_map(|(pair_id, _, channel_id, _)| {
          slot_by_channel
            .get(channel_id)
            .cloned()
            .map(|slot| (*pair_id, slot))
        })
        .collect()
    }
    (Some(handle), _, _) => {
      handle.clear_udp_channels();
      Vec::new()
    }
    (None, _, _) => Vec::new(),
  };

  timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
    let response = QomtServerControlHello {
      interfaces: server_descs,
      bootstrap_server_if_id,
      extend_token,
      pairs,
    };
    control_stream
      .write_all(&postcard::to_allocvec(&response).unwrap())
      .await?;
    control_stream.flush().await?;
    control_stream.shutdown().await?;
    anyhow::Ok(())
  })
  .await
  .context("timed out sending QomT server interface metadata")??;

  #[cfg_attr(not(test), allow(unused_mut))]
  let mut qomt_connection = match (udp_quiche_config, udp_slots_with_pair.is_empty()) {
    (Some(udp_quiche_config), false) => {
      let datagram_router = QomtDatagramRouter::new();
      datagram_router.configure_tiers(datagram_tiers);

      let udp_slots = (0..udp_slots_with_pair.len())
        .map(|_| Arc::new(Mutex::new(QomtUdpConnection::Connecting)))
        .collect();
      let udp_quiche_config = Arc::new(Mutex::new(udp_quiche_config));

      QomtConnection::with_udp_supervisors(
        inner,
        datagram_router,
        udp_slots,
        move |udp_slots, datagram_router, udp_stream_sender| async move {
          let mut tasks = JoinSet::new();
          for ((pair_id, duplex_slot), udp_slot) in udp_slots_with_pair.into_iter().zip(udp_slots) {
            tasks.spawn(supervise_accept_side_udp(
              pair_id,
              udp_quiche_config.clone(),
              duplex_slot,
              udp_slot,
              datagram_router.clone(),
              udp_stream_sender.clone(),
            ));
          }
          while tasks.join_next().await.is_some() {}
        },
      )
    }
    _ => QomtConnection::new(inner),
  };

  #[cfg(test)]
  {
    qomt_connection.underlay_metrics = Some(underlay_metrics);
  }

  Ok(qomt_connection)
}

fn main_keepalive_tasks(inner: &QuicConnection, period: Duration) -> JoinSet<()> {
  let mut tasks = JoinSet::new();
  tasks.spawn(inner.keepalive_future(period));
  tasks
}

#[cfg(test)]
mod main_keepalive_tests {
  use super::*;
  use crate::quic_connection::tests::get_quiche_configs;
  use std::sync::atomic::{AtomicUsize, Ordering};

  async fn idle_pair() -> anyhow::Result<(QuicConnection, QuicConnection, Arc<AtomicUsize>)> {
    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    server_config.set_max_idle_timeout(400);
    client_config.set_max_idle_timeout(400);
    let (to_server, from_client) = flume::bounded::<QuicBytesPacket>(64);
    let (to_client, from_server) = flume::bounded::<QuicBytesPacket>(64);
    let packets = Arc::new(AtomicUsize::new(0));
    let count = packets.clone();
    let server_stream = from_client.into_stream().inspect(move |_| {
      count.fetch_add(1, Ordering::Relaxed);
    });
    let id = QuicConnection::generate_connection_id();
    let client = QuicConnection::connect_with_sink_and_stream(
      &id,
      &mut client_config,
      to_server.into_sink(),
      from_server.into_stream(),
    );
    let server = QuicConnection::accept_with_sink_and_stream(
      client.id(),
      &mut server_config,
      to_client.into_sink(),
      server_stream,
    );
    timeout(Duration::from_secs(3), async {
      tokio::try_join!(client.established(), server.established())
    })
    .await??;
    Ok((server, client, packets))
  }

  #[tokio::test]
  async fn main_keepalive_control_expires_without_ping() -> anyhow::Result<()> {
    let (server, client, _) = idle_pair().await?;
    timeout(Duration::from_secs(3), async {
      tokio::join!(server.wait_closed(), client.wait_closed());
    })
    .await?;
    Ok(())
  }

  #[tokio::test]
  async fn main_keepalive_preserves_idle_connection_and_stops_on_owner_drop() -> anyhow::Result<()>
  {
    let (server, client, packets) = idle_pair().await?;
    let mut owner = QomtConnection::new(client);
    owner._join_set.abort_all();
    owner._join_set = main_keepalive_tasks(&owner.inner, Duration::from_millis(50));
    let before = packets.load(Ordering::Relaxed);
    sleep(Duration::from_millis(1300)).await;
    assert_eq!(server.state(), State::Established);
    assert_eq!(owner.state(), State::Established);
    let sent = packets.load(Ordering::Relaxed) - before;
    assert!(
      (10..=60).contains(&sent),
      "bounded keepalive packet count: {sent}"
    );
    let mut outgoing = owner.open_stream();
    outgoing.write_all(b"after idle").await?;
    outgoing.shutdown().await?;
    let mut incoming = timeout(Duration::from_secs(2), server.accept_stream())
      .await??
      .unwrap();
    let mut data = Vec::new();
    timeout(Duration::from_secs(2), incoming.read_to_end(&mut data)).await??;
    assert_eq!(data, b"after idle");
    drop(incoming);
    drop(outgoing);
    let QomtConnection {
      inner: client,
      _join_set: tasks,
      ..
    } = owner;
    drop(tasks);
    // Raw handles remain alive. Stopping the owner's timer must restore expiry.
    timeout(Duration::from_secs(3), async {
      tokio::join!(server.wait_closed(), client.wait_closed());
    })
    .await?;
    Ok(())
  }
}
