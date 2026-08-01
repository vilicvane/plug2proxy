use std::{
  net::SocketAddr,
  ops::Deref,
  sync::{Arc, Mutex},
  time::Duration,
};

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use rand::Rng;
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  task::JoinSet,
  time::{Instant, MissedTickBehavior, interval_at, sleep, timeout, timeout_at},
};

use crate::{
  mt_connections::{
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MtConnections, MtConnectionsId, MtConnectionsPacket,
    MtConnectionsSideUdpDuplex, MtConnectionsUdpPacket, UdpDuplexSlot, mt_connections_connect,
  },
  qomt::QomtStream,
  quic_connection::{
    MAX_DATAGRAM_SIZE, QuicBytesPacket, QuicConnection, QuicConnectionError, QuicPathMetrics, State,
  },
};

use super::{
  QomtDatagramRegistration, QomtDatagramRouter, QomtDatagramSendOutcome, QomtDatagramStats,
};

pub const MAX_PENDING_QOMT_HANDSHAKES: usize = 64;

/// UDP 旁路的握手超时：旁路是增强，不能拖慢 TCP 主路径——正常场景
/// UDP 握手与 TCP 握手并行、亚秒级完成；失败或对端未启用 UDP 时
/// 快速放弃（旁路静默缺席），而不是等满 mTCP 握手超时。
const QOMT_UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

const QOMT_UDP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const QOMT_UDP_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const QOMT_UDP_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
const RTT_INFLATION_MINIMUM: Duration = Duration::from_millis(10);
const RTT_INFLATION_BASELINE_DIVISOR: u32 = 2;
const UDP_RTT_ADVANTAGE_MINIMUM: Duration = Duration::from_millis(5);

#[derive(Clone, Copy)]
pub(crate) struct QomtUdpReconnectPolicy {
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
  udp: Arc<Mutex<QomtUdpConnection>>,
  datagram_router: Arc<QomtDatagramRouter>,
  // UDP supervisor runs independently from the main handshake, but stops on
  // main QUIC Closed; owner drop aborts it as a final fallback.
  _join_set: JoinSet<()>,
}

enum QomtUdpConnection {
  Disabled,
  Connecting,
  Established(Arc<QuicConnection>),
  Reconnecting,
  Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QomtUdpState {
  Disabled,
  Connecting,
  Established,
  Reconnecting,
  Closed,
}

impl QomtConnection {
  pub fn new(inner: QuicConnection) -> Self {
    let datagram_router = QomtDatagramRouter::new();

    Self {
      inner,
      udp: Arc::new(Mutex::new(QomtUdpConnection::Disabled)),
      datagram_router,
      _join_set: JoinSet::new(),
    }
  }

  fn with_udp_supervisor<TSupervisor>(
    inner: QuicConnection,
    supervisor: impl FnOnce(Arc<Mutex<QomtUdpConnection>>, Arc<QomtDatagramRouter>) -> TSupervisor
    + Send
    + 'static,
  ) -> Self
  where
    TSupervisor: std::future::Future<Output = ()> + Send + 'static,
  {
    let udp = Arc::new(Mutex::new(QomtUdpConnection::Connecting));
    let datagram_router = QomtDatagramRouter::new();
    let mut join_set = JoinSet::new();
    let main_closed = inner.closed_future();
    let supervisor_udp = udp.clone();
    let supervisor_datagram_router = datagram_router.clone();
    let cleanup_udp = udp.clone();
    let cleanup_datagram_router = datagram_router.clone();

    join_set.spawn(async move {
      tokio::select! {
        _ = main_closed => {}
        _ = supervisor(supervisor_udp, supervisor_datagram_router) => {}
      }

      // Drop the losing future first, then remove every reference to its last
      // UDP generation. The main connection is the lifetime authority for the
      // bypass; a terminal main path must never leave a reconnect loop alive.
      cleanup_datagram_router.deactivate();
      *cleanup_udp.lock().unwrap() = QomtUdpConnection::Closed;
    });

    Self {
      inner,
      udp,
      datagram_router,
      _join_set: join_set,
    }
  }

  pub async fn established(&self) -> Result<(), QuicConnectionError> {
    self.inner.established().await
  }

  pub fn open_stream(&self) -> QomtStream {
    QomtStream::new(self.inner.open_stream())
  }

  pub async fn accept_stream(&self) -> Result<Option<QomtStream>, QuicConnectionError> {
    self
      .inner
      .accept_stream()
      .await
      .map(|stream| stream.map(QomtStream::new))
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
    match &*self.udp.lock().unwrap() {
      QomtUdpConnection::Disabled => QomtUdpState::Disabled,
      QomtUdpConnection::Connecting => QomtUdpState::Connecting,
      QomtUdpConnection::Established(connection) => match connection.state() {
        State::Established => QomtUdpState::Established,
        State::Initial => QomtUdpState::Connecting,
        State::Draining | State::Closed => QomtUdpState::Closed,
      },
      QomtUdpConnection::Reconnecting => QomtUdpState::Reconnecting,
      QomtUdpConnection::Closed => QomtUdpState::Closed,
    }
  }

  pub fn diagnostics(&self) -> String {
    let mut diagnostics = self.inner.diagnostics();

    match &*self.udp.lock().unwrap() {
      QomtUdpConnection::Disabled => diagnostics.push_str(" udp=disabled"),
      QomtUdpConnection::Connecting => diagnostics.push_str(" udp=connecting"),
      QomtUdpConnection::Established(connection) => {
        diagnostics.push_str(&format!(" udp=[{}]", connection.diagnostics()));
      }
      QomtUdpConnection::Reconnecting => diagnostics.push_str(" udp=reconnecting"),
      QomtUdpConnection::Closed => diagnostics.push_str(" udp=closed"),
    }

    let datagram = self.datagram_router.stats();
    diagnostics.push_str(&format!(
      " qomt_dgram=[sent={} recv={} send_full={} unknown={} recv_full={} malformed={}]",
      datagram.sent,
      datagram.received,
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

  pub(crate) fn max_association_datagram_payload_len(&self) -> Option<usize> {
    self.datagram_router.max_payload_len()
  }

  pub(crate) fn rtt_prefers_udp(&self) -> bool {
    let Some(main) = self.inner.datagram_socket().path_metrics() else {
      return false;
    };
    let Some(udp) = self.datagram_router.path_metrics() else {
      return false;
    };

    path_metrics_prefer_udp(main, udp)
  }

  #[cfg(test)]
  pub(crate) fn datagram_route_count(&self) -> usize {
    self.datagram_router.route_count()
  }

  #[cfg(test)]
  pub(crate) fn udp_connection_id(&self) -> Option<Vec<u8>> {
    match &*self.udp.lock().unwrap() {
      QomtUdpConnection::Established(connection) => Some(connection.id().to_vec()),
      _ => None,
    }
  }
}

fn path_metrics_prefer_udp(main: QuicPathMetrics, udp: QuicPathMetrics) -> bool {
  let Some(main_min_rtt) = main.min_rtt else {
    return false;
  };

  let inflation_threshold =
    RTT_INFLATION_MINIMUM.max(main_min_rtt / RTT_INFLATION_BASELINE_DIVISOR);
  main.rtt.saturating_sub(main_min_rtt) >= inflation_threshold
    && udp.rtt.saturating_add(UDP_RTT_ADVANTAGE_MINIMUM) < main.rtt
}

async fn run_established_udp_generation(
  connection: QuicConnection,
  udp: &Arc<Mutex<QomtUdpConnection>>,
  datagram_router: &Arc<QomtDatagramRouter>,
  keepalive_interval: Option<Duration>,
) -> Duration {
  let established_at = Instant::now();
  let connection = Arc::new(connection);
  let diagnostic_id = connection.diagnostic_id();
  let socket = connection.datagram_socket();
  *udp.lock().unwrap() = QomtUdpConnection::Established(connection.clone());

  let mut router_run = Box::pin(datagram_router.clone().run(socket));
  let terminal = connection.wait_closed();
  tokio::pin!(terminal);

  let mut keepalive = keepalive_interval.map(|period| {
    let mut interval = interval_at(Instant::now() + period, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
  });
  let mut router_finished = false;

  loop {
    tokio::select! {
      _ = &mut terminal => break,
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
  mut udp_quiche_config: quiche::Config,
  address: SocketAddr,
  mt_connections_id: MtConnectionsId,
  policy: QomtUdpReconnectPolicy,
  udp: Arc<Mutex<QomtUdpConnection>>,
  datagram_router: Arc<QomtDatagramRouter>,
) {
  let mut retry_delay = policy.reconnect_initial_delay;
  let mut generation = 0u64;

  loop {
    *udp.lock().unwrap() = if generation == 0 {
      QomtUdpConnection::Connecting
    } else {
      QomtUdpConnection::Reconnecting
    };

    let connection =
      match MtConnectionsSideUdpDuplex::connect_side(address, mt_connections_id).await {
        Ok(udp_duplex) => {
          let udp_connection_id = QuicConnection::generate_connection_id();
          let udp_connection =
            QuicConnection::connect(&udp_connection_id, &mut udp_quiche_config, udp_duplex);
          establish_connect_side_udp_connection(udp_connection).await
        }
        Err(error) => {
          log::warn!("error creating UDP side channel to {address}: {error}");
          None
        }
      };

    if let Some(connection) = connection {
      generation = generation.saturating_add(1);
      log::info!("QomT UDP generation {generation} to {address} established");
      let lifetime = run_established_udp_generation(
        connection,
        &udp,
        &datagram_router,
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
    log::debug!("retrying QomT UDP connection to {address} in {actual_delay:?}");
    sleep(actual_delay).await;
    retry_delay = retry_delay
      .saturating_mul(2)
      .min(policy.reconnect_max_delay);
  }
}

async fn supervise_accept_side_udp(
  mut udp_quiche_config: quiche::Config,
  udp_duplex_slot: Arc<UdpDuplexSlot<QuicBytesPacket>>,
  udp: Arc<Mutex<QomtUdpConnection>>,
  datagram_router: Arc<QomtDatagramRouter>,
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
      establish_accept_side_udp_connection(&mut udp_quiche_config, udp_duplex).await
    else {
      *udp.lock().unwrap() = QomtUdpConnection::Reconnecting;
      continue;
    };

    generation = generation.saturating_add(1);
    log::info!("accepted QomT UDP generation {generation}");
    run_established_udp_generation(connection, &udp, &datagram_router, None).await;
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
  udp_quiche_config: &mut quiche::Config,
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

    let udp_connection = QuicConnection::accept_with_first_packet(
      &udp_connection_id,
      udp_quiche_config,
      first_packet,
      udp_duplex,
    );
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

pub async fn qomt_connect(
  quiche_config: &mut quiche::Config,
  udp_quiche_config: Option<quiche::Config>,
  address: SocketAddr,
  connections: usize,
) -> anyhow::Result<QomtConnection> {
  qomt_connect_with_udp_policy(
    quiche_config,
    udp_quiche_config,
    address,
    connections,
    QomtUdpReconnectPolicy::default(),
  )
  .await
}

pub(crate) async fn qomt_connect_with_udp_policy(
  quiche_config: &mut quiche::Config,
  udp_quiche_config: Option<quiche::Config>,
  address: SocketAddr,
  connections: usize,
  udp_policy: QomtUdpReconnectPolicy,
) -> anyhow::Result<QomtConnection> {
  let (mut mt_connections, extend_signal_sender) =
    mt_connections_connect::<QuicBytesPacket>(address, connections)
      .await
      .context("failed to create mTCP connections.")?;
  let mt_connections_id = mt_connections.id();

  let connection_id = QuicConnection::generate_connection_id();

  mt_connections.send(connection_id.to_vec().into()).await?;

  let inner = QuicConnection::connect(&connection_id, quiche_config, mt_connections);

  let qomt_connection = match udp_quiche_config {
    Some(udp_quiche_config) => {
      QomtConnection::with_udp_supervisor(inner, move |udp, datagram_router| {
        supervise_connect_side_udp(
          udp_quiche_config,
          address,
          mt_connections_id,
          udp_policy,
          udp,
          datagram_router,
        )
      })
    }
    None => QomtConnection::new(inner),
  };

  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    qomt_connection.established(),
  )
  .await
  .context("timed out establishing QUIC connection")??;

  extend_signal_sender.send(()).ok();

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

  // MtConnections 将随 QUIC 连接 move，先取出 UDP 槽位以便之后等待。
  let udp_duplex_slot = mt_connections.udp_duplex_slot();

  let inner = QuicConnection::accept(&connection_id, quiche_config, mt_connections);

  // The supervisor waits for every UDP generation without delaying the main
  // handshake. Each generation still has its own absolute Initial/QUIC
  // handshake deadline.
  let qomt_connection = match udp_quiche_config {
    Some(udp_quiche_config) => {
      QomtConnection::with_udp_supervisor(inner, move |udp, datagram_router| {
        supervise_accept_side_udp(udp_quiche_config, udp_duplex_slot, udp, datagram_router)
      })
    }
    None => QomtConnection::new(inner),
  };

  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    qomt_connection.established(),
  )
  .await
  .context("timed out establishing QUIC connection")??;

  Ok(qomt_connection)
}

#[cfg(test)]
mod path_selection_tests {
  use super::*;

  fn metrics(rtt_millis: u64, min_rtt_millis: Option<u64>) -> QuicPathMetrics {
    QuicPathMetrics {
      rtt: Duration::from_millis(rtt_millis),
      min_rtt: min_rtt_millis.map(Duration::from_millis),
      rttvar: Duration::ZERO,
      dgram_sent: 0,
      dgram_recv: 0,
      dgram_lost: 0,
    }
  }

  #[test]
  fn rtt_policy_uses_one_fixed_threshold() {
    assert!(!path_metrics_prefer_udp(
      metrics(29, Some(20)),
      metrics(20, Some(20)),
    ));
    assert!(path_metrics_prefer_udp(
      metrics(30, Some(20)),
      metrics(24, Some(20)),
    ));
    assert!(!path_metrics_prefer_udp(
      metrics(30, Some(20)),
      metrics(25, Some(20)),
    ));
  }

  #[test]
  fn rtt_policy_requires_a_baseline_and_strict_udp_advantage() {
    assert!(!path_metrics_prefer_udp(
      metrics(30, None),
      metrics(20, Some(20)),
    ));
    assert!(!path_metrics_prefer_udp(
      metrics(30, Some(20)),
      metrics(25, Some(20)),
    ));
  }
}
