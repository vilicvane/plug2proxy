use std::{
  net::SocketAddr,
  pin::Pin,
  sync::{
    Arc, Mutex,
    atomic::{self, AtomicU64, AtomicUsize},
  },
  task::{Context, Poll},
  time::{Duration, Instant},
};

use futures::{Sink, Stream};
use lowkit::{DropCallback, SelfWrapExt, TurnArcWeak, tokio_join_set};
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
  io::{AsyncRead, AsyncWrite},
  net::TcpStream,
  sync::{Notify, mpsc},
  task::JoinSet,
  time::{Instant as TokioInstant, MissedTickBehavior, interval_at, timeout},
};
use uuid::{Uuid, serde::compact};

use super::mt_connections_side_udp::{MtConnectionsSideUdpDuplex, MtConnectionsUdpPacket};
use crate::{primitives::ConnectionSide, utils::task::reap_finished_tasks};

type UdpDispatchRegistration = DropCallback<Box<dyn Fn() + Send>>;

pub const MT_CONNECTIONS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MT_CONNECTIONS_PACKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MT_CONNECTIONS_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
pub const MT_CONNECTIONS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const MT_CONNECTIONS_KEEPALIVE_RETRIES: u32 = 3;
pub const MT_CONNECTIONS_TCP_USER_TIMEOUT: Duration = Duration::from_secs(60);
const MT_CONNECTIONS_DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(5 * 60);

struct MtConnectionsDiagnostics {
  created_at: Instant,
  tcp_write_packets: AtomicU64,
  tcp_write_bytes: AtomicU64,
  tcp_read_packets: AtomicU64,
  tcp_read_bytes: AtomicU64,
  pending_tcp_writes: AtomicUsize,
  pending_packet_deliveries: AtomicUsize,
  last_tcp_write_progress_millis: AtomicU64,
  last_tcp_read_progress_millis: AtomicU64,
}

impl MtConnectionsDiagnostics {
  fn new() -> Self {
    Self {
      created_at: Instant::now(),
      tcp_write_packets: AtomicU64::new(0),
      tcp_write_bytes: AtomicU64::new(0),
      tcp_read_packets: AtomicU64::new(0),
      tcp_read_bytes: AtomicU64::new(0),
      pending_tcp_writes: AtomicUsize::new(0),
      pending_packet_deliveries: AtomicUsize::new(0),
      last_tcp_write_progress_millis: AtomicU64::new(0),
      last_tcp_read_progress_millis: AtomicU64::new(0),
    }
  }

  fn elapsed_millis(&self) -> u64 {
    self.created_at.elapsed().as_millis().min(u64::MAX as u128) as u64
  }

  fn record_tcp_write(&self, bytes: usize) {
    self
      .tcp_write_packets
      .fetch_add(1, atomic::Ordering::Relaxed);
    self
      .tcp_write_bytes
      .fetch_add(bytes as u64, atomic::Ordering::Relaxed);
    self
      .last_tcp_write_progress_millis
      .store(self.elapsed_millis(), atomic::Ordering::Release);
  }

  fn record_tcp_read(&self, bytes: usize) {
    self
      .tcp_read_packets
      .fetch_add(1, atomic::Ordering::Relaxed);
    self
      .tcp_read_bytes
      .fetch_add(bytes as u64, atomic::Ordering::Relaxed);
    self
      .last_tcp_read_progress_millis
      .store(self.elapsed_millis(), atomic::Ordering::Release);
  }

  fn snapshot(&self) -> String {
    let age_millis = self.elapsed_millis();
    let last_write_millis = self
      .last_tcp_write_progress_millis
      .load(atomic::Ordering::Acquire);
    let last_read_millis = self
      .last_tcp_read_progress_millis
      .load(atomic::Ordering::Acquire);

    format!(
      "age_ms={age_millis} tcp_write_packets={} tcp_write_bytes={} \
       tcp_read_packets={} tcp_read_bytes={} pending_tcp_writes={} \
       pending_packet_deliveries={} tcp_write_idle_ms={} tcp_read_idle_ms={}",
      self.tcp_write_packets.load(atomic::Ordering::Relaxed),
      self.tcp_write_bytes.load(atomic::Ordering::Relaxed),
      self.tcp_read_packets.load(atomic::Ordering::Relaxed),
      self.tcp_read_bytes.load(atomic::Ordering::Relaxed),
      self.pending_tcp_writes.load(atomic::Ordering::Acquire),
      self
        .pending_packet_deliveries
        .load(atomic::Ordering::Acquire),
      age_millis.saturating_sub(last_write_millis),
      age_millis.saturating_sub(last_read_millis),
    )
  }
}

pub(crate) fn configure_mt_tcp_stream(tcp_stream: &TcpStream) -> std::io::Result<()> {
  tcp_stream.set_nodelay(true)?;

  let socket = SockRef::from(tcp_stream);

  #[cfg(target_os = "linux")]
  socket
    .set_tcp_congestion(b"bbr")
    .inspect_err(|error| {
      log::warn!("failed to enable BBR for mTCP connection: {error}");
    })
    .ok();

  socket.set_tcp_keepalive(
    &TcpKeepalive::new()
      .with_time(MT_CONNECTIONS_KEEPALIVE_TIME)
      .with_interval(MT_CONNECTIONS_KEEPALIVE_INTERVAL)
      .with_retries(MT_CONNECTIONS_KEEPALIVE_RETRIES),
  )?;

  #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
  socket.set_tcp_user_timeout(Some(MT_CONNECTIONS_TCP_USER_TIMEOUT))?;

  Ok(())
}

pub struct MtConnections<TPacket>
where
  TPacket: 'static,
{
  id: MtConnectionsId,
  peer_address: SocketAddr,
  packet_sink: flume::r#async::SendSink<'static, TPacket>,
  packet_stream: flume::r#async::RecvStream<'static, TPacket>,
  connection_count: Arc<AtomicUsize>,
  udp_duplex: Arc<UdpDuplexSlot<TPacket>>,
  _udp_registration: Option<UdpDispatchRegistration>,
  join_set: JoinSet<()>,
}

/// UDP 侧双工通道的共享槽位：duplex 由 connect 侧建立、listener 侧分发
/// 循环写入；qomt 通过 `wait`/`take` 取出。独立于 MtConnections 存活，
/// 以便 MtConnections 被 move 进 QUIC 连接后仍可等待/取出。
pub struct UdpDuplexSlot<TPacket>
where
  TPacket: 'static,
{
  duplex: Mutex<Option<MtConnectionsSideUdpDuplex<TPacket>>>,
  notify: Notify,
}

impl<TPacket> UdpDuplexSlot<TPacket> {
  fn new() -> Self {
    Self {
      duplex: Mutex::new(None),
      notify: Notify::new(),
    }
  }
}

impl<TPacket> UdpDuplexSlot<TPacket>
where
  TPacket: MtConnectionsUdpPacket,
{
  pub(crate) fn set(&self, duplex: MtConnectionsSideUdpDuplex<TPacket>) {
    *self.duplex.lock().unwrap() = Some(duplex);
    self.notify.notify_one();
  }

  pub(crate) fn take(&self) -> Option<MtConnectionsSideUdpDuplex<TPacket>> {
    self.duplex.lock().unwrap().take()
  }

  /// 等待 duplex 就绪（listener 侧由分发循环在首包到达时创建，可能在
  /// accept 返回之后；connect 侧通常在返回前已就绪）。无超时，由调用方
  /// 包 `timeout`；已就绪时立即返回。
  pub(crate) async fn wait(&self) -> Option<MtConnectionsSideUdpDuplex<TPacket>> {
    loop {
      let notified = self.notify.notified();
      tokio::pin!(notified);

      if let Some(duplex) = self.take() {
        return Some(duplex);
      }

      notified.await;
    }
  }
}

impl<TPacket> MtConnections<TPacket>
where
  TPacket: MtConnectionsPacket,
{
  pub fn new(
    initial_tcp_stream: TcpStream,
    side: ConnectionSide,
    id: MtConnectionsId,
  ) -> (
    Self,
    mpsc::UnboundedSender<TcpStream>,
    mpsc::UnboundedReceiver<()>,
  ) {
    let peer_address = initial_tcp_stream.peer_addr().unwrap();

    let (tcp_stream_sender, mut tcp_stream_receiver) = mpsc::unbounded_channel();
    let (tcp_stream_close_sender, tcp_stream_close_receiver) = mpsc::unbounded_channel();

    let (external_packet_sender, packet_receiver) = flume::bounded::<TPacket>(0);
    let (packet_sender, external_packet_receiver) = flume::bounded::<TPacket>(0);

    let connection_count = Arc::new(AtomicUsize::new(0));
    let diagnostics = Arc::new(MtConnectionsDiagnostics::new());
    let manager_connection_count = connection_count.clone();
    let manager_diagnostics = diagnostics.clone();

    let manager = async move {
      let (all_connections_closed_sender, mut all_connections_closed_receiver) = mpsc::channel(1);

      let packet_sender = TurnArcWeak::new(packet_sender).mutex().arc();

      let pipe_bidirectional = |tcp_stream: TcpStream| {
        let tcp_stream_close_sender = tcp_stream_close_sender.clone();

        let packet_sender = packet_sender.clone();
        let packet_receiver = packet_receiver.clone();

        let connection_count = manager_connection_count.clone();
        let diagnostics = manager_diagnostics.clone();

        let all_connections_closed_sender = all_connections_closed_sender.clone();

        async move {
          let Some(packet_sender) = packet_sender.lock().unwrap().get_arc() else {
            return;
          };

          let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

          connection_count.fetch_add(1, atomic::Ordering::Relaxed);
          let write_diagnostics = diagnostics.clone();
          let read_diagnostics = diagnostics.clone();

          let copy_result = tokio::select! {
              result = async move {
              loop {
                match packet_receiver.recv_async().await {
                  Ok(packet) => {
                    let packet_length = packet.len();
                      write_diagnostics
                        .pending_tcp_writes
                        .fetch_add(1, atomic::Ordering::AcqRel);
                    let write_result = timeout(
                      MT_CONNECTIONS_PACKET_WRITE_TIMEOUT,
                      TPacket::write_packet(&mut tcp_write, packet),
                    )
                    .await;
                      write_diagnostics
                        .pending_tcp_writes
                        .fetch_sub(1, atomic::Ordering::AcqRel);
                    write_result
                      .map_err(|_| anyhow::anyhow!("timed out writing packet to TCP stream"))??;
                      write_diagnostics.record_tcp_write(packet_length);
                  }
                  Err(flume::RecvError::Disconnected) => break,
                }
              }

              log::debug!("{side} write tcp stream loop ended");

              anyhow::Ok(())
            } => result,
            result = async move {
              loop {
                let Some(packet) = TPacket::read_next_packet(&mut tcp_read).await? else {
                  break;
                };
                  read_diagnostics.record_tcp_read(packet.len());
                  read_diagnostics
                    .pending_packet_deliveries
                    .fetch_add(1, atomic::Ordering::AcqRel);
                  let send_result = packet_sender.send_async(packet).await;
                  read_diagnostics
                    .pending_packet_deliveries
                  .fetch_sub(1, atomic::Ordering::AcqRel);
                send_result?;
              }

              log::debug!("{side} read tcp stream loop ended");

              anyhow::Ok(())
            } => result,
          };

          copy_result
            .inspect_err(|error| {
              log::warn!("error copying bidirectional packet stream: {}", error);
            })
            .ok();

          let all_connections_closed =
            connection_count.fetch_sub(1, atomic::Ordering::Relaxed) == 1;

          if all_connections_closed {
            all_connections_closed_sender.send(()).await.ok();
          } else {
            tcp_stream_close_sender.send(()).ok();
          }
        }
      };

      let mut join_set = JoinSet::new();

      join_set.spawn(pipe_bidirectional(initial_tcp_stream));

      while let Some(tcp_stream) = tokio::select!(
        tcp_stream = tcp_stream_receiver.recv() => tcp_stream,
        _ = all_connections_closed_receiver.recv() => None,
      ) {
        reap_finished_tasks(&mut join_set, "mTCP path task");
        join_set.spawn(pipe_bidirectional(tcp_stream));
      }
    };

    let diagnostic_connection_count = connection_count.clone();
    let diagnostic_counters = diagnostics.clone();
    let diagnostics_loop = async move {
      let mut interval = interval_at(
        TokioInstant::now() + MT_CONNECTIONS_DIAGNOSTIC_INTERVAL,
        MT_CONNECTIONS_DIAGNOSTIC_INTERVAL,
      );
      interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

      loop {
        interval.tick().await;
        let paths = diagnostic_connection_count.load(atomic::Ordering::Acquire);

        if paths == 0 {
          break;
        }

        log::debug!(
          "mTCP diagnostic: side={side} peer={peer_address} paths={paths} {}",
          diagnostic_counters.snapshot()
        );
      }
    };

    let mt_connections = Self {
      id,
      peer_address,
      packet_sink: external_packet_sender.into_sink(),
      packet_stream: external_packet_receiver.into_stream(),
      connection_count: connection_count.clone(),
      udp_duplex: Arc::new(UdpDuplexSlot::new()),
      _udp_registration: None,
      join_set: tokio_join_set!(manager, diagnostics_loop),
    };

    (mt_connections, tcp_stream_sender, tcp_stream_close_receiver)
  }

  pub fn peer_address(&self) -> SocketAddr {
    self.peer_address
  }

  pub fn id(&self) -> MtConnectionsId {
    self.id
  }

  pub fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
    self.join_set.spawn(task);
  }

  pub fn connection_count(&self) -> usize {
    self.connection_count.load(atomic::Ordering::Relaxed)
  }

  #[cfg(test)]
  pub(crate) fn connection_count_observer(&self) -> Arc<AtomicUsize> {
    self.connection_count.clone()
  }

  pub(crate) fn set_udp_registration(&mut self, registration: UdpDispatchRegistration) {
    assert!(
      self._udp_registration.replace(registration).is_none(),
      "UDP dispatch registration may only be installed once",
    );
  }
}

impl<TPacket> MtConnections<TPacket>
where
  TPacket: MtConnectionsPacket + MtConnectionsUdpPacket,
{
  /// 设置 UDP 侧双工通道（connect 侧建立后、listener 侧分发到达后调用）。
  pub fn set_udp_duplex(&self, udp_duplex: MtConnectionsSideUdpDuplex<TPacket>) {
    self.udp_duplex.set(udp_duplex);
  }

  /// 取出 UDP 侧双工通道，供上层（qomt）创建并行的 QUIC connection over UDP。
  ///
  /// UDP 通道建立失败（如本地 bind 失败）时为 `None`，上层静默缺席。
  pub fn take_udp_duplex(&self) -> Option<MtConnectionsSideUdpDuplex<TPacket>> {
    self.udp_duplex.take()
  }

  /// 等待 UDP 侧双工通道就绪（listener 侧由分发循环在首包到达时创建，
  /// 可能在 accept 返回之后；connect 侧通常在返回前已就绪）。
  ///
  /// 无超时：由调用方包 `timeout`。通道已就绪时立即返回。
  pub async fn wait_udp_duplex(&self) -> Option<MtConnectionsSideUdpDuplex<TPacket>> {
    self.udp_duplex.wait().await
  }

  /// 共享的 UDP duplex 槽位（listener 侧登记用）：listener 分发循环可
  /// 在 accept 之后把到达的 UDP 通道写入该槽位，由本侧 wait/take 取出。
  /// 独立于 MtConnections 存活：本实例被 move 进 QUIC 连接后仍可用。
  pub(crate) fn udp_duplex_slot(&self) -> Arc<UdpDuplexSlot<TPacket>> {
    self.udp_duplex.clone()
  }
}

impl<TPacket> Stream for MtConnections<TPacket> {
  type Item = TPacket;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(cx)
  }
}

impl<TPacket> Sink<TPacket> for MtConnections<TPacket> {
  type Error = flume::SendError<TPacket>;

  fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_ready(cx)
  }

  fn start_send(mut self: Pin<&mut Self>, item: TPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink).start_send(item)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_flush(cx)
  }

  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_close(cx)
  }
}

pub trait MtConnectionsPacket: Sized + Send + Sync + 'static {
  fn len(&self) -> usize;

  fn is_empty(&self) -> bool {
    self.len() == 0
  }

  fn read_next_packet(
    stream: &mut (dyn AsyncRead + Unpin + Send),
  ) -> impl Future<Output = Result<Option<Self>, std::io::Error>> + Send;

  fn write_packet(
    stream: &mut (dyn AsyncWrite + Unpin + Send),
    packet: Self,
  ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct MtConnectionsId(#[serde(with = "compact")] Uuid);

impl MtConnectionsId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }

  pub fn as_bytes(&self) -> &[u8; 16] {
    self.0.as_bytes()
  }

  pub fn from_bytes(bytes: [u8; 16]) -> Self {
    Self(Uuid::from_bytes(bytes))
  }
}

impl Default for MtConnectionsId {
  fn default() -> Self {
    Self::new()
  }
}

pub const MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE: usize = 4 + 1 + 16;
pub const MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE: usize = 4 + 1 + 16;

const MAGIC: u32 = u32::from_be_bytes(*b"QomT");

pub struct MtConnectionsMagic;

impl<'de> Deserialize<'de> for MtConnectionsMagic {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: serde::Deserializer<'de>,
  {
    let magic = <[u8; 4]>::deserialize(deserializer)?;

    if magic != MAGIC.to_be_bytes() {
      return Err(serde::de::Error::custom("Bad magic"));
    }

    Ok(MtConnectionsMagic)
  }
}

impl Serialize for MtConnectionsMagic {
  fn serialize<TSerializer>(
    &self,
    serializer: TSerializer,
  ) -> Result<TSerializer::Ok, TSerializer::Error>
  where
    TSerializer: serde::Serializer,
  {
    MAGIC.to_be_bytes().serialize(serializer)
  }
}

#[derive(Serialize, Deserialize)]
pub struct MtConnectionsRequestHead {
  pub magic: MtConnectionsMagic,
  pub data: MtConnectionsRequestHeadData,
}

#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub enum MtConnectionsRequestHeadData {
  Create,
  Extend(MtConnectionsId),
}

#[derive(Serialize, Deserialize)]
pub struct MtConnectionsResponseHead {
  pub magic: MtConnectionsMagic,
  pub data: MtConnectionsResponseHeadData,
}

#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub enum MtConnectionsResponseHeadData {
  Created(MtConnectionsId),
  Extended,
  AlreadyClosed,
}

#[derive(thiserror::Error, Debug)]
pub enum MtConnectionsError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_postcard_serialization() {
    let id = MtConnectionsId::new();

    let request_head_bytes =
      postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
        magic: MtConnectionsMagic,
        data: MtConnectionsRequestHeadData::Create,
      })
      .unwrap();

    let response_head_bytes =
      postcard::to_vec::<_, MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE>(&MtConnectionsResponseHead {
        magic: MtConnectionsMagic,
        data: MtConnectionsResponseHeadData::Created(id),
      })
      .unwrap();

    let request_head =
      postcard::from_bytes::<MtConnectionsRequestHead>(&request_head_bytes).unwrap();
    let response_head =
      postcard::from_bytes::<MtConnectionsResponseHead>(&response_head_bytes).unwrap();

    assert_eq!(request_head.data, MtConnectionsRequestHeadData::Create);
    assert_eq!(
      response_head.data,
      MtConnectionsResponseHeadData::Created(id)
    );
  }
}
