use std::{
  collections::HashMap,
  fmt::Write as _,
  future::Future,
  pin::Pin,
  sync::{
    Arc, Mutex,
    atomic::{self, AtomicBool, AtomicU64, AtomicUsize},
  },
  time::{Duration, Instant},
};

use colored::Colorize;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lits::bytes;
use lowkit::{DropCallback, SelfWrapExt, tokio_join_set};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, duplex},
  sync::{Notify, mpsc, watch},
  task::JoinSet,
  time::{Instant as TokioInstant, MissedTickBehavior, interval_at, sleep, sleep_until},
};

use crate::{
  constants::SERVER_COMMON_NAME,
  mt_connections::MtConnectionsUnderlayMetrics,
  primitives::ConnectionSide,
  quic_connection::{
    MAX_DATAGRAM_SIZE, QUIC_DATAGRAM_QUEUE_CAPACITY, QuicBytesPacket, QuicStream,
    UNSPECIFIED_SOCKET_ADDRESS,
  },
  utils::task::reap_finished_tasks,
};

const READ_WRITE_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

const STREAM_PIPE_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;
const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(5 * 60);
const UNDERLAY_LOSS_DELAY_UPDATE_INTERVAL: Duration = Duration::from_millis(50);
const UNDERLAY_LOSS_DELAY_LOG_INTERVAL: Duration = Duration::from_secs(5);
const UNDERLAY_LOSS_DELAY_QUANTUM: Duration = Duration::from_millis(10);
const UNDERLAY_LOSS_DELAY_LOG_ACK_STALL: Duration = Duration::from_millis(250);
// Packets on the main QomT connection are distributed across independent,
// reliable TCP streams. A path with older queued bytes can be overtaken for
// seconds even while every TCP socket reports a healthy RTT and no
// retransmissions, so TCP_INFO cannot measure the resulting receive-side
// merge delay. Keep time-threshold loss detection beyond the largest
// reordering delay observed in production. PTO remains enabled, and a packet
// lost when a TCP path closes is still recovered after this bounded delay.
const RELIABLE_MULTIPATH_REORDER_DELAY_FLOOR: Duration = Duration::from_secs(5);

// Upper bound for how long the send loop may park after quiche reports
// Done. quiche's own timer can legitimately be far in the future (the
// one-hour idle timeout) or unset, so a missed wakeup would otherwise
// freeze the connection indefinitely. on_timeout() is a no-op when no
// quiche timer is due, making the extra wakeups cheap.
const SEND_DONE_BACKSTOP: Duration = Duration::from_secs(1);

fn shutdown_torn_down_local_stream(
  connection: &mut quiche::Connection,
  side: ConnectionSide,
  id: u64,
) -> Option<quiche::Result<()>> {
  let locally_initiated = (id & 0x1) == u64::from(matches!(side, ConnectionSide::Server));

  locally_initiated.then(|| connection.stream_shutdown(id, quiche::Shutdown::Read, 0))
}

/// A structured snapshot of the active QUIC path metrics used by QomT's
/// packet-path selection. All values come from one `path_stats()` snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicPathMetrics {
  pub rtt: Duration,
  pub min_rtt: Option<Duration>,
  pub rttvar: Duration,
  pub dgram_sent: usize,
  pub dgram_recv: usize,
  pub dgram_lost: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum QuicDatagramSendError {
  #[error("QUIC DATAGRAM is unavailable on this connection")]
  Unavailable,
  #[error("QUIC DATAGRAM is too large: {length} bytes (maximum: {maximum:?})")]
  TooLarge {
    length: usize,
    maximum: Option<usize>,
  },
  #[error("QUIC DATAGRAM send queue is full")]
  QueueFull,
  #[error("QUIC DATAGRAM send failed: {0}")]
  Quiche(quiche::Error),
}

struct StreamSignals {
  recv: Notify,
  send: Notify,
  created: AtomicBool,
  external_dropped: AtomicBool,
  active_tasks: AtomicUsize,
}

impl StreamSignals {
  fn new(created: bool) -> Self {
    Self {
      recv: Notify::new(),
      send: Notify::new(),
      created: AtomicBool::new(created),
      external_dropped: AtomicBool::new(false),
      active_tasks: AtomicUsize::new(2),
    }
  }
}

struct ConnectionSignals {
  connection_send: Notify,
  streams: Mutex<HashMap<u64, Arc<StreamSignals>>>,
  transport_closed: AtomicBool,
  driver_failed: AtomicBool,
  created_at: Instant,
  underlying_send_pending: AtomicBool,
  last_underlying_send_progress_millis: AtomicU64,
  last_underlying_recv_progress_millis: AtomicU64,
  underlay_loss_delay_floor_micros: AtomicU64,
  state_updater: Arc<StateUpdater>,
}

impl ConnectionSignals {
  fn new(state_updater: Arc<StateUpdater>) -> Self {
    Self {
      connection_send: Notify::new(),
      streams: Mutex::new(HashMap::new()),
      transport_closed: AtomicBool::new(false),
      driver_failed: AtomicBool::new(false),
      created_at: Instant::now(),
      underlying_send_pending: AtomicBool::new(false),
      last_underlying_send_progress_millis: AtomicU64::new(0),
      last_underlying_recv_progress_millis: AtomicU64::new(0),
      underlay_loss_delay_floor_micros: AtomicU64::new(0),
      state_updater,
    }
  }

  fn elapsed_millis(&self) -> u64 {
    self.created_at.elapsed().as_millis().min(u64::MAX as u128) as u64
  }

  fn stream_task_finished(&self, id: u64, stream_signals: &Arc<StreamSignals>) {
    if stream_signals
      .active_tasks
      .fetch_sub(1, atomic::Ordering::AcqRel)
      != 1
    {
      return;
    }

    let mut streams = self.streams.lock().unwrap();

    if streams
      .get(&id)
      .is_some_and(|signals| Arc::ptr_eq(signals, stream_signals))
    {
      streams.remove(&id);
    }
  }

  fn mark_transport_closed(&self) {
    if self.transport_closed.swap(true, atomic::Ordering::AcqRel) {
      return;
    }

    self.wake_closed();
  }

  fn mark_driver_failed(&self) {
    if self.driver_failed.swap(true, atomic::Ordering::AcqRel) {
      return;
    }

    self.wake_closed();
  }

  fn wake_closed(&self) {
    self.state_updater.set(State::Closed);
    self.connection_send.notify_one();

    for signals in self.streams.lock().unwrap().values() {
      signals.recv.notify_one();
      signals.send.notify_one();
    }
  }

  fn transport_closed(&self) -> bool {
    self.transport_closed.load(atomic::Ordering::Acquire)
  }

  fn driver_failed(&self) -> bool {
    self.driver_failed.load(atomic::Ordering::Acquire)
  }
}

/// Cloneable connection-level access to QUIC DATAGRAM frames.
///
/// Clones share one bounded receive queue. `recv()` therefore distributes
/// each datagram to exactly one waiting clone, which matches the intended
/// single QomT connection-level router consumer.
#[derive(Clone)]
pub struct QuicDatagramSocket {
  connection: Arc<Mutex<quiche::Connection>>,
  connection_signals: Arc<ConnectionSignals>,
  connection_alive: Arc<AtomicBool>,
  receiver: flume::Receiver<Vec<u8>>,
}

impl QuicDatagramSocket {
  pub fn try_send(&self, datagram: &[u8]) -> Result<(), QuicDatagramSendError> {
    if !self.is_available() {
      return Err(QuicDatagramSendError::Unavailable);
    }

    let (result, maximum) = {
      let mut connection = self.connection.lock().unwrap();
      if !self.connection_alive.load(atomic::Ordering::Acquire)
        || self.connection_signals.state_updater.state() != State::Established
        || self.connection_signals.transport_closed()
        || self.connection_signals.driver_failed()
        || !connection.is_established()
        || connection.is_draining()
        || connection.is_closed()
      {
        return Err(QuicDatagramSendError::Unavailable);
      }
      let maximum = connection.dgram_max_writable_len();

      (connection.dgram_send(datagram), maximum)
    };

    match result {
      Ok(()) => {
        // dgram_send() only queues the frame inside quiche. Wake the driver so
        // latency does not depend on the send loop's one-second backstop.
        self.connection_signals.connection_send.notify_one();
        Ok(())
      }
      Err(quiche::Error::Done) => Err(QuicDatagramSendError::QueueFull),
      Err(quiche::Error::InvalidState) => Err(QuicDatagramSendError::Unavailable),
      Err(quiche::Error::BufferTooShort) => Err(QuicDatagramSendError::TooLarge {
        length: datagram.len(),
        maximum,
      }),
      Err(error) => Err(QuicDatagramSendError::Quiche(error)),
    }
  }

  pub async fn recv(&self) -> Option<Vec<u8>> {
    loop {
      if !self.connection_alive.load(atomic::Ordering::Acquire)
        || self.connection_signals.transport_closed()
        || self.connection_signals.driver_failed()
      {
        return None;
      }

      match self.connection_signals.state_updater.state() {
        State::Initial => {
          if self
            .connection_signals
            .state_updater
            .wait(State::Established)
            .await
            != State::Established
          {
            return None;
          }
        }
        State::Established => {
          return tokio::select! {
            datagram = self.receiver.recv_async() => datagram.ok(),
            _ = self.connection_signals.state_updater.wait(State::Draining) => None,
          };
        }
        State::Draining | State::Closed => return None,
      }
    }
  }

  pub fn max_writable_len(&self) -> Option<usize> {
    if !self.is_available() {
      return None;
    }

    let connection = self.connection.lock().unwrap();
    if !self.connection_alive.load(atomic::Ordering::Acquire)
      || self.connection_signals.state_updater.state() != State::Established
      || self.connection_signals.transport_closed()
      || self.connection_signals.driver_failed()
      || !connection.is_established()
      || connection.is_draining()
      || connection.is_closed()
    {
      return None;
    }

    connection.dgram_max_writable_len()
  }

  pub fn path_metrics(&self) -> Option<QuicPathMetrics> {
    if !self.is_available() {
      return None;
    }

    let connection = self.connection.lock().unwrap();
    if !self.connection_alive.load(atomic::Ordering::Acquire)
      || self.connection_signals.state_updater.state() != State::Established
      || self.connection_signals.transport_closed()
      || self.connection_signals.driver_failed()
      || !connection.is_established()
      || connection.is_draining()
      || connection.is_closed()
    {
      return None;
    }
    let path = connection
      .path_stats()
      .find(|path| path.active)
      .or_else(|| connection.path_stats().next())?;

    Some(QuicPathMetrics {
      rtt: path.rtt,
      min_rtt: path.min_rtt,
      rttvar: path.rttvar,
      dgram_sent: path.dgram_sent,
      dgram_recv: path.dgram_recv,
      dgram_lost: path.dgram_lost,
    })
  }

  fn is_available(&self) -> bool {
    self.connection_alive.load(atomic::Ordering::Acquire)
      && self.connection_signals.state_updater.state() == State::Established
      && !self.connection_signals.transport_closed()
      && !self.connection_signals.driver_failed()
  }
}

fn drain_received_datagrams(
  connection: &mut quiche::Connection,
  sender: &flume::Sender<Vec<u8>>,
  side: ConnectionSide,
) {
  loop {
    let datagram = match connection.dgram_recv_buf() {
      Ok(datagram) => datagram,
      Err(quiche::Error::Done) => break,
      Err(error) => {
        log::warn!("{side}: error receiving QUIC DATAGRAM: {error}");
        break;
      }
    };

    match sender.try_send(datagram) {
      Ok(()) => {}
      Err(flume::TrySendError::Full(_)) => {
        // DATAGRAM delivery is deliberately lossy; never block the underlying
        // QUIC recv driver behind an application consumer.
        log::trace!("{side}: dropping QUIC DATAGRAM because wrapper queue is full");
      }
      Err(flume::TrySendError::Disconnected(_)) => {
        log::trace!("{side}: dropping QUIC DATAGRAM because receiver is gone");
      }
    }
  }
}

fn format_connection_id(id: &quiche::ConnectionId<'_>) -> String {
  let mut formatted = String::with_capacity(12);

  for byte in id.as_ref().iter().take(6) {
    write!(&mut formatted, "{byte:02x}").unwrap();
  }

  formatted
}

fn normalize_stream_send_result(
  result: Result<usize, quiche::Error>,
  empty_fin: bool,
) -> Result<Option<usize>, quiche::Error> {
  match result {
    Ok(length) => Ok(Some(length)),
    // quiche queues a zero-length FIN before returning Done when the
    // connection has send capacity. Retrying would queue nothing new and
    // strand this task forever.
    Err(quiche::Error::Done) if empty_fin => Ok(Some(0)),
    Err(quiche::Error::Done) => Ok(None),
    Err(error) => Err(error),
  }
}

#[cfg(test)]
mod stream_send_result_tests {
  use super::normalize_stream_send_result;

  #[test]
  fn empty_fin_done_is_accepted() {
    assert_eq!(
      normalize_stream_send_result(Err(quiche::Error::Done), true).unwrap(),
      Some(0),
    );
  }

  #[test]
  fn data_done_remains_blocked() {
    assert_eq!(
      normalize_stream_send_result(Err(quiche::Error::Done), false).unwrap(),
      None,
    );
  }
}

fn format_connection_diagnostics(
  connection: &Arc<Mutex<quiche::Connection>>,
  signals: &ConnectionSignals,
  side: ConnectionSide,
  connection_id: &str,
) -> String {
  let (active_streams, uncreated_streams, externally_dropped_streams) = {
    let streams = signals.streams.lock().unwrap();

    (
      streams.len(),
      streams
        .values()
        .filter(|stream| !stream.created.load(atomic::Ordering::Acquire))
        .count(),
      streams
        .values()
        .filter(|stream| stream.external_dropped.load(atomic::Ordering::Acquire))
        .count(),
    )
  };
  let connection_age_millis = signals.elapsed_millis();
  let last_send_progress_millis = signals
    .last_underlying_send_progress_millis
    .load(atomic::Ordering::Acquire);
  let last_recv_progress_millis = signals
    .last_underlying_recv_progress_millis
    .load(atomic::Ordering::Acquire);
  let connection = connection.lock().unwrap();
  let stats = connection.stats();
  let path = connection.path_stats().next().map(|path| {
    format!(
      "rtt_ms={} rttvar_ms={} cwnd={} pto={} delivery_rate={} path_lost={} path_retrans={}",
      path.rtt.as_millis(),
      path.rttvar.as_millis(),
      path.cwnd,
      path.total_pto_count,
      path.delivery_rate,
      path.lost,
      path.retrans
    )
  });

  format!(
    "cid={connection_id} side={side} state={:?} age_ms={connection_age_millis} \
     streams={active_streams} uncreated_streams={uncreated_streams} \
     externally_dropped_streams={externally_dropped_streams} \
     underlying_send_pending={} underlying_send_idle_ms={} underlying_recv_idle_ms={} \
     underlay_loss_floor_ms={} \
     quic_sent_packets={} quic_recv_packets={} quic_sent_bytes={} quic_recv_bytes={} \
     quic_acked_bytes={} quic_lost_packets={} quic_spurious_lost_packets={} \
     quic_lost_bytes={} quic_retrans_packets={} quic_stream_retrans_bytes={} \
     data_blocked_sent={} data_blocked_recv={} \
     stream_data_blocked_sent={} stream_data_blocked_recv={} \
     streams_blocked_bidi_recv={} reset_local={} reset_remote={} stopped_local={} \
     stopped_remote={} tx_buffered={:?} path=[{}] transport_closed={} driver_failed={}",
    signals.state_updater.state(),
    signals
      .underlying_send_pending
      .load(atomic::Ordering::Acquire),
    connection_age_millis.saturating_sub(last_send_progress_millis),
    connection_age_millis.saturating_sub(last_recv_progress_millis),
    signals
      .underlay_loss_delay_floor_micros
      .load(atomic::Ordering::Acquire)
      / 1000,
    stats.sent,
    stats.recv,
    stats.sent_bytes,
    stats.recv_bytes,
    stats.acked_bytes,
    stats.lost,
    stats.spurious_lost,
    stats.lost_bytes,
    stats.retrans,
    stats.stream_retrans_bytes,
    stats.data_blocked_sent_count,
    stats.data_blocked_recv_count,
    stats.stream_data_blocked_sent_count,
    stats.stream_data_blocked_recv_count,
    stats.streams_blocked_bidi_recv_count,
    stats.reset_stream_count_local,
    stats.reset_stream_count_remote,
    stats.stopped_stream_count_local,
    stats.stopped_stream_count_remote,
    stats.tx_buffered_state,
    path.unwrap_or_else(|| "none".to_owned()),
    signals.transport_closed(),
    signals.driver_failed(),
  )
}

pub struct QuicConnection {
  connection: Arc<Mutex<quiche::Connection>>,
  id: quiche::ConnectionId<'static>,
  next_stream_id_index: AtomicU64,
  side: ConnectionSide,
  state_updater: Arc<StateUpdater>,
  connection_signals: Arc<ConnectionSignals>,
  create_stream: Arc<dyn Fn(ConnectionSide, u64) -> QuicStream + Send + Sync>,
  stream_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<QuicStream>>,
  datagram_socket: QuicDatagramSocket,
  _join_set: JoinSet<()>,
}

impl QuicConnection {
  pub(crate) fn attach_reliable_underlay_metrics(
    &mut self,
    metrics: Arc<MtConnectionsUnderlayMetrics>,
  ) {
    let connection = self.connection.clone();
    let connection_signals = self.connection_signals.clone();
    let diagnostic_id = self.diagnostic_id();
    let side = self.side;

    self._join_set.spawn(async move {
      let mut interval = interval_at(TokioInstant::now(), UNDERLAY_LOSS_DELAY_UPDATE_INTERVAL);
      interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
      let quantum_micros = UNDERLAY_LOSS_DELAY_QUANTUM.as_micros() as u64;
      let mut applied_floor = Duration::ZERO;
      let mut last_log = Instant::now()
        .checked_sub(UNDERLAY_LOSS_DELAY_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);

      loop {
        interval.tick().await;
        let snapshot = metrics.snapshot();
        let loss_delay_floor = if snapshot.paths > 1 {
          snapshot
            .loss_delay_floor
            .max(RELIABLE_MULTIPATH_REORDER_DELAY_FLOOR)
        } else {
          snapshot.loss_delay_floor
        };
        let floor_micros = loss_delay_floor.as_micros().min(u64::MAX as u128) as u64;
        let quantized_micros = floor_micros.saturating_add(quantum_micros.saturating_sub(1))
          / quantum_micros
          * quantum_micros;
        let floor = Duration::from_micros(quantized_micros);

        let (quic_rtt, floor_changed) = {
          let mut connection = connection.lock().unwrap();
          let floor_changed = floor != applied_floor;
          if floor_changed {
            connection.set_loss_detection_delay_floor(floor);
            applied_floor = floor;
          }
          (
            connection
              .path_stats()
              .find(|path| path.active)
              .map(|path| path.rtt),
            floor_changed,
          )
        };

        connection_signals
          .underlay_loss_delay_floor_micros
          .store(quantized_micros, atomic::Ordering::Release);

        if floor_changed {
          connection_signals.connection_send.notify_one();
        }

        let now_guard_active = snapshot.quorum_ack_stall >= UNDERLAY_LOSS_DELAY_LOG_ACK_STALL
          && quic_rtt.is_some_and(|rtt| floor > rtt.saturating_mul(2));
        if now_guard_active && last_log.elapsed() >= UNDERLAY_LOSS_DELAY_LOG_INTERVAL {
          log::info!(
            "QomT TCP loss guard active: cid={diagnostic_id} side={side} \
             quic_rtt_ms={} tcp_info=[{snapshot}]",
            quic_rtt.unwrap_or_default().as_millis(),
          );
          last_log = Instant::now();
        }
      }
    });
  }

  pub fn connect<TStream>(
    connection_id: &quiche::ConnectionId<'static>,
    quiche_config: &mut quiche::Config,
    underlying_stream: TStream,
  ) -> Self
  where
    TStream: Sink<QuicBytesPacket> + Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
    TStream::Error: std::fmt::Display,
  {
    let (underlying_sink, underlying_stream) = underlying_stream.split();

    Self::connect_with_sink_and_stream(
      connection_id,
      quiche_config,
      underlying_sink,
      underlying_stream,
    )
  }

  pub fn connect_with_sink_and_stream<TSink, TStream>(
    connection_id: &quiche::ConnectionId<'static>,
    quiche_config: &mut quiche::Config,
    underlying_sink: TSink,
    underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<QuicBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
  {
    let connection = quiche::connect(
      SERVER_COMMON_NAME.some(),
      connection_id,
      *UNSPECIFIED_SOCKET_ADDRESS,
      *UNSPECIFIED_SOCKET_ADDRESS,
      quiche_config,
    )
    .unwrap_or_else(|error| panic!("failed to connect to quiche connection: {}", error));

    Self::create(
      connection,
      connection_id.clone(),
      ConnectionSide::Client,
      None,
      underlying_sink,
      underlying_stream,
    )
  }

  pub fn accept<TStream>(
    connection_id: &quiche::ConnectionId<'static>,
    quiche_config: &mut quiche::Config,
    underlying_stream: TStream,
  ) -> Self
  where
    TStream: Sink<QuicBytesPacket> + Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
    TStream::Error: std::fmt::Display,
  {
    let (underlying_sink, underlying_stream) = underlying_stream.split();

    Self::accept_with_sink_and_stream(
      connection_id,
      quiche_config,
      underlying_sink,
      underlying_stream,
    )
  }

  pub fn accept_with_sink_and_stream<TSink, TStream>(
    connection_id: &quiche::ConnectionId<'static>,
    quiche_config: &mut quiche::Config,
    underlying_sink: TSink,
    underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<QuicBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
  {
    Self::accept_with_optional_first_packet_and_sink_and_stream(
      connection_id,
      quiche_config,
      None,
      underlying_sink,
      underlying_stream,
    )
  }

  /// 同 [`accept`]，但预置一个已从底层流读出的包
  /// （如应用层为解析连接 ID 而读走的首包），recv 循环先处理它再继续。
  pub fn accept_with_first_packet<TStream>(
    connection_id: &quiche::ConnectionId<'static>,
    quiche_config: &mut quiche::Config,
    first_packet: QuicBytesPacket,
    underlying_stream: TStream,
  ) -> Self
  where
    TStream: Sink<QuicBytesPacket> + Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
    TStream::Error: std::fmt::Display,
  {
    let (underlying_sink, underlying_stream) = underlying_stream.split();

    Self::accept_with_optional_first_packet_and_sink_and_stream(
      connection_id,
      quiche_config,
      Some(first_packet),
      underlying_sink,
      underlying_stream,
    )
  }

  fn accept_with_optional_first_packet_and_sink_and_stream<TSink, TStream>(
    connection_id: &quiche::ConnectionId<'static>,
    quiche_config: &mut quiche::Config,
    first_packet: Option<QuicBytesPacket>,
    underlying_sink: TSink,
    underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<QuicBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
  {
    let connection = quiche::accept(
      connection_id,
      None,
      *UNSPECIFIED_SOCKET_ADDRESS,
      *UNSPECIFIED_SOCKET_ADDRESS,
      quiche_config,
    )
    .unwrap_or_else(|error| panic!("failed to accept quiche connection: {}", error));

    Self::create(
      connection,
      connection_id.clone(),
      ConnectionSide::Server,
      first_packet,
      underlying_sink,
      underlying_stream,
    )
  }

  fn create<TSink, TStream>(
    connection: quiche::Connection,
    id: quiche::ConnectionId<'static>,
    side: ConnectionSide,
    first_packet: Option<QuicBytesPacket>,
    mut underlying_sink: TSink,
    mut underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<QuicBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = QuicBytesPacket> + Unpin + Send + 'static,
  {
    let connection = connection.mutex().arc();
    let state_updater = StateUpdater::new(side).arc();
    let connection_signals = ConnectionSignals::new(state_updater.clone()).arc();
    let diagnostic_connection_id = format_connection_id(&id);

    let (stream_sender, stream_receiver) = mpsc::unbounded_channel();
    let (datagram_sender, datagram_receiver) = flume::bounded(QUIC_DATAGRAM_QUEUE_CAPACITY);
    let connection_alive = Arc::new(AtomicBool::new(true));
    let datagram_socket = QuicDatagramSocket {
      connection: connection.clone(),
      connection_signals: connection_signals.clone(),
      connection_alive,
      receiver: datagram_receiver,
    };

    let create_stream = {
      let connection = connection.clone();
      let connection_signals = connection_signals.clone();
      let join_set = JoinSet::new().mutex().arc();

      move |side: ConnectionSide, id: u64| {
        log::debug!("{side} {id}: quic stream create");

        // Duplex ends close both directions on drop, so a dead stream task
        // fails the external writer (BrokenPipe) and reader (EOF) instead
        // of leaving them blocked on the in-memory pipe forever.
        let (external_read, mut write) = duplex(STREAM_PIPE_BUFFER_SIZE);
        let (mut read, external_write) = duplex(STREAM_PIPE_BUFFER_SIZE);

        let stream_signals = StreamSignals::new(side == ConnectionSide::Server).arc();

        assert!(
          connection_signals
            .streams
            .lock()
            .unwrap()
            .insert(id, stream_signals.clone())
            .is_none()
        );

        let mut join_set = join_set.lock().unwrap();
        reap_finished_tasks(&mut join_set, "QUIC stream task");

        // stream send loop
        join_set.spawn({
          let connection = connection.clone();
          let connection_signals = connection_signals.clone();
          let stream_signals = stream_signals.clone();

          async move {
            let mut buffer = [0; READ_WRITE_BUFFER_SIZE];

            'outer: loop {
              // When the external writer is dropped, the duplex pipe
              // delivers any buffered bytes and then EOF, so this read
              // alone drives the drain-then-FIN shutdown.
              let read_result = tokio::select! {
                result = read.read(&mut buffer) => result,
                _ = connection_signals.state_updater.wait(State::Closed) => break,
              };

              match read_result {
                Ok(total_length) => {
                  log::trace!("{side} {id}: stream send read {total_length} bytes");

                  let mut offset = 0;

                  loop {
                    log::trace!("{side} {id}: stream send {offset}..{total_length}");

                    let empty_fin = total_length == 0;
                    let stream_send_result = normalize_stream_send_result(
                      connection.lock().unwrap().stream_send(
                        id,
                        &buffer[offset..total_length],
                        empty_fin,
                      ),
                      empty_fin,
                    );

                    match stream_send_result {
                      Ok(Some(length)) => {
                        stream_signals
                          .created
                          .store(true, atomic::Ordering::Release);
                        stream_signals.recv.notify_one();
                        connection_signals.connection_send.notify_one();

                        offset += length;

                        log::trace!(
                          "{side} {id}: {stream_send} {offset}/{total_length}",
                          stream_send = "stream send".on_green(),
                        );

                        if offset == total_length {
                          break;
                        }
                      }
                      Ok(None) => {
                        log::trace!("{side} {id}: stream send done");

                        // If the stream was collected or stopped while we
                        // were blocked on flow control, stream_send will
                        // return Done forever. Detect that terminal state
                        // and give up instead of retrying pointlessly.
                        let terminal = matches!(
                          connection.lock().unwrap().stream_capacity(id),
                          Err(quiche::Error::InvalidStreamState(_))
                            | Err(quiche::Error::StreamStopped(_))
                        );
                        if terminal {
                          log::debug!("{side} {id}: stream gone while blocked; abandoning send");
                          break 'outer;
                        }

                        // Beyond the notification-driven wakeup, re-arm on a
                        // timer: the writable dispatch is packet-driven and
                        // quiche's send capacity snapshot can go stale once
                        // packets stop entirely, so a parked task would
                        // otherwise never observe that the stream was
                        // stopped or that capacity returned.
                        tokio::select! {
                          _ = stream_signals.send.notified() => {}
                          _ = sleep(Duration::from_secs(1)) => {}
                          _ = connection_signals.state_updater.wait(State::Closed) => {
                            break 'outer;
                          }
                        }
                      }
                      Err(error) => {
                        log::warn!("error writing to quic stream: {error}");
                        break 'outer;
                      }
                    }
                  }

                  if total_length == 0 {
                    log::debug!("{side} {id}: stream FIN sent");
                    break;
                  }
                }
                Err(error) => {
                  log::warn!("error reading from quic stream: {error}");

                  connection
                    .lock()
                    .unwrap()
                    .stream_shutdown(id, quiche::Shutdown::Write, 0)
                    .inspect_err(|error| {
                      log::warn!("error aborting quic stream write side: {error}")
                    })
                    .ok();

                  connection_signals.connection_send.notify_one();
                  break;
                }
              }
            }

            // The recv task waits for the send side to settle before it
            // touches quiche for this stream (e.g. to shut down a dropped
            // stream). Always mark it settled and wake the recv task, even
            // when the send loop failed, so an early error cannot strand it.
            stream_signals
              .created
              .store(true, atomic::Ordering::Release);
            stream_signals.recv.notify_one();

            connection_signals.stream_task_finished(id, &stream_signals);
            log::debug!("{side} {id}: stream send loop ended");
          }
        });

        // stream recv loop
        join_set.spawn({
          let connection = connection.clone();
          let connection_signals = connection_signals.clone();
          let stream_signals = stream_signals.clone();

          async move {
            let mut buffer = vec![0; READ_WRITE_BUFFER_SIZE];

            loop {
              // Wait until the send task has settled and quiche knows the
              // stream before acting on an external drop. Shutting down
              // before the first stream_send() creates the stream fails
              // with Error::Done and would silently lose the STOP_SENDING,
              // leaving the peer free to stream into a dead stream until
              // flow control wedges the whole connection.
              if !stream_signals.created.load(atomic::Ordering::Acquire) {
                tokio::select! {
                  _ = stream_signals.recv.notified() => continue,
                  _ = connection_signals.state_updater.wait(State::Closed) => break,
                }
              }

              if stream_signals
                .external_dropped
                .load(atomic::Ordering::Acquire)
              {
                connection
                  .lock()
                  .unwrap()
                  .stream_shutdown(id, quiche::Shutdown::Read, 0)
                  .inspect_err(|error| {
                    if !matches!(error, quiche::Error::Done) {
                      log::warn!("error stopping quic stream read side: {error}");
                    }
                  })
                  .ok();

                connection_signals.connection_send.notify_one();
                break;
              }

              let stream_recv_result = {
                log::trace!(
                  "{side} {id}: {stream_recv}",
                  stream_recv = "stream recv".on_red()
                );

                let mut connection = connection.lock().unwrap();

                connection.stream_recv(id, &mut buffer)
              };

              match stream_recv_result {
                Ok((length, finished)) => {
                  connection_signals.connection_send.notify_one();

                  log::trace!("{side} {id}: stream recv {length} {finished}");

                  if length > 0 {
                    let write_result = tokio::select! {
                      result = write.write_all(&buffer[..length]) => result,
                      _ = connection_signals.state_updater.wait(State::Closed) => break,
                    };

                    if let Err(error) = write_result {
                      log::warn!("error writing packet to stream: {error}");

                      connection
                        .lock()
                        .unwrap()
                        .stream_shutdown(id, quiche::Shutdown::Read, 0)
                        .ok();
                      connection_signals.connection_send.notify_one();
                      break;
                    }
                  }

                  if finished {
                    log::debug!("{side} {id}: stream FIN received");
                    break;
                  }
                }
                Err(error) => {
                  // A fully closed bidirectional stream can be collected by
                  // quiche while processing ACK/FIN state. In that case
                  // stream_recv() can no longer consume a FIN, but
                  // stream_finished() intentionally remains true.
                  if connection.lock().unwrap().stream_finished(id) {
                    log::debug!("{side} {id}: stream observed finished");
                    break;
                  }

                  if matches!(error, quiche::Error::Done) {
                    log::trace!("{side} {id}: stream recv done");

                    tokio::select! {
                      _ = stream_signals.recv.notified() => {}
                      _ = connection_signals.state_updater.wait(State::Closed) => break,
                    }
                  } else {
                    log::warn!("error receiving packet from quiche stream: {}", error);
                    break;
                  }
                }
              }
            }

            write
              .shutdown()
              .await
              .inspect_err(|error| {
                log::warn!("error shutting down stream: {}", error);
              })
              .ok();

            connection_signals.stream_task_finished(id, &stream_signals);
            log::debug!("{side} {id}: stream recv loop ended");
          }
        });

        let drop_callback = DropCallback::new({
          let stream_signals = stream_signals.clone();

          Box::new(move || {
            log::debug!("{side} {id}: external stream dropped");
            stream_signals
              .external_dropped
              .store(true, atomic::Ordering::Release);
            stream_signals.recv.notify_one();
            stream_signals.send.notify_one();
          }) as Box<dyn Fn() + Send>
        });

        QuicStream::new(side, id, external_read, external_write, drop_callback)
      }
    }
    .arc();

    Self {
      connection: connection.clone(),
      id,
      side,
      state_updater: state_updater.clone(),
      connection_signals: connection_signals.clone(),
      create_stream: create_stream.clone(),
      next_stream_id_index: AtomicU64::new(0),
      stream_receiver: stream_receiver.tokio_mutex(),
      datagram_socket,
      _join_set: {
        let send_loop = {
          let connection = connection.clone();
          let connection_signals = connection_signals.clone();
          let state_updater = state_updater.clone();

          async move {
            let mut buffer = [0; MAX_DATAGRAM_SIZE];

            let mut packet_count = 0;
            let mut byte_count = 0;

            loop {
              log::trace!("{side} {send}", send = "send".green());

              let send_result = {
                let mut connection = connection.lock().unwrap();

                let result = connection.send(&mut buffer);

                state_updater.update(&connection);

                result
              };

              match send_result {
                Ok((length, send_info)) => {
                  packet_count += 1;
                  byte_count += length;

                  log::trace!("{side} send {packet_count} packets, {byte_count} bytes");

                  tokio::select! {
                    _ = sleep_until(send_info.at.into()) => {}
                    _ = state_updater.wait(State::Closed) => break,
                  }

                  connection_signals
                    .underlying_send_pending
                    .store(true, atomic::Ordering::Release);

                  let send_result = tokio::select! {
                    result = underlying_sink.send(buffer[..length].to_vec().into()) => Some(result),
                    _ = state_updater.wait(State::Closed) => None,
                  };

                  connection_signals
                    .underlying_send_pending
                    .store(false, atomic::Ordering::Release);

                  match send_result {
                    Some(Ok(())) => {
                      connection_signals
                        .last_underlying_send_progress_millis
                        .store(
                          connection_signals.elapsed_millis(),
                          atomic::Ordering::Release,
                        );
                    }
                    Some(Err(error)) => {
                      log::warn!("error sending packet to underlying sink: {error}");
                      connection_signals.mark_transport_closed();
                      break;
                    }
                    None => break,
                  }
                }
                Err(quiche::Error::Done) => {
                  log::trace!("{side} send done");

                  let timeout_instant = connection.lock().unwrap().timeout_instant();

                  let backstop = TokioInstant::now() + SEND_DONE_BACKSTOP;

                  let deadline = timeout_instant
                    .map(Into::into)
                    .unwrap_or(backstop)
                    .min(backstop);

                  tokio::select! {
                    _ = connection_signals.connection_send.notified() => {}
                    _ = sleep_until(deadline) => {
                      let mut connection = connection.lock().unwrap();
                      connection.on_timeout();
                      state_updater.update(&connection);
                    }
                    _ = state_updater.wait(State::Closed) => break,
                  }
                }
                Err(error) => {
                  log::warn!("error sending packet to quiche connection: {error}");
                  connection_signals.mark_driver_failed();
                  break;
                }
              }
            }

            log::debug!("{side} send loop ended");
          }
        };

        let recv_loop = {
          let connection = connection.clone();
          let connection_signals = connection_signals.clone();
          let state_updater = state_updater.clone();

          async move {
            let receive_info: quiche::RecvInfo = quiche::RecvInfo {
              from: *UNSPECIFIED_SOCKET_ADDRESS,
              to: *UNSPECIFIED_SOCKET_ADDRESS,
            };

            let mut packet_count = 0;
            let mut byte_count = 0;

            // 预置首包（应用层为解析连接 ID 读走的包）先处理，再进入循环。
            let mut pending_first_packet = first_packet;

            'recv_loop: loop {
              let mut packet = if let Some(first_packet) = pending_first_packet.take() {
                first_packet
              } else {
                tokio::select! {
                  packet = underlying_stream.next() => {
                    let Some(packet) = packet else {
                      connection_signals.mark_transport_closed();
                      break;
                    };

                    packet
                  }
                  _ = state_updater.wait(State::Closed) => break,
                }
              };

              packet_count += 1;
              byte_count += packet.len();
              connection_signals
                .last_underlying_recv_progress_millis
                .store(
                  connection_signals.elapsed_millis(),
                  atomic::Ordering::Release,
                );

              log::trace!("{side} underlying read {packet_count} packets, {byte_count} bytes");

              let recv_result = {
                log::trace!("{side} {} {}", "recv".red(), packet.len());

                let mut connection = connection.lock().unwrap();

                let result = connection.recv(&mut packet, receive_info);

                state_updater.update(&connection);
                drain_received_datagrams(&mut connection, &datagram_sender, side);

                result
              };

              connection_signals.connection_send.notify_one();

              // Reconcile terminal stream state after every driver step, even
              // when quiche reports Done for the packet. A stream can have
              // been collected while processing ACK/FIN state and therefore
              // no longer be present in readable().
              let active_stream_ids = connection_signals
                .streams
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(&id, signals)| {
                  signals
                    .created
                    .load(atomic::Ordering::Acquire)
                    .then_some(id)
                })
                .collect::<Vec<_>>();

              let finished = {
                let connection = connection.lock().unwrap();

                active_stream_ids
                  .into_iter()
                  .filter(|&id| connection.stream_finished(id))
                  .collect::<Vec<_>>()
              };

              for id in finished {
                if let Some(signals) = connection_signals.streams.lock().unwrap().get(&id).cloned()
                {
                  signals.recv.notify_one();
                }
              }

              match recv_result {
                Ok(_) => {
                  // Source code suggests that recv always return the length of the packet if Ok.

                  log::trace!("{side} recv ok");

                  let (readable, writable) = {
                    let connection = connection.lock().unwrap();

                    (
                      connection.readable().collect::<Vec<_>>(),
                      connection.writable().collect::<Vec<_>>(),
                    )
                  };

                  for id in writable {
                    if let Some(signals) =
                      connection_signals.streams.lock().unwrap().get(&id).cloned()
                    {
                      signals.send.notify_one();
                    }
                  }

                  for id in readable {
                    log::trace!("{side} {id}: stream recv readable");

                    if let Some(signals) =
                      connection_signals.streams.lock().unwrap().get(&id).cloned()
                    {
                      signals.recv.notify_one();
                    } else {
                      // Only a peer-initiated stream can legitimately be
                      // unknown to us. A locally-initiated id missing from
                      // the map is a leftover of a torn-down stream (RFC
                      // 9000 §2.1: bit 0x1 marks the initiator);
                      // re-creating it would spawn a ghost stream that
                      // nobody consumes and that never gets reaped.
                      if let Some(shutdown_result) = {
                        let mut connection = connection.lock().unwrap();

                        shutdown_torn_down_local_stream(&mut connection, side, id)
                      } {
                        match shutdown_result {
                          Ok(()) => {
                            log::debug!(
                              "{side} {id}: discarded readable for torn-down local stream"
                            );
                            connection_signals.connection_send.notify_one();
                          }
                          Err(quiche::Error::Done) => {
                            log::trace!("{side} {id}: torn-down local stream already gone");
                          }
                          Err(error) => {
                            log::warn!(
                              "{side} {id}: error discarding torn-down local stream: {error}"
                            );
                          }
                        }

                        continue;
                      }

                      let stream = create_stream(ConnectionSide::Server, id);

                      if stream_sender
                        .send(stream)
                        .inspect_err(|error| {
                          log::warn!("error sending stream to stream sender: {}", error)
                        })
                        .is_err()
                      {
                        break 'recv_loop;
                      }
                    };
                  }
                }
                Err(quiche::Error::Done) => continue 'recv_loop,
                Err(error) => {
                  log::warn!("error receiving packet from quiche connection: {}", error);
                  continue 'recv_loop;
                }
              }
            }

            log::debug!("{side} recv loop ended");
          }
        };

        let finished_stream_reconciliation_loop = {
          let connection = connection.clone();
          let connection_signals = connection_signals.clone();
          let state_updater = state_updater.clone();

          async move {
            loop {
              tokio::select! {
                _ = sleep(Duration::from_millis(100)) => {}
                _ = state_updater.wait(State::Closed) => break,
              }

              let active_stream_ids = connection_signals
                .streams
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(&id, signals)| {
                  signals
                    .created
                    .load(atomic::Ordering::Acquire)
                    .then_some(id)
                })
                .collect::<Vec<_>>();

              let finished = {
                let connection = connection.lock().unwrap();

                active_stream_ids
                  .into_iter()
                  .filter(|&id| connection.stream_finished(id))
                  .collect::<Vec<_>>()
              };

              for id in finished {
                if let Some(signals) = connection_signals.streams.lock().unwrap().get(&id).cloned()
                {
                  signals.recv.notify_one();
                }
              }
            }
          }
        };

        let diagnostics_loop = {
          let connection = connection.clone();
          let connection_signals = connection_signals.clone();
          let state_updater = state_updater.clone();

          async move {
            let mut interval = interval_at(
              TokioInstant::now() + DIAGNOSTIC_INTERVAL,
              DIAGNOSTIC_INTERVAL,
            );
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
              tokio::select! {
                _ = interval.tick() => {
                  log::debug!(
                    "QOMT diagnostic: {}",
                    format_connection_diagnostics(
                      &connection,
                      &connection_signals,
                      side,
                      &diagnostic_connection_id,
                    )
                  );
                }
                _ = state_updater.wait(State::Closed) => break,
              }
            }
          }
        };

        tokio_join_set!(
          send_loop,
          recv_loop,
          finished_stream_reconciliation_loop,
          diagnostics_loop
        )
      },
    }
  }

  pub fn generate_connection_id() -> quiche::ConnectionId<'static> {
    quiche::ConnectionId::from_vec(rand::random::<[u8; quiche::MAX_CONN_ID_LEN]>().to_vec())
  }

  pub fn state(&self) -> State {
    self.state_updater.state()
  }

  pub fn id(&self) -> &quiche::ConnectionId<'static> {
    &self.id
  }

  pub fn diagnostic_id(&self) -> String {
    format_connection_id(&self.id)
  }

  pub fn diagnostics(&self) -> String {
    format_connection_diagnostics(
      &self.connection,
      &self.connection_signals,
      self.side,
      &self.diagnostic_id(),
    )
  }

  pub fn datagram_socket(&self) -> QuicDatagramSocket {
    self.datagram_socket.clone()
  }

  /// Ask quiche to emit an ack-eliciting packet on the active path.
  ///
  /// quiche turns this into a PING only when the next packet would otherwise
  /// contain no ack-eliciting frame. This is used by the UDP QomT branch as a
  /// transport-native keepalive: if the peer stops acknowledging packets,
  /// quiche's idle timer is what eventually moves the connection to a
  /// terminal state.
  pub fn send_ack_eliciting(&self) -> quiche::Result<()> {
    if self.state_updater.state() != State::Established
      || self.connection_signals.transport_closed()
      || self.connection_signals.driver_failed()
    {
      return Err(quiche::Error::InvalidState);
    }

    self.connection.lock().unwrap().send_ack_eliciting()?;
    self.connection_signals.connection_send.notify_one();

    Ok(())
  }

  /// Wait until quiche has fully classified the connection as closed.
  pub async fn wait_closed(&self) {
    self.state_updater.wait(State::Closed).await;
  }

  /// An owned close signal for tasks whose lifetime must be bounded by this
  /// QUIC connection without retaining the [`QuicConnection`] owner itself.
  pub(crate) fn closed_future(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
    let state_updater = self.state_updater.clone();

    Box::pin(async move {
      state_updater.wait(State::Closed).await;
    })
  }

  pub async fn accept_stream(&self) -> Result<Option<QuicStream>, QuicConnectionError> {
    let mut stream_receiver = self.stream_receiver.lock().await;

    tokio::select! {
      stream = stream_receiver.recv() => stream.map_or_else(
        || self.build_connection_result(None),
        |stream| Ok(Some(stream)),
      ),
      _ = self.state_updater.wait(State::Closed) => self.build_connection_result(None),
    }
  }

  pub fn open_stream(&self) -> QuicStream {
    let stream_id_index = self
      .next_stream_id_index
      .fetch_add(1, atomic::Ordering::Relaxed);

    let stream_id = stream_id_index << 2 | self.side.stream_id_bits();

    (self.create_stream)(ConnectionSide::Client, stream_id)
  }

  pub async fn established(&self) -> Result<(), QuicConnectionError> {
    self.state_updater.wait(State::Established).await;

    self.build_connection_result(())
  }

  fn build_connection_result<TOk>(&self, ok: TOk) -> Result<TOk, QuicConnectionError> {
    let connection = self.connection.lock().unwrap();

    let quiche_error = connection
      .local_error()
      .map(|error| QuicConnectionError::QuicheConnectionLocal(error.clone()))
      .or_else(|| {
        connection
          .peer_error()
          .map(|error| QuicConnectionError::QuicheConnectionPeer(error.clone()))
      });

    drop(connection);

    if let Some(error) = quiche_error {
      Err(error)
    } else if self.connection_signals.driver_failed() {
      Err(QuicConnectionError::DriverFailed)
    } else if self.connection_signals.transport_closed() {
      Err(QuicConnectionError::UnderlyingTransportClosed)
    } else {
      Ok(ok)
    }
  }
}

impl Drop for QuicConnection {
  fn drop(&mut self) {
    // Close the owner gate before joining any in-flight DATAGRAM operation,
    // so new socket calls cannot keep joining the mutex waiters while Drop is
    // trying to quiesce the connection.
    self
      .datagram_socket
      .connection_alive
      .store(false, atomic::Ordering::Release);
    let _connection = self
      .connection
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    self.state_updater.set(State::Closed);
  }
}

impl ConnectionSide {
  pub fn stream_id_bits(&self) -> u64 {
    match self {
      ConnectionSide::Client => 0b00,
      ConnectionSide::Server => 0b01,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum State {
  Initial,
  Established,
  Draining,
  Closed,
}

struct StateUpdater {
  side: ConnectionSide,
  state: watch::Sender<State>,
}

impl StateUpdater {
  fn new(side: ConnectionSide) -> Self {
    let (state, _) = watch::channel(State::Initial);

    StateUpdater { side, state }
  }

  fn state(&self) -> State {
    *self.state.borrow()
  }

  fn update(&self, connection: &quiche::Connection) -> State {
    let new_state = if connection.is_closed() {
      State::Closed
    } else if connection.is_draining() {
      State::Draining
    } else if connection.is_established() {
      State::Established
    } else {
      State::Initial
    };

    self.set(new_state)
  }

  fn set(&self, new_state: State) -> State {
    let mut result = new_state;

    self.state.send_if_modified(|state| {
      if *state >= new_state {
        result = *state;
        false
      } else {
        log::debug!("{} new state: {new_state:?}", self.side);
        *state = new_state;
        true
      }
    });

    result
  }

  async fn wait(&self, target_state: State) -> State {
    let mut state_receiver = self.state.subscribe();

    loop {
      let state = *state_receiver.borrow_and_update();

      if state >= target_state {
        return state;
      }

      if state_receiver.changed().await.is_err() {
        return state;
      }
    }
  }
}

#[derive(thiserror::Error, Debug)]
pub enum QuicConnectionError {
  #[error("Quiche connection local error: {0:?}")]
  QuicheConnectionLocal(quiche::ConnectionError),
  #[error("Quiche connection peer error: {0:?}")]
  QuicheConnectionPeer(quiche::ConnectionError),
  #[error("QUIC connection driver stopped after an unrecoverable quiche error")]
  DriverFailed,
  #[error("Underlying packet transport closed")]
  UnderlyingTransportClosed,
}

#[cfg(test)]
mod unit_tests {
  use tokio::time::timeout;

  use super::*;
  use crate::quic_connection::tests::get_quiche_configs;

  #[tokio::test(flavor = "multi_thread")]
  async fn torn_down_local_stream_shutdown_clears_readable_state() -> anyhow::Result<()> {
    timeout(Duration::from_secs(5), async {
      let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

      let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
        flume::bounded::<QuicBytesPacket>(0);
      let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
        flume::bounded::<QuicBytesPacket>(0);

      let connection_id = QuicConnection::generate_connection_id();
      let out_connection = QuicConnection::connect_with_sink_and_stream(
        &connection_id,
        &mut out_quiche_config,
        out_to_hub_packet_sender.into_sink(),
        hub_to_out_packet_receiver.into_stream(),
      );
      let hub_connection = QuicConnection::accept_with_sink_and_stream(
        out_connection.id(),
        &mut hub_quiche_config,
        hub_to_out_packet_sender.into_sink(),
        out_to_hub_packet_receiver.into_stream(),
      );

      tokio::try_join!(out_connection.established(), hub_connection.established())?;

      let mut out_stream = out_connection.open_stream();
      out_stream.write_all(b"request").await?;

      let mut hub_stream = hub_connection
        .accept_stream()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing request stream"))?;
      let mut request = [0; 7];
      hub_stream.read_exact(&mut request).await?;
      assert_eq!(&request, b"request");

      // Leave the external reader idle so its 8 KiB pipe fills and quiche
      // retains additional response bytes in the readable set.
      hub_stream.write_all(&vec![0xa5; 64 * 1024]).await?;

      timeout(Duration::from_secs(2), async {
        loop {
          if out_connection.connection.lock().unwrap().stream_readable(0) {
            break;
          }

          sleep(Duration::from_millis(10)).await;
        }
      })
      .await?;

      let shutdown_result = shutdown_torn_down_local_stream(
        &mut out_connection.connection.lock().unwrap(),
        ConnectionSide::Client,
        0,
      );

      assert!(matches!(shutdown_result, Some(Ok(()))));
      assert!(!out_connection.connection.lock().unwrap().stream_readable(0));

      out_connection
        .connection_signals
        .connection_send
        .notify_one();
      drop(out_stream);
      drop(hub_stream);

      anyhow::Ok(())
    })
    .await?
  }
}
