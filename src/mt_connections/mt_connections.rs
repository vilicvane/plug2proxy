use std::{
  cmp::Reverse,
  collections::{HashMap, VecDeque},
  fmt,
  net::SocketAddr,
  pin::Pin,
  sync::{
    Arc, Mutex,
    atomic::{self, AtomicU64, AtomicUsize},
  },
  task::{Context, Poll},
  time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use futures::{Sink, Stream};
use lowkit::{DropCallback, SelfWrapExt, TurnArcWeak, tokio_join_set};
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use tokio::{
  io::{AsyncRead, AsyncWrite, AsyncWriteExt},
  net::TcpStream,
  sync::{Notify, mpsc, watch},
  task::JoinSet,
  time::{Instant as TokioInstant, MissedTickBehavior, interval_at, sleep_until, timeout},
};
use uuid::{Uuid, serde::compact};

use super::{
  interface::{TokenBucket, has_pair_budget, pair_next_ready, refund_pair, try_take_pair},
  mt_connections_listener::MtListenerSessionHandle,
  mt_connections_side_udp::{MtConnectionsSideUdpDuplex, MtConnectionsUdpPacket},
};
use crate::{
  primitives::ConnectionSide, quic_connection::MAX_DATAGRAM_SIZE, utils::task::reap_finished_tasks,
};

type UdpDispatchRegistration = DropCallback<Box<dyn Fn() + Send>>;

pub const MT_CONNECTIONS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MT_CONNECTIONS_PACKET_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MT_CONNECTIONS_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
pub const MT_CONNECTIONS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const MT_CONNECTIONS_KEEPALIVE_RETRIES: u32 = 3;
pub const MT_CONNECTIONS_TCP_USER_TIMEOUT: Duration = Duration::from_secs(60);
// Linux treats zero as "use net.ipv4.tcp_notsent_lowat", whose default is
// UINT_MAX. One is therefore the smallest effective per-socket value: the
// socket becomes writable again only after its unsent queue drains to zero.
pub const MT_CONNECTIONS_TCP_NOTSENT_LOWAT: u32 = 1;
const MT_CONNECTIONS_DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub(crate) const MT_CONNECTIONS_ROTATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MT_CONNECTIONS_TCP_INFO_INTERVAL: Duration = Duration::from_millis(50);
const MT_CONNECTIONS_TCP_INFO_STALE_AFTER: Duration = Duration::from_millis(250);
const MT_CONNECTIONS_HOL_STALL_MIN: Duration = Duration::from_millis(500);
const MT_CONNECTIONS_DEAD_STALL_MIN: Duration = Duration::from_secs(3);
pub(crate) const MT_TCP_CA_RECOVERY: u8 = 3;
pub(crate) const MT_TCP_CA_LOSS: u8 = 4;
pub(crate) const MT_TCP_DEAD_BACKOFF: u8 = 3;
pub(crate) const BOOTSTRAP_FALLBACK_GROUP_ID: u16 = u16::MAX;
pub(super) const ESTIMATED_TCP_MSS_BYTES: u64 = 1448;
const FALLBACK_INFLIGHT_HALF_LIFE_SECS: f64 = 0.2;
const MIN_GROUP_QUEUE_CAPACITY: usize = 4;
const EXPRESS_QUEUE_CAPACITY: usize = 16;
const TCP_WIRE_OVERHEAD_BYTES: u64 = 56;
const SUGGESTED_SERIALIZATION_TARGET_MILLIS: u128 = 30;
const MIN_DYNAMIC_DATAGRAM_SIZE: usize = 2048;

fn group_bulk_queue_capacity(writable_paths: usize) -> usize {
  writable_paths.saturating_sub(1).max(MIN_GROUP_QUEUE_CAPACITY)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnderlaySendReadiness {
  Ready {
    allow_bulk: bool,
    bulk_ready_at: Option<Instant>,
  },
  Wait {
    ready_at: Option<Instant>,
  },
  Closed,
}

pub(crate) trait UnderlayControl: Send + Sync {
  fn loss_notify(&self) -> &Notify;

  fn sender_notify(&self) -> &Notify;

  fn suggested_send_datagram_size(&self) -> usize;

  fn send_readiness(&self) -> UnderlaySendReadiness;
}

#[derive(Clone, Debug)]
pub(crate) struct PathGroupSpec {
  pub id: u16,
  pub local_out: Option<Arc<TokenBucket>>,
  pub peer_in: Option<Arc<TokenBucket>>,
}

struct SequencedPacket<TPacket> {
  packet: TPacket,
  seq: u64,
}

struct QueuedPacket<TPacket> {
  packet: TPacket,
  seq: u64,
}

struct PathGroupState<TPacket> {
  id: u16,
  local_out: Option<Arc<TokenBucket>>,
  peer_in: Option<Arc<TokenBucket>>,
  express_queue: VecDeque<QueuedPacket<TPacket>>,
  bulk_queue: VecDeque<QueuedPacket<TPacket>>,
  express_path_id: Option<u64>,
  writable_paths: usize,
  #[cfg(test)]
  enqueued_bytes: u64,
}

impl<TPacket> PathGroupState<TPacket> {
  fn new(
    id: u16,
    local_out: Option<Arc<TokenBucket>>,
    peer_in: Option<Arc<TokenBucket>>,
  ) -> Self {
    Self {
      id,
      local_out,
      peer_in,
      express_queue: VecDeque::with_capacity(EXPRESS_QUEUE_CAPACITY),
      bulk_queue: VecDeque::with_capacity(MIN_GROUP_QUEUE_CAPACITY),
      express_path_id: None,
      writable_paths: 0,
      #[cfg(test)]
      enqueued_bytes: 0,
    }
  }

  fn is_empty(&self) -> bool {
    self.express_queue.is_empty() && self.bulk_queue.is_empty()
  }

  fn suggested_datagram_size(&self) -> usize {
    let effective_rate = match (
      self
        .local_out
        .as_ref()
        .map(|bucket| bucket.rate_bytes_per_second()),
      self
        .peer_in
        .as_ref()
        .map(|bucket| bucket.rate_bytes_per_second()),
    ) {
      (Some(local_rate), Some(peer_rate)) => Some(local_rate.min(peer_rate)),
      (Some(rate), None) | (None, Some(rate)) => Some(rate),
      (None, None) => None,
    };

    match effective_rate {
      Some(rate) => ((rate as u128 * SUGGESTED_SERIALIZATION_TARGET_MILLIS / 1_000) as usize)
        .clamp(MIN_DYNAMIC_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE),
      None => MAX_DATAGRAM_SIZE,
    }
  }
}

enum EnqueueOutcome<TPacket> {
  Enqueued,
  Closed,
  Wait {
    packet: TPacket,
    ready_at: Option<Instant>,
  },
}

enum ClaimOutcome<TPacket> {
  Packet(TPacket),
  Wait,
  Closed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MtTcpInfo {
  pub(crate) ca_state: u8,
  pub(crate) probes: u8,
  pub(crate) backoff: u8,
  pub(crate) rtt: Duration,
  pub(crate) rttvar: Duration,
  pub(crate) rto: Duration,
  pub(crate) snd_mss: u32,
  pub(crate) unacked: u32,
  pub(crate) notsent_bytes: u32,
  pub(crate) retrans: u32,
  pub(crate) total_retrans: u32,
  pub(crate) bytes_acked: u64,
  pub(crate) delivered: u32,
}

impl MtTcpInfo {
  fn has_outstanding_send_data(&self) -> bool {
    self.unacked > 0 || self.notsent_bytes > 0
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpPathHealth {
  Clean,
  Stalling,
  Dead,
}

#[derive(Clone, Copy, Debug)]
struct MtTcpPathSample {
  info: MtTcpInfo,
  sampled_at: Instant,
}

#[derive(Debug)]
struct MtTcpPathState {
  group_id: u16,
  local_address: Option<SocketAddr>,
  peer_address: SocketAddr,
  last_cumulative_ack: Instant,
  last_delivery_progress: Instant,
  health: TcpPathHealth,
  dead_pending: bool,
  transport: quiche::ReliableTransport,
  active: watch::Sender<bool>,
  retiring: watch::Sender<bool>,
  dead: watch::Sender<bool>,
  write_open: bool,
  wake: Arc<Notify>,
  last_claimed_seq: u64,
  writing_bytes: u64,
  bytes_written_since_sample: u64,
  fallback_inflight_bytes: f64,
  fallback_inflight_updated_at: Instant,
  sample: Option<MtTcpPathSample>,
  rtt_minima: VecDeque<(Instant, Duration)>,
}

impl MtTcpPathState {
  fn is_writable(&self) -> bool {
    *self.active.borrow() && !*self.retiring.borrow() && !*self.dead.borrow() && self.write_open
  }

  fn is_live(&self) -> bool {
    !*self.retiring.borrow() && !*self.dead.borrow()
  }

  fn decay_fallback_inflight(&mut self, now: Instant) {
    let elapsed = now
      .saturating_duration_since(self.fallback_inflight_updated_at)
      .as_secs_f64();
    if elapsed > 0.0 {
      self.fallback_inflight_bytes *= 0.5_f64.powf(elapsed / FALLBACK_INFLIGHT_HALF_LIFE_SECS);
      if self.fallback_inflight_bytes < 1.0 {
        self.fallback_inflight_bytes = 0.0;
      }
      self.fallback_inflight_updated_at = now;
    }
  }

  fn record_fallback_write(&mut self, wire_bytes: u64, now: Instant) {
    self.decay_fallback_inflight(now);
    self.fallback_inflight_bytes += wire_bytes as f64;
  }

  fn estimated_inflight_bytes(&mut self, now: Instant) -> u64 {
    if let Some(sample) = self.sample.filter(|sample| {
      now.saturating_duration_since(sample.sampled_at) <= MT_CONNECTIONS_TCP_INFO_STALE_AFTER
    }) {
      let mss = u64::from(sample.info.snd_mss).max(ESTIMATED_TCP_MSS_BYTES);
      u64::from(sample.info.unacked)
        .saturating_mul(mss)
        .saturating_add(u64::from(sample.info.notsent_bytes))
        .saturating_add(self.bytes_written_since_sample)
        .saturating_add(self.writing_bytes)
    } else {
      self.decay_fallback_inflight(now);
      (self.fallback_inflight_bytes.round() as u64).max(self.writing_bytes)
    }
  }

  fn sort_key(&mut self, path_id: u64, now: Instant) -> (bool, u64, Duration, u64) {
    let inflight_bytes = self.estimated_inflight_bytes(now);
    let min_rtt = self.minimum_rtt(now).unwrap_or(Duration::MAX);
    let retransmitting = self
      .sample
      .filter(|sample| {
        now.saturating_duration_since(sample.sampled_at) <= MT_CONNECTIONS_TCP_INFO_STALE_AFTER
      })
      .is_some_and(|sample| sample.info.ca_state >= MT_TCP_CA_RECOVERY || sample.info.retrans > 0);

    (retransmitting, inflight_bytes, min_rtt, path_id)
  }

  fn minimum_rtt(&mut self, now: Instant) -> Option<Duration> {
    while self.rtt_minima.front().is_some_and(|(sampled_at, _)| {
      now.saturating_duration_since(*sampled_at) >= MT_CONNECTIONS_ROTATION_INTERVAL
    }) {
      self.rtt_minima.pop_front();
    }
    self.rtt_minima.front().map(|(_, rtt)| *rtt)
  }

  fn record_rtt(&mut self, now: Instant, rtt: Duration) {
    self.minimum_rtt(now);
    while self
      .rtt_minima
      .back()
      .is_some_and(|(_, previous)| *previous >= rtt)
    {
      self.rtt_minima.pop_back();
    }
    self.rtt_minima.push_back((now, rtt));
  }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MtConnectionsUnderlaySnapshot {
  pub paths: usize,
  pub sampled_paths: usize,
  pub active_paths: usize,
  pub stalling_paths: usize,
  pub max_rtt: Duration,
  pub max_rttvar: Duration,
  pub max_rto: Duration,
  pub max_ack_stall: Duration,
  pub max_delivery_stall: Duration,
  pub max_backoff: u8,
  pub total_unacked: u64,
  pub retransmitting_paths: usize,
  pub total_retrans: u64,
}

impl fmt::Display for MtConnectionsUnderlaySnapshot {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "paths={} sampled_paths={} active_paths={} stalling_paths={} max_rtt_ms={} max_rttvar_ms={} \
       max_rto_ms={} max_ack_stall_ms={} max_delivery_stall_ms={} max_backoff={} total_unacked={} \
       retransmitting_paths={} \
       total_retrans={}",
      self.paths,
      self.sampled_paths,
      self.active_paths,
      self.stalling_paths,
      self.max_rtt.as_millis(),
      self.max_rttvar.as_millis(),
      self.max_rto.as_millis(),
      self.max_ack_stall.as_millis(),
      self.max_delivery_stall.as_millis(),
      self.max_backoff,
      self.total_unacked,
      self.retransmitting_paths,
      self.total_retrans,
    )
  }
}

struct MtConnectionsState<TPacket> {
  next_path_id: u64,
  paths: HashMap<u64, MtTcpPathState>,
  groups: Vec<PathGroupState<TPacket>>,
  pending: VecDeque<SequencedPacket<TPacket>>,
  closed: bool,
}

impl<TPacket> Default for MtConnectionsState<TPacket> {
  fn default() -> Self {
    Self {
      next_path_id: 0,
      paths: HashMap::new(),
      groups: vec![PathGroupState::new(0, None, None)],
      pending: VecDeque::new(),
      closed: false,
    }
  }
}

pub(crate) struct MtConnectionsUnderlayMetrics<TPacket = crate::quic_connection::QuicBytesPacket> {
  state: Mutex<MtConnectionsState<TPacket>>,
  next_packet_seq: AtomicU64,
  pub(crate) loss_notify: Notify,
  sender_notify: Notify,
  closed_notify: Notify,
  non_fallback_path_notify: Notify,
}

impl<TPacket> Default for MtConnectionsUnderlayMetrics<TPacket> {
  fn default() -> Self {
    Self {
      state: Mutex::new(MtConnectionsState::default()),
      next_packet_seq: AtomicU64::new(0),
      loss_notify: Notify::new(),
      sender_notify: Notify::new(),
      closed_notify: Notify::new(),
      non_fallback_path_notify: Notify::new(),
    }
  }
}

impl<TPacket: MtConnectionsPacket> MtConnectionsUnderlayMetrics<TPacket> {
  fn sequence_packet(&self, packet: TPacket) -> SequencedPacket<TPacket> {
    let seq = self.next_packet_seq.fetch_add(1, atomic::Ordering::Relaxed) + 1;

    SequencedPacket { packet, seq }
  }

  fn fail_packet_delivery(packet: &TPacket, loss_notify: &Notify) {
    let failed = quiche::ReliableTransport::default();
    failed.fail();
    if packet.bind_reliable_transport(failed) {
      loss_notify.notify_one();
    }
  }

  fn sync_group_express_path(
    paths: &mut HashMap<u64, MtTcpPathState>,
    group: &mut PathGroupState<TPacket>,
    now: Instant,
  ) {
    if group.writable_paths < 2 {
      group.express_path_id = None;
      return;
    }

    if let Some(express_id) = group.express_path_id
      && paths
        .get(&express_id)
        .is_some_and(|path| path.group_id == group.id && path.is_writable())
    {
      return;
    }

    group.express_path_id = paths
      .iter_mut()
      .filter(|(_, path)| path.group_id == group.id && path.is_writable())
      .map(|(&path_id, path)| path.sort_key(path_id, now))
      .min()
      .map(|(_, _, _, path_id)| path_id);
  }

  fn drain_stranded_from_queue(
    queue: &mut VecDeque<QueuedPacket<TPacket>>,
    min_last_seq: u64,
    local_out: Option<&TokenBucket>,
    peer_in: Option<&TokenBucket>,
    #[cfg(test)] enqueued_bytes: &mut u64,
    loss_notify: &Notify,
  ) -> bool {
    let mut removed_any = false;
    let mut index = 0;

    while index < queue.len() {
      let is_stranded =
        queue[index].packet.has_reliable_delivery() && queue[index].seq <= min_last_seq;
      if is_stranded {
        let queued = queue.remove(index).unwrap();
        let wire_bytes = queued.packet.len() as u64 + TCP_WIRE_OVERHEAD_BYTES;
        refund_pair(local_out, peer_in, wire_bytes);
        #[cfg(test)]
        {
          *enqueued_bytes = enqueued_bytes.saturating_sub(wire_bytes);
        }
        Self::fail_packet_delivery(&queued.packet, loss_notify);
        removed_any = true;
      } else {
        index += 1;
      }
    }

    removed_any
  }

  fn reconcile_stranded_group_packets(
    state: &mut MtConnectionsState<TPacket>,
    group_id: u16,
    now: Instant,
    loss_notify: &Notify,
    sender_notify: &Notify,
  ) {
    let MtConnectionsState { paths, groups, .. } = state;
    let Some(group) = groups.iter_mut().find(|group| group.id == group_id) else {
      return;
    };
    if group.writable_paths == 0 {
      group.express_path_id = None;
      return;
    }

    Self::sync_group_express_path(paths, group, now);

    let (min_express_last_seq, min_bulk_last_seq) = match group.express_path_id {
      Some(express_id) => {
        let express_seq = paths.get(&express_id).map(|path| path.last_claimed_seq);
        let bulk_seq = paths
          .iter()
          .filter(|(id, path)| {
            path.group_id == group_id && path.is_writable() && **id != express_id
          })
          .map(|(_, path)| path.last_claimed_seq)
          .min();
        (express_seq, bulk_seq)
      }
      None => {
        let sole_seq = paths
          .values()
          .filter(|path| path.group_id == group_id && path.is_writable())
          .map(|path| path.last_claimed_seq)
          .min();
        (sole_seq, sole_seq)
      }
    };

    let mut removed_any = false;
    if let Some(min_seq) = min_express_last_seq {
      removed_any |= Self::drain_stranded_from_queue(
        &mut group.express_queue,
        min_seq,
        group.local_out.as_deref(),
        group.peer_in.as_deref(),
        #[cfg(test)]
        &mut group.enqueued_bytes,
        loss_notify,
      );
    }
    if let Some(min_seq) = min_bulk_last_seq {
      removed_any |= Self::drain_stranded_from_queue(
        &mut group.bulk_queue,
        min_seq,
        group.local_out.as_deref(),
        group.peer_in.as_deref(),
        #[cfg(test)]
        &mut group.enqueued_bytes,
        loss_notify,
      );
    }

    if removed_any {
      sender_notify.notify_waiters();
    }
  }

  fn two_smallest_bulk_last_seqs(
    paths: &HashMap<u64, MtTcpPathState>,
    group_id: u16,
    express_id: u64,
  ) -> (Option<(u64, u64)>, Option<u64>) {
    let mut min1: Option<(u64, u64)> = None;
    let mut min2: Option<u64> = None;

    for (&id, path) in paths {
      if path.group_id != group_id || !path.is_writable() || id == express_id {
        continue;
      }

      let seq = path.last_claimed_seq;
      match min1 {
        None => min1 = Some((id, seq)),
        Some((_, best_seq)) if seq < best_seq => {
          min2 = Some(best_seq);
          min1 = Some((id, seq));
        }
        Some(_) => {
          min2 = Some(min2.map_or(seq, |second| second.min(seq)));
        }
      }
    }

    (min1, min2)
  }

  fn wake_group_paths(
    state: &mut MtConnectionsState<TPacket>,
    group_id: u16,
    now: Instant,
    exclude_path_id: Option<u64>,
    loss_notify: &Notify,
    sender_notify: &Notify,
  ) {
    Self::reconcile_stranded_group_packets(state, group_id, now, loss_notify, sender_notify);

    let MtConnectionsState { paths, groups, .. } = state;
    let Some(group) = groups.iter_mut().find(|group| group.id == group_id) else {
      return;
    };
    if group.is_empty() || group.writable_paths == 0 {
      return;
    }

    match group.express_path_id {
      None => {
        if let Some((_, sole)) = paths.iter().find(|(id, path)| {
          path.group_id == group_id
            && path.is_writable()
            && path.writing_bytes == 0
            && Some(**id) != exclude_path_id
        }) {
          let can_claim =
            Self::find_claimable_lane_index(&group.express_queue, sole.last_claimed_seq, None)
              .is_some()
              || Self::find_claimable_lane_index(&group.bulk_queue, sole.last_claimed_seq, None)
                .is_some();
          if can_claim {
            sole.wake.notify_one();
          }
        }
      }
      Some(express_id) => {
        if !group.express_queue.is_empty()
          && Some(express_id) != exclude_path_id
          && let Some(express_path) = paths.get(&express_id)
          && express_path.writing_bytes == 0
          && Self::find_claimable_lane_index(
            &group.express_queue,
            express_path.last_claimed_seq,
            None,
          )
          .is_some()
        {
          express_path.wake.notify_one();
        }

        let bulk_needed = group.bulk_queue.len();
        if bulk_needed > 0 {
          let (min1, min2) = Self::two_smallest_bulk_last_seqs(paths, group_id, express_id);

          let mut idle_bulk: Vec<(bool, u64, Duration, u64)> = paths
            .iter_mut()
            .filter(|(id, path)| {
              let id = **id;
              if path.group_id != group_id
                || !path.is_writable()
                || id == express_id
                || Some(id) == exclude_path_id
                || path.writing_bytes != 0
              {
                return false;
              }

              let min_sibling_seq = if min1.is_some_and(|(best_id, _)| best_id == id) {
                min2
              } else {
                min1.map(|(_, seq)| seq)
              };

              Self::find_claimable_lane_index(
                &group.bulk_queue,
                path.last_claimed_seq,
                min_sibling_seq,
              )
              .is_some()
            })
            .map(|(&id, path)| path.sort_key(id, now))
            .collect();
          idle_bulk.sort_unstable();

          for (_, _, _, target_id) in idle_bulk.into_iter().take(bulk_needed) {
            if let Some(target) = paths.get(&target_id) {
              target.wake.notify_one();
            }
          }
        }
      }
    }
  }

  fn rescue_group_queues(
    group: &mut PathGroupState<TPacket>,
    pending: &mut VecDeque<SequencedPacket<TPacket>>,
  ) -> bool {
    let had_packets = !group.is_empty();

    for queue in [&mut group.express_queue, &mut group.bulk_queue] {
      while let Some(queued) = queue.pop_back() {
        let wire_bytes = queued.packet.len() as u64 + TCP_WIRE_OVERHEAD_BYTES;
        refund_pair(
          group.local_out.as_deref(),
          group.peer_in.as_deref(),
          wire_bytes,
        );
        #[cfg(test)]
        {
          group.enqueued_bytes = group.enqueued_bytes.saturating_sub(wire_bytes);
        }
        pending.push_front(SequencedPacket {
          packet: queued.packet,
          seq: queued.seq,
        });
      }
    }

    if had_packets {
      pending.make_contiguous().sort_by_key(|item| item.seq);
    }

    had_packets
  }

  fn sync_group_writable(
    state: &mut MtConnectionsState<TPacket>,
    sender_notify: &Notify,
    loss_notify: &Notify,
    group_id: u16,
    was_writable: bool,
    is_writable: bool,
  ) {
    if was_writable == is_writable {
      return;
    }

    let now = Instant::now();
    let Some(group_index) = state.groups.iter().position(|group| group.id == group_id) else {
      return;
    };

    if is_writable {
      state.groups[group_index].writable_paths += 1;
      Self::reconcile_stranded_group_packets(state, group_id, now, loss_notify, sender_notify);
      sender_notify.notify_waiters();
      if !state.groups[group_index].is_empty() {
        Self::wake_group_paths(state, group_id, now, None, loss_notify, sender_notify);
      }
    } else {
      state.groups[group_index].writable_paths =
        state.groups[group_index].writable_paths.saturating_sub(1);

      if state.groups[group_index].writable_paths == 0 {
        state.groups[group_index].express_path_id = None;
        let MtConnectionsState {
          groups, pending, ..
        } = state;
        if Self::rescue_group_queues(&mut groups[group_index], pending) {
          sender_notify.notify_waiters();
        }
      } else {
        Self::reconcile_stranded_group_packets(state, group_id, now, loss_notify, sender_notify);
        if !state.groups[group_index].is_empty() {
          Self::wake_group_paths(state, group_id, now, None, loss_notify, sender_notify);
        }
      }
    }
  }

  #[cfg(test)]
  pub(crate) fn register_path(
    &self,
    local_address: Option<SocketAddr>,
    peer_address: SocketAddr,
  ) -> u64 {
    self.register_path_in_group(0, local_address, peer_address)
  }

  pub(crate) fn register_path_in_group(
    &self,
    group_id: u16,
    local_address: Option<SocketAddr>,
    peer_address: SocketAddr,
  ) -> u64 {
    let mut state = self.state.lock().unwrap();
    let path_id = state.next_path_id;
    state.next_path_id += 1;
    let now = Instant::now();

    let effective_group_id = if state.groups.iter().any(|group| group.id == group_id) {
      group_id
    } else {
      state
        .groups
        .last()
        .map(|group| group.id)
        .unwrap_or(group_id)
    };

    state.paths.insert(
      path_id,
      MtTcpPathState {
        group_id: effective_group_id,
        local_address,
        peer_address,
        last_cumulative_ack: now,
        last_delivery_progress: now,
        health: TcpPathHealth::Clean,
        dead_pending: false,
        transport: quiche::ReliableTransport::default(),
        active: watch::channel(true).0,
        retiring: watch::channel(false).0,
        dead: watch::channel(false).0,
        write_open: true,
        wake: Arc::new(Notify::new()),
        last_claimed_seq: 0,
        writing_bytes: 0,
        bytes_written_since_sample: 0,
        fallback_inflight_bytes: 0.0,
        fallback_inflight_updated_at: now,
        sample: None,
        rtt_minima: VecDeque::new(),
      },
    );

    Self::sync_group_writable(
      &mut state,
      &self.sender_notify,
      &self.loss_notify,
      effective_group_id,
      false,
      true,
    );

    let pending_dead_ids: Vec<u64> = state
      .paths
      .iter()
      .filter_map(|(&id, candidate)| {
        (id != path_id && candidate.dead_pending && candidate.is_live()).then_some(id)
      })
      .collect();

    for dead_id in pending_dead_ids {
      if state.paths.values().filter(|candidate| candidate.is_live()).count() <= 1 {
        break;
      }
      let (was_writable, dead_group_id, is_writable) = {
        let dead_path = state.paths.get_mut(&dead_id).unwrap();
        let was_writable = dead_path.is_writable();
        dead_path.dead_pending = false;
        dead_path.dead.send_replace(true);
        (was_writable, dead_path.group_id, dead_path.is_writable())
      };
      Self::sync_group_writable(
        &mut state,
        &self.sender_notify,
        &self.loss_notify,
        dead_group_id,
        was_writable,
        is_writable,
      );
    }

    if effective_group_id != BOOTSTRAP_FALLBACK_GROUP_ID {
      self.non_fallback_path_notify.notify_waiters();
    }

    path_id
  }

  pub(crate) fn remove_path(&self, path_id: u64) {
    let mut state = self.state.lock().unwrap();

    if let Some(path) = state.paths.remove(&path_id) {
      let was_writable = path.is_writable();
      let group_id = path.group_id;
      path.transport.fail();
      self.loss_notify.notify_one();
      Self::sync_group_writable(
        &mut state,
        &self.sender_notify,
        &self.loss_notify,
        group_id,
        was_writable,
        false,
      );
    }
  }

  pub(crate) fn update_path(&self, path_id: u64, info: MtTcpInfo, now: Instant) {
    let mut state = self.state.lock().unwrap();
    let live_paths = state
      .paths
      .values()
      .filter(|candidate| candidate.is_live())
      .count();
    let Some(path) = state.paths.get_mut(&path_id) else {
      return;
    };

    let was_writable = path.is_writable();
    let group_id = path.group_id;

    let ack_advanced = path
      .sample
      .is_some_and(|sample| info.bytes_acked > sample.info.bytes_acked);
    let delivered_advanced = path
      .sample
      .is_some_and(|sample| info.delivered > sample.info.delivered);
    let delivery_progressed = ack_advanced || delivered_advanced;

    // Repeated reads of TCP_INFO must not keep an old RTT observation alive;
    // record RTT only on initial sample or verified outbound delivery progress.
    if !info.rtt.is_zero() && (path.sample.is_none() || delivery_progressed) {
      path.record_rtt(now, info.rtt);
    }

    if !info.has_outstanding_send_data() {
      path.last_cumulative_ack = now;
      path.last_delivery_progress = now;
    } else {
      if ack_advanced {
        path.last_cumulative_ack = now;
      }
      if delivery_progressed {
        path.last_delivery_progress = now;
      }
    }

    path.sample = Some(MtTcpPathSample {
      info,
      sampled_at: now,
    });
    path.bytes_written_since_sample = 0;

    let rtt_spread = info.rtt.saturating_add(info.rttvar);
    let stall_window = MT_CONNECTIONS_HOL_STALL_MIN
      .max(info.rto.saturating_mul(2))
      .max(rtt_spread.saturating_mul(4));
    let dead_window = MT_CONNECTIONS_DEAD_STALL_MIN.max(rtt_spread.saturating_mul(8));

    let health = if !info.has_outstanding_send_data() {
      TcpPathHealth::Clean
    } else {
      let hol_stall = now.saturating_duration_since(path.last_cumulative_ack);
      let delivery_stall = now.saturating_duration_since(path.last_delivery_progress);
      let unanswered_timeouts = info.backoff.max(info.probes);

      if delivery_stall >= dead_window && unanswered_timeouts >= MT_TCP_DEAD_BACKOFF {
        TcpPathHealth::Dead
      } else if info.ca_state >= MT_TCP_CA_LOSS
        || unanswered_timeouts > 0
        || hol_stall >= stall_window
      {
        TcpPathHealth::Stalling
      } else {
        TcpPathHealth::Clean
      }
    };

    path.health = health;

    match health {
      TcpPathHealth::Clean => {
        path.dead_pending = false;
        if path.transport.is_failed() {
          path.transport = quiche::ReliableTransport::default();
        }
        if !*path.active.borrow() {
          path.active.send_replace(true);
        }
      }
      TcpPathHealth::Stalling => {
        if *path.active.borrow() {
          path.active.send_replace(false);
        }
      }
      TcpPathHealth::Dead => {
        if *path.active.borrow() {
          path.active.send_replace(false);
        }
        if !path.transport.is_failed() {
          path.transport.fail();
          self.loss_notify.notify_one();
        }
        if live_paths > 1 {
          path.dead_pending = false;
          path.dead.send_replace(true);
        } else {
          path.dead_pending = true;
        }
      }
    }

    let is_writable = path.is_writable();
    Self::sync_group_writable(
      &mut state,
      &self.sender_notify,
      &self.loss_notify,
      group_id,
      was_writable,
      is_writable,
    );

    if state
      .groups
      .iter()
      .any(|group| group.id == group_id && !group.is_empty())
    {
      Self::wake_group_paths(
        &mut state,
        group_id,
        now,
        None,
        &self.loss_notify,
        &self.sender_notify,
      );
    }
  }

  fn sample_failed(&self, path_id: u64, now: Instant) {
    let mut state = self.state.lock().unwrap();

    if let Some(path) = state.paths.get_mut(&path_id) {
      let was_writable = path.is_writable();
      let group_id = path.group_id;
      let last_sample = path
        .sample
        .map_or(path.last_delivery_progress, |sample| sample.sampled_at);
      if now.saturating_duration_since(last_sample) >= MT_CONNECTIONS_TCP_INFO_STALE_AFTER
        && *path.active.borrow()
      {
        path.health = TcpPathHealth::Stalling;
        path.active.send_replace(false);
      }
      let is_writable = path.is_writable();
      Self::sync_group_writable(
        &mut state,
        &self.sender_notify,
        &self.loss_notify,
        group_id,
        was_writable,
        is_writable,
      );
    }
  }

  fn subscribe_path(&self, path_id: u64) -> watch::Receiver<bool> {
    self.state.lock().unwrap().paths[&path_id]
      .active
      .subscribe()
  }

  fn subscribe_retirement(&self, path_id: u64) -> watch::Receiver<bool> {
    self.state.lock().unwrap().paths[&path_id]
      .retiring
      .subscribe()
  }

  fn subscribe_dead(&self, path_id: u64) -> watch::Receiver<bool> {
    self.state.lock().unwrap().paths[&path_id]
      .dead
      .subscribe()
  }

  pub(crate) fn retire_path(&self, path_id: u64) {
    let mut state = self.state.lock().unwrap();

    if let Some(path) = state.paths.get_mut(&path_id) {
      let was_writable = path.is_writable();
      let group_id = path.group_id;
      path.retiring.send_replace(true);
      let is_writable = path.is_writable();
      Self::sync_group_writable(
        &mut state,
        &self.sender_notify,
        &self.loss_notify,
        group_id,
        was_writable,
        is_writable,
      );
    }
  }

  fn mark_write_closed(&self, path_id: u64) {
    let mut state = self.state.lock().unwrap();

    if let Some(path) = state.paths.get_mut(&path_id) {
      let was_writable = path.is_writable();
      let group_id = path.group_id;
      path.write_open = false;
      path.writing_bytes = 0;
      let is_writable = path.is_writable();
      Self::sync_group_writable(
        &mut state,
        &self.sender_notify,
        &self.loss_notify,
        group_id,
        was_writable,
        is_writable,
      );
    }
  }

  pub(crate) fn has_non_fallback_path(&self) -> bool {
    self
      .state
      .lock()
      .unwrap()
      .paths
      .values()
      .any(|path| path.group_id != BOOTSTRAP_FALLBACK_GROUP_ID && path.is_live())
  }

  pub(crate) fn non_fallback_path_notify(&self) -> &Notify {
    &self.non_fallback_path_notify
  }

  #[cfg(test)]
  pub(crate) fn available_path_count(&self) -> usize {
    self
      .state
      .lock()
      .unwrap()
      .paths
      .values()
      .filter(|path| path.is_live())
      .count()
  }

  pub(crate) fn available_path_count_in_group(&self, group_id: u16) -> usize {
    self
      .state
      .lock()
      .unwrap()
      .paths
      .values()
      .filter(|path| path.group_id == group_id && path.is_live())
      .count()
  }

  #[cfg(test)]
  pub(crate) fn retire_worst_path(&self, target_connections: usize, now: Instant) -> Option<u64> {
    self.retire_worst_path_in_group(0, target_connections, now)
  }

  pub(crate) fn retire_worst_path_in_group(
    &self,
    group_id: u16,
    target_connections: usize,
    now: Instant,
  ) -> Option<u64> {
    let mut state = self.state.lock().unwrap();

    if state
      .paths
      .values()
      .filter(|path| path.group_id == group_id && path.is_live())
      .count()
      <= target_connections.max(1)
    {
      return None;
    }

    let (path_id, minimum_rtt) = state
      .paths
      .iter_mut()
      .filter(|(_, path)| path.group_id == group_id && path.is_live())
      .filter_map(|(&path_id, path)| path.minimum_rtt(now).map(|rtt| (path_id, rtt)))
      .max_by_key(|(path_id, rtt)| (*rtt, Reverse(*path_id)))?;

    let (was_writable, local_address, peer_address) = {
      let path = state.paths.get_mut(&path_id).unwrap();
      let was_writable = path.is_writable();
      path.retiring.send_replace(true);
      (was_writable, path.local_address, path.peer_address)
    };

    Self::sync_group_writable(
      &mut state,
      &self.sender_notify,
      &self.loss_notify,
      group_id,
      was_writable,
      false,
    );

    log::info!(
      "retiring mTCP path {:?}->{}: group={group_id}, minimum RTT over the last five minutes={:?}, \
       target_connections={target_connections}",
      local_address,
      peer_address,
      minimum_rtt,
    );

    Some(path_id)
  }

  pub(crate) fn configure_groups(
    &self,
    specs: Vec<PathGroupSpec>,
    bootstrap_group_id: Option<u16>,
    fallback_limits: Option<(Option<Arc<TokenBucket>>, Option<Arc<TokenBucket>>)>,
  ) {
    let mut state = self.state.lock().unwrap();
    let now = Instant::now();
    let old_groups = std::mem::take(&mut state.groups);

    for mut old in old_groups.into_iter().rev() {
      Self::rescue_group_queues(&mut old, &mut state.pending);
    }

    let mut new_groups: Vec<PathGroupState<TPacket>> = specs
      .into_iter()
      .map(|spec| PathGroupState::new(spec.id, spec.local_out, spec.peer_in))
      .collect();

    let target_bootstrap_group = match bootstrap_group_id {
      Some(group_id) => group_id,
      None => {
        let (local_out, peer_in) = fallback_limits.unwrap_or((None, None));
        new_groups.push(PathGroupState::new(
          BOOTSTRAP_FALLBACK_GROUP_ID,
          local_out,
          peer_in,
        ));
        BOOTSTRAP_FALLBACK_GROUP_ID
      }
    };

    let mut has_non_fallback = false;
    for path in state.paths.values_mut() {
      path.group_id = target_bootstrap_group;
      path.wake.notify_one();
      if path.group_id != BOOTSTRAP_FALLBACK_GROUP_ID && !*path.retiring.borrow() {
        has_non_fallback = true;
      }
      if path.is_writable()
        && let Some(group) = new_groups
          .iter_mut()
          .find(|group| group.id == path.group_id)
      {
        group.writable_paths += 1;
      }
    }

    for group in &mut new_groups {
      Self::sync_group_express_path(&mut state.paths, group, now);
    }

    state.groups = new_groups;
    self.sender_notify.notify_waiters();

    if has_non_fallback {
      self.non_fallback_path_notify.notify_waiters();
    }
  }

  fn pop_pending(&self) -> Option<SequencedPacket<TPacket>> {
    self.state.lock().unwrap().pending.pop_front()
  }

  fn swap_with_earlier_pending(&self, current: &mut SequencedPacket<TPacket>) {
    let mut state = self.state.lock().unwrap();
    if let Some(earlier) = state
      .pending
      .pop_front_if(|front| front.seq < current.seq)
    {
      let displaced = std::mem::replace(current, earlier);
      state.pending.push_back(displaced);
      state.pending.make_contiguous().sort_by_key(|item| item.seq);
    }
  }

  fn is_closed(&self) -> bool {
    self.state.lock().unwrap().closed
  }

  #[cfg(test)]
  pub(crate) fn group_enqueued_bytes(&self, group_id: u16) -> u64 {
    self
      .state
      .lock()
      .unwrap()
      .groups
      .iter()
      .find(|group| group.id == group_id)
      .map_or(0, |group| group.enqueued_bytes)
  }

  fn mark_closed(&self) {
    let mut state = self.state.lock().unwrap();
    state.closed = true;
    state.pending.clear();
    for group in &mut state.groups {
      group.express_queue.clear();
      group.bulk_queue.clear();
    }
    for path in state.paths.values() {
      path.wake.notify_waiters();
    }
    self.closed_notify.notify_waiters();
    self.sender_notify.notify_waiters();
    self.non_fallback_path_notify.notify_waiters();
  }

  #[cfg(test)]
  fn try_enqueue(&self, packet: TPacket, now: Instant) -> EnqueueOutcome<SequencedPacket<TPacket>> {
    self.try_enqueue_sequenced(self.sequence_packet(packet), now)
  }

  fn group_lane_has_eligible_path(
    paths: &HashMap<u64, MtTcpPathState>,
    group: &PathGroupState<TPacket>,
    is_express: bool,
    monotonic_required: bool,
    seq: u64,
  ) -> bool {
    if !monotonic_required {
      return group.writable_paths > 0;
    }

    match group.express_path_id {
      Some(express_id) if is_express => paths
        .get(&express_id)
        .is_some_and(|path| path.is_writable() && path.last_claimed_seq < seq),
      Some(express_id) => paths.iter().any(|(&id, path)| {
        path.group_id == group.id
          && path.is_writable()
          && id != express_id
          && path.last_claimed_seq < seq
      }),
      None => paths
        .values()
        .any(|path| path.group_id == group.id && path.is_writable() && path.last_claimed_seq < seq),
    }
  }

  fn try_enqueue_sequenced(
    &self,
    item: SequencedPacket<TPacket>,
    now: Instant,
  ) -> EnqueueOutcome<SequencedPacket<TPacket>> {
    let mut state = self.state.lock().unwrap();
    if state.closed {
      return EnqueueOutcome::Closed;
    }

    let is_express = item.packet.is_express();
    let monotonic_required = item.packet.has_reliable_delivery();
    let seq = item.seq;

    {
      let MtConnectionsState { paths, groups, .. } = &mut *state;
      for group in groups.iter_mut() {
        if group.writable_paths > 0 {
          Self::sync_group_express_path(paths, group, now);
        }
      }
    }

    let any_group_writable = state.groups.iter().any(|group| group.writable_paths > 0);
    let any_eligible_writable_path = state.groups.iter().any(|group| {
      group.writable_paths > 0
        && Self::group_lane_has_eligible_path(
          &state.paths,
          group,
          is_express,
          monotonic_required,
          seq,
        )
    });

    if any_group_writable && !any_eligible_writable_path {
      Self::fail_packet_delivery(&item.packet, &self.loss_notify);
      return EnqueueOutcome::Enqueued;
    }

    let packet_len = item.packet.len();
    let wire_bytes = packet_len as u64 + TCP_WIRE_OVERHEAD_BYTES;
    let mut earliest_refill: Option<Instant> = None;
    let mut enqueued_group_id: Option<u16> = None;
    let mut pending_item = Some(item);

    let MtConnectionsState { paths, groups, .. } = &mut *state;

    for allow_hard_cap in [false, true] {
      for group in groups.iter_mut() {
        if group.writable_paths == 0 {
          continue;
        }

        let (queue_len, base_limit) = if is_express {
          (group.express_queue.len(), EXPRESS_QUEUE_CAPACITY)
        } else {
          (
            group.bulk_queue.len(),
            group_bulk_queue_capacity(group.writable_paths),
          )
        };
        let queue_limit = if allow_hard_cap {
          base_limit + 1
        } else {
          base_limit
        };

        if queue_len >= queue_limit {
          continue;
        }

        if !Self::group_lane_has_eligible_path(paths, group, is_express, monotonic_required, seq) {
          continue;
        }

        match try_take_pair(
          group.local_out.as_deref(),
          group.peer_in.as_deref(),
          wire_bytes,
          now,
        ) {
          Ok(()) => {
            #[cfg(test)]
            {
              group.enqueued_bytes += wire_bytes;
            }
            let item = pending_item.take().unwrap();
            let queued = QueuedPacket {
              packet: item.packet,
              seq: item.seq,
            };
            if is_express {
              group.express_queue.push_back(queued);
            } else {
              group.bulk_queue.push_back(queued);
            }
            enqueued_group_id = Some(group.id);
            break;
          }
          Err(ready_at) => {
            if !allow_hard_cap {
              earliest_refill = Some(match earliest_refill {
                Some(previous) => previous.min(ready_at),
                None => ready_at,
              });
            }
          }
        }
      }

      if enqueued_group_id.is_some() {
        break;
      }
    }

    if let Some(group_id) = enqueued_group_id {
      Self::wake_group_paths(
        &mut state,
        group_id,
        now,
        None,
        &self.loss_notify,
        &self.sender_notify,
      );
      return EnqueueOutcome::Enqueued;
    }

    EnqueueOutcome::Wait {
      packet: pending_item.unwrap(),
      ready_at: earliest_refill,
    }
  }

  fn worker_notify(&self, path_id: u64) -> Option<Arc<Notify>> {
    self
      .state
      .lock()
      .unwrap()
      .paths
      .get(&path_id)
      .map(|path| path.wake.clone())
  }

  fn find_claimable_lane_index(
    queue: &VecDeque<QueuedPacket<TPacket>>,
    my_last_seq: u64,
    min_sibling_last_seq: Option<u64>,
  ) -> Option<usize> {
    let mut min_skipped_monotonic_seq: Option<u64> = None;

    for (index, item) in queue.iter().enumerate() {
      let monotonic = item.packet.has_reliable_delivery();
      let seq = item.seq;

      if monotonic && seq <= my_last_seq {
        min_skipped_monotonic_seq =
          Some(min_skipped_monotonic_seq.map_or(seq, |previous| previous.min(seq)));
        continue;
      }

      if let Some(min_skipped) = min_skipped_monotonic_seq
        && !min_sibling_last_seq.is_some_and(|sibling_seq| sibling_seq < min_skipped)
      {
        return None;
      }

      return Some(index);
    }

    None
  }

  fn pop_lane_packet(
    queue: &mut VecDeque<QueuedPacket<TPacket>>,
    my_last_seq: u64,
    min_sibling_last_seq: Option<u64>,
  ) -> Option<QueuedPacket<TPacket>> {
    let index = Self::find_claimable_lane_index(queue, my_last_seq, min_sibling_last_seq)?;
    queue.remove(index)
  }

  fn claim_packet(&self, path_id: u64, now: Instant) -> ClaimOutcome<TPacket> {
    let mut state = self.state.lock().unwrap();
    if state.closed {
      return ClaimOutcome::Closed;
    }

    let (group_id, my_last_seq, transport) = {
      let Some(path) = state.paths.get_mut(&path_id) else {
        return ClaimOutcome::Closed;
      };
      let finished_bytes = std::mem::take(&mut path.writing_bytes);
      path.bytes_written_since_sample = path
        .bytes_written_since_sample
        .saturating_add(finished_bytes);
      if !path.is_writable() {
        return ClaimOutcome::Wait;
      }
      (path.group_id, path.last_claimed_seq, path.transport.clone())
    };

    Self::reconcile_stranded_group_packets(
      &mut state,
      group_id,
      now,
      &self.loss_notify,
      &self.sender_notify,
    );

    let (express_path_id, has_packets) = {
      let Some(group) = state.groups.iter().find(|group| group.id == group_id) else {
        return ClaimOutcome::Wait;
      };
      (group.express_path_id, !group.is_empty())
    };
    if !has_packets {
      return ClaimOutcome::Wait;
    }

    let min_sibling_last_seq: Option<u64> = match express_path_id {
      Some(express_id) if express_id == path_id => None,
      Some(express_id) => state
        .paths
        .iter()
        .filter(|(id, path)| {
          path.group_id == group_id && path.is_writable() && **id != path_id && **id != express_id
        })
        .map(|(_, path)| path.last_claimed_seq)
        .min(),
      None => None,
    };

    let claimed = {
      let group = state
        .groups
        .iter_mut()
        .find(|group| group.id == group_id)
        .unwrap();

      match express_path_id {
        Some(express_id) if express_id == path_id => {
          Self::pop_lane_packet(&mut group.express_queue, my_last_seq, min_sibling_last_seq)
            .map(|queued| (queued, !group.is_empty()))
        }
        Some(_) => Self::pop_lane_packet(&mut group.bulk_queue, my_last_seq, min_sibling_last_seq)
          .map(|queued| (queued, !group.is_empty())),
        None => Self::pop_lane_packet(&mut group.express_queue, my_last_seq, min_sibling_last_seq)
          .or_else(|| Self::pop_lane_packet(&mut group.bulk_queue, my_last_seq, min_sibling_last_seq))
          .map(|queued| (queued, !group.is_empty())),
      }
    };

    let Some((queued, has_more)) = claimed else {
      Self::wake_group_paths(
        &mut state,
        group_id,
        now,
        Some(path_id),
        &self.loss_notify,
        &self.sender_notify,
      );
      return ClaimOutcome::Wait;
    };

    let wire_bytes = queued.packet.len() as u64 + TCP_WIRE_OVERHEAD_BYTES;
    if let Some(path) = state.paths.get_mut(&path_id) {
      path.last_claimed_seq = path.last_claimed_seq.max(queued.seq);
      path.writing_bytes = wire_bytes;
      path.record_fallback_write(wire_bytes, now);
    }

    let _ = queued.packet.bind_reliable_transport(transport);
    self.sender_notify.notify_waiters();

    if has_more {
      Self::wake_group_paths(
        &mut state,
        group_id,
        now,
        Some(path_id),
        &self.loss_notify,
        &self.sender_notify,
      );
    }

    ClaimOutcome::Packet(queued.packet)
  }

  #[cfg(test)]
  pub(crate) fn bind_packet(&self, path_id: u64, packet: &TPacket) -> bool {
    let state = self.state.lock().unwrap();
    let path = &state.paths[&path_id];
    let bound = packet.bind_reliable_transport(path.transport.clone());

    if path.transport.is_failed() && bound {
      self.loss_notify.notify_one();
      return false;
    }

    true
  }

  pub(crate) fn snapshot(&self) -> MtConnectionsUnderlaySnapshot {
    let now = Instant::now();
    let state = self.state.lock().unwrap();
    let mut snapshot = MtConnectionsUnderlaySnapshot {
      paths: state.paths.len(),
      ..Default::default()
    };

    for path in state.paths.values() {
      snapshot.active_paths += usize::from(*path.active.borrow() && path.is_live());
      snapshot.stalling_paths +=
        usize::from(path.health == TcpPathHealth::Stalling && path.is_live());

      let Some(sample) = path.sample.filter(|sample| {
        now.saturating_duration_since(sample.sampled_at) <= MT_CONNECTIONS_TCP_INFO_STALE_AFTER
      }) else {
        continue;
      };

      snapshot.sampled_paths += 1;
      if sample.info.has_outstanding_send_data() {
        snapshot.max_ack_stall = snapshot
          .max_ack_stall
          .max(now.saturating_duration_since(path.last_cumulative_ack));
        snapshot.max_delivery_stall = snapshot
          .max_delivery_stall
          .max(now.saturating_duration_since(path.last_delivery_progress));
      }
      snapshot.max_backoff = snapshot.max_backoff.max(sample.info.backoff);
      snapshot.max_rtt = snapshot.max_rtt.max(sample.info.rtt);
      snapshot.max_rttvar = snapshot.max_rttvar.max(sample.info.rttvar);
      snapshot.max_rto = snapshot.max_rto.max(sample.info.rto);
      snapshot.total_unacked += u64::from(sample.info.unacked);
      snapshot.total_retrans += u64::from(sample.info.total_retrans);
      snapshot.retransmitting_paths +=
        usize::from(sample.info.ca_state >= MT_TCP_CA_RECOVERY || sample.info.retrans > 0);
    }

    snapshot
  }

  fn describe_path(&self, path_id: u64) -> String {
    self
      .state
      .lock()
      .unwrap()
      .paths
      .get(&path_id)
      .map(|path| format!("{:?}->{}", path.local_address, path.peer_address))
      .unwrap_or_else(|| format!("path#{path_id}"))
  }
}

impl<TPacket: MtConnectionsPacket> UnderlayControl for MtConnectionsUnderlayMetrics<TPacket> {
  fn loss_notify(&self) -> &Notify {
    &self.loss_notify
  }

  fn sender_notify(&self) -> &Notify {
    &self.sender_notify
  }

  fn suggested_send_datagram_size(&self) -> usize {
    let state = self.state.lock().unwrap();
    let now = Instant::now();

    let selected = state
      .groups
      .iter()
      .filter(|group| group.writable_paths > 0)
      .find(|group| has_pair_budget(group.local_out.as_deref(), group.peer_in.as_deref(), now))
      .or_else(|| {
        state
          .groups
          .iter()
          .filter(|group| group.writable_paths > 0)
          .min_by_key(|group| {
            pair_next_ready(group.local_out.as_deref(), group.peer_in.as_deref(), now)
          })
      });

    let Some(group) = selected else {
      return MAX_DATAGRAM_SIZE;
    };

    group.suggested_datagram_size()
  }

  fn send_readiness(&self) -> UnderlaySendReadiness {
    let state = self.state.lock().unwrap();
    if state.closed {
      return UnderlaySendReadiness::Closed;
    }

    if state.paths.is_empty() {
      return UnderlaySendReadiness::Ready {
        allow_bulk: true,
        bulk_ready_at: None,
      };
    }

    let now = Instant::now();
    let mut express_ready = false;
    let mut express_ready_at: Option<Instant> = None;
    let mut bulk_ready = false;
    let mut bulk_ready_at: Option<Instant> = None;
    let pending_empty = state.pending.is_empty();

    for group in &state.groups {
      if group.writable_paths == 0 {
        continue;
      }

      let has_budget = has_pair_budget(group.local_out.as_deref(), group.peer_in.as_deref(), now);
      let next_ready = (!has_budget)
        .then(|| pair_next_ready(group.local_out.as_deref(), group.peer_in.as_deref(), now))
        .flatten();

      if group.express_queue.len() < EXPRESS_QUEUE_CAPACITY {
        if has_budget {
          express_ready = true;
        } else if let Some(ready_at) = next_ready {
          express_ready_at =
            Some(express_ready_at.map_or(ready_at, |previous| previous.min(ready_at)));
        }
      }

      if pending_empty && group.bulk_queue.len() < group_bulk_queue_capacity(group.writable_paths) {
        if has_budget {
          bulk_ready = true;
        } else if let Some(ready_at) = next_ready {
          bulk_ready_at = Some(bulk_ready_at.map_or(ready_at, |previous| previous.min(ready_at)));
        }
      }
    }

    if express_ready {
      UnderlaySendReadiness::Ready {
        allow_bulk: bulk_ready,
        bulk_ready_at,
      }
    } else {
      UnderlaySendReadiness::Wait {
        ready_at: express_ready_at,
      }
    }
  }
}

#[cfg(target_os = "linux")]
fn read_mt_tcp_info(raw_fd: std::os::fd::RawFd) -> std::io::Result<MtTcpInfo> {
  // Linux UAPI struct tcp_info through tcpi_bytes_acked (offset 120),
  // tcpi_notsent_bytes (offset 144), and tcpi_delivered (offset 192). Fixed
  // UAPI offsets and native-endian reads work identically on x86_64 and aarch64.
  let mut info = [0u8; 232];
  let mut length = info.len() as libc::socklen_t;
  let result = unsafe {
    libc::getsockopt(
      raw_fd,
      libc::IPPROTO_TCP,
      libc::TCP_INFO,
      info.as_mut_ptr().cast(),
      &mut length,
    )
  };
  if result != 0 {
    return Err(std::io::Error::last_os_error());
  }
  let len = length as usize;
  if len < 128 {
    return Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "TCP_INFO lacks tcpi_bytes_acked",
    ));
  }
  let u32_at = |offset| u32::from_ne_bytes(info[offset..offset + 4].try_into().unwrap());
  let u64_at = |offset| u64::from_ne_bytes(info[offset..offset + 8].try_into().unwrap());
  Ok(MtTcpInfo {
    ca_state: info[1],
    probes: info[3],
    backoff: info[4],
    rtt: Duration::from_micros(u64::from(u32_at(68))),
    rttvar: Duration::from_micros(u64::from(u32_at(72))),
    rto: Duration::from_micros(u64::from(u32_at(8))),
    snd_mss: u32_at(16),
    unacked: u32_at(24),
    notsent_bytes: if len >= 148 { u32_at(144) } else { 0 },
    retrans: u32_at(36),
    total_retrans: u32_at(100),
    bytes_acked: u64_at(120),
    delivered: if len >= 196 { u32_at(192) } else { 0 },
  })
}

#[cfg(target_os = "linux")]
async fn monitor_mt_tcp_info<TPacket: MtConnectionsPacket>(
  raw_fd: std::os::fd::RawFd,
  path_id: u64,
  metrics: Arc<MtConnectionsUnderlayMetrics<TPacket>>,
) -> std::io::Result<()> {
  let mut interval = interval_at(TokioInstant::now(), MT_CONNECTIONS_TCP_INFO_INTERVAL);
  interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

  loop {
    interval.tick().await;
    match read_mt_tcp_info(raw_fd) {
      Ok(info) => metrics.update_path(path_id, info, Instant::now()),
      Err(error) => {
        if error.kind() == std::io::ErrorKind::Unsupported {
          return Err(error);
        }
        metrics.sample_failed(path_id, Instant::now());
        log::debug!(
          "failed to sample mTCP TCP_INFO for {}: {error}",
          metrics.describe_path(path_id),
        );
      }
    }
  }
}

#[cfg(not(target_os = "linux"))]
async fn monitor_mt_tcp_info<TPacket>(
  _raw_fd: i32,
  _path_id: u64,
  _metrics: Arc<MtConnectionsUnderlayMetrics<TPacket>>,
) -> std::io::Result<()> {
  std::future::pending().await
}

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

  #[cfg(any(target_os = "android", target_os = "linux"))]
  socket.set_tcp_notsent_lowat(MT_CONNECTIONS_TCP_NOTSENT_LOWAT)?;

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
  underlay_metrics: Arc<MtConnectionsUnderlayMetrics<TPacket>>,
  udp_duplex: Arc<UdpDuplexSlot<TPacket>>,
  _udp_registration: Option<UdpDispatchRegistration>,
  listener_handle: Option<MtListenerSessionHandle<TPacket>>,
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
  pub(crate) fn new() -> Self {
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
    mpsc::UnboundedSender<(TcpStream, u16)>,
    mpsc::UnboundedReceiver<u16>,
  ) {
    let peer_address = initial_tcp_stream.peer_addr().unwrap();

    let (tcp_stream_sender, mut tcp_stream_receiver) = mpsc::unbounded_channel();
    let (tcp_stream_close_sender, tcp_stream_close_receiver) = mpsc::unbounded_channel();

    let (external_packet_sender, packet_receiver) = flume::bounded::<TPacket>(0);
    let (packet_sender, external_packet_receiver) = flume::bounded::<TPacket>(0);

    let connection_count = Arc::new(AtomicUsize::new(1));
    let diagnostics = Arc::new(MtConnectionsDiagnostics::new());
    let underlay_metrics = Arc::new(MtConnectionsUnderlayMetrics::default());
    let manager_connection_count = connection_count.clone();
    let manager_diagnostics = diagnostics.clone();
    let manager_underlay_metrics = underlay_metrics.clone();
    let dispatch_underlay_metrics = underlay_metrics.clone();

    let dispatch_loop = async move {
      'dispatch: loop {
        let mut item = if let Some(pending) = dispatch_underlay_metrics.pop_pending() {
          pending
        } else {
          let closed = dispatch_underlay_metrics.closed_notify.notified();
          tokio::pin!(closed);
          closed.as_mut().enable();
          if dispatch_underlay_metrics.is_closed() {
            break 'dispatch;
          }

          tokio::select! {
            biased;
            _ = &mut closed => break 'dispatch,
            received = packet_receiver.recv_async() => match received {
              Ok(packet) => dispatch_underlay_metrics.sequence_packet(packet),
              Err(flume::RecvError::Disconnected) => break 'dispatch,
            },
          }
        };

        loop {
          dispatch_underlay_metrics.swap_with_earlier_pending(&mut item);

          let notified = dispatch_underlay_metrics.sender_notify.notified();
          tokio::pin!(notified);
          notified.as_mut().enable();

          match dispatch_underlay_metrics.try_enqueue_sequenced(item, Instant::now()) {
            EnqueueOutcome::Enqueued => break,
            EnqueueOutcome::Closed => break 'dispatch,
            EnqueueOutcome::Wait {
              packet: returned,
              ready_at: Some(ready_at),
            } => {
              item = returned;
              tokio::select! {
                _ = &mut notified => {}
                _ = sleep_until(ready_at.into()) => {}
              }
            }
            EnqueueOutcome::Wait {
              packet: returned,
              ready_at: None,
            } => {
              item = returned;
              notified.await;
            }
          }
        }
      }
    };

    let manager = async move {
      struct ConnectionCountGuard {
        count: Arc<AtomicUsize>,
        closed_sender: mpsc::Sender<()>,
      }

      impl Drop for ConnectionCountGuard {
        fn drop(&mut self) {
          if self.count.fetch_sub(1, atomic::Ordering::AcqRel) == 1 {
            let _ = self.closed_sender.try_send(());
          }
        }
      }

      let (all_connections_closed_sender, mut all_connections_closed_receiver) = mpsc::channel(1);

      let packet_sender = TurnArcWeak::new(packet_sender).mutex().arc();

      let pipe_bidirectional = |tcp_stream: TcpStream, group_id: u16| {
        let tcp_stream_close_sender = tcp_stream_close_sender.clone();

        let packet_sender = packet_sender.clone();

        let connection_count = manager_connection_count.clone();
        let diagnostics = manager_diagnostics.clone();
        let underlay_metrics = manager_underlay_metrics.clone();

        let all_connections_closed_sender = all_connections_closed_sender.clone();

        async move {
          let _count_guard = ConnectionCountGuard {
            count: connection_count,
            closed_sender: all_connections_closed_sender,
          };

          let Some(packet_sender) = packet_sender.lock().unwrap().get_arc() else {
            return;
          };

          let local_address = tcp_stream.local_addr().ok();
          let peer_address = tcp_stream.peer_addr().unwrap_or(peer_address);
          let path_id =
            underlay_metrics.register_path_in_group(group_id, local_address, peer_address);
          let path_registration = DropCallback::new({
            let metrics = underlay_metrics.clone();
            move || metrics.remove_path(path_id)
          });
          let mut path_active = underlay_metrics.subscribe_path(path_id);
          let mut path_retiring = underlay_metrics.subscribe_retirement(path_id);
          let mut retirement_deadline = path_retiring.clone();
          let mut path_dead = underlay_metrics.subscribe_dead(path_id);
          let write_metrics = underlay_metrics.clone();
          let read_metrics = underlay_metrics.clone();
          let recv_order = quiche::ReliableRecv::default();

          #[cfg(target_os = "linux")]
          let raw_fd = tcp_stream.as_raw_fd();
          #[cfg(not(target_os = "linux"))]
          let raw_fd = -1;

          let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

          let write_diagnostics = diagnostics.clone();
          let read_diagnostics = diagnostics.clone();

          let write = async move {
            let Some(worker_notify) = write_metrics.worker_notify(path_id) else {
              write_metrics.mark_write_closed(path_id);
              return anyhow::Ok(());
            };

            'write_loop: loop {
              if *path_retiring.borrow_and_update() {
                break;
              }

              let packet = loop {
                if *path_retiring.borrow_and_update() {
                  break 'write_loop;
                }
                let active = *path_active.borrow_and_update();

                let notified = worker_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                if active {
                  match write_metrics.claim_packet(path_id, Instant::now()) {
                    ClaimOutcome::Packet(packet) => break packet,
                    ClaimOutcome::Wait => {}
                    ClaimOutcome::Closed => break 'write_loop,
                  }
                }

                tokio::select! {
                  biased;
                  changed = path_retiring.changed() => {
                    changed?;
                    break 'write_loop;
                  }
                  changed = path_active.changed() => {
                    changed?;
                    continue;
                  }
                  _ = &mut notified, if active => {}
                }
              };

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

            write_metrics.mark_write_closed(path_id);

            // Finish the current frame before sending FIN. Keep receiving
            // until the peer has likewise drained its write half.
            timeout(MT_CONNECTIONS_PACKET_WRITE_TIMEOUT, tcp_write.shutdown()).await??;
            log::debug!("{side} write tcp stream loop ended");

            anyhow::Ok(())
          };
          let read = async move {
            loop {
              let Some(mut packet) = TPacket::read_next_packet(&mut tcp_read).await? else {
                read_metrics.retire_path(path_id);
                break;
              };
              if packet.is_empty() {
                continue;
              }
              packet.set_reliable_recv(recv_order.clone());
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
          };
          let copy_result = tokio::select! {
            result = async {
              tokio::try_join!(write, read)?;
              anyhow::Ok(())
            } => result,
            result = monitor_mt_tcp_info(raw_fd, path_id, underlay_metrics.clone()) => {
              result.map_err(Into::into)
            },
            result = async move {
              while !*retirement_deadline.borrow_and_update() {
                retirement_deadline.changed().await?;
              }
              tokio::time::sleep(MT_CONNECTIONS_TCP_USER_TIMEOUT).await;
              anyhow::bail!("timed out draining retired mTCP path");
            } => result,
            result = async move {
              while !*path_dead.borrow_and_update() {
                path_dead.changed().await?;
              }
              anyhow::bail!("closing dead mTCP path after unanswered TCP retransmissions");
            } => result,
          };

          let closed_group_id = underlay_metrics
            .state
            .lock()
            .unwrap()
            .paths
            .get(&path_id)
            .map(|path| path.group_id)
            .unwrap_or(group_id);
          drop(path_registration);

          copy_result
            .inspect_err(|error| {
              log::warn!("error copying bidirectional packet stream: {}", error);
            })
            .ok();

          tcp_stream_close_sender.send(closed_group_id).ok();
        }
      };

      let mut join_set = JoinSet::new();

      join_set.spawn(pipe_bidirectional(initial_tcp_stream, 0));

      loop {
        let (tcp_stream, group_id) = tokio::select! {
          biased;
          tcp_stream = tcp_stream_receiver.recv() => match tcp_stream {
            Some(item) => item,
            None => break,
          },
          _ = all_connections_closed_receiver.recv() => {
            if let Ok(item) = tcp_stream_receiver.try_recv() {
              item
            } else if manager_connection_count.load(atomic::Ordering::Acquire) > 0 {
              continue;
            } else {
              break;
            }
          }
        };

        reap_finished_tasks(&mut join_set, "mTCP path task");
        manager_connection_count.fetch_add(1, atomic::Ordering::AcqRel);
        join_set.spawn(pipe_bidirectional(tcp_stream, group_id));
      }

      manager_underlay_metrics.mark_closed();
    };

    let diagnostic_connection_count = connection_count.clone();
    let diagnostic_counters = diagnostics.clone();
    let diagnostic_underlay_metrics = underlay_metrics.clone();
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
          "mTCP diagnostic: side={side} peer={peer_address} paths={paths} {} tcp_info=[{}]",
          diagnostic_counters.snapshot(),
          diagnostic_underlay_metrics.snapshot(),
        );
      }
    };

    let mt_connections = Self {
      id,
      peer_address,
      packet_sink: external_packet_sender.into_sink(),
      packet_stream: external_packet_receiver.into_stream(),
      connection_count: connection_count.clone(),
      underlay_metrics,
      udp_duplex: Arc::new(UdpDuplexSlot::new()),
      _udp_registration: None,
      listener_handle: None,
      join_set: tokio_join_set!(dispatch_loop, manager, diagnostics_loop),
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

  pub(crate) fn underlay_metrics(&self) -> Arc<MtConnectionsUnderlayMetrics<TPacket>> {
    self.underlay_metrics.clone()
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

  pub(crate) fn set_listener_handle(&mut self, handle: MtListenerSessionHandle<TPacket>) {
    self.listener_handle = Some(handle);
  }

  pub(crate) fn take_listener_handle(&mut self) -> Option<MtListenerSessionHandle<TPacket>> {
    self.listener_handle.take()
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
  /// Reports whether this frame belongs to the Express lane (control, ACK,
  /// handshake, or low-urgency interactive stream).
  fn is_express(&self) -> bool {
    false
  }

  /// Reports whether sender-local reliable delivery metadata is attached,
  /// requiring strictly monotonic wire ordering per TCP `ReliableRecv` domain.
  fn has_reliable_delivery(&self) -> bool {
    false
  }

  /// Binds sender-local delivery metadata, returning whether metadata exists.
  fn bind_reliable_transport(&self, transport: quiche::ReliableTransport) -> bool;

  /// Associates a received frame with its TCP ordering domain.
  fn set_reliable_recv(&mut self, recv: quiche::ReliableRecv);

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

pub const MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE: usize = 64;
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
  Extend {
    id: MtConnectionsId,
    pair_id: u16,
    token: [u8; 32],
  },
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

  struct DrainTestPacket {
    bytes: Vec<u8>,
    write_gate: Option<(Arc<Notify>, Arc<Notify>)>,
  }

  impl MtConnectionsPacket for DrainTestPacket {
    fn bind_reliable_transport(&self, _transport: quiche::ReliableTransport) -> bool {
      false
    }

    fn set_reliable_recv(&mut self, _recv: quiche::ReliableRecv) {}

    fn len(&self) -> usize {
      self.bytes.len()
    }

    async fn read_next_packet(
      stream: &mut (dyn AsyncRead + Unpin + Send),
    ) -> std::io::Result<Option<Self>> {
      use crate::quic_connection::QuicBytesPacket;
      Ok(
        QuicBytesPacket::read_next_packet(stream)
          .await?
          .map(|packet| Self {
            bytes: packet.as_slice().to_vec(),
            write_gate: None,
          }),
      )
    }

    async fn write_packet(
      stream: &mut (dyn AsyncWrite + Unpin + Send),
      packet: Self,
    ) -> std::io::Result<()> {
      stream.write_u32(packet.bytes.len() as u32).await?;
      if let Some((started, release)) = packet.write_gate {
        started.notify_one();
        release.notified().await;
      }
      stream.write_all(&packet.bytes).await
    }
  }

  #[tokio::test]
  async fn retiring_tcp_finishes_a_partial_frame_and_keeps_receiving_after_fin()
  -> anyhow::Result<()> {
    use crate::quic_connection::QuicBytesPacket;
    use futures::{SinkExt, StreamExt};

    timeout(Duration::from_secs(5), async {
      let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
      let (client, (mut peer, _)) = tokio::try_join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept(),
      )?;
      let (transport, _sender, _) = MtConnections::<DrainTestPacket>::new(
        client,
        ConnectionSide::Client,
        MtConnectionsId::new(),
      );
      let metrics = transport.underlay_metrics();
      let (mut outgoing, mut incoming) = transport.split();
      let started = Arc::new(Notify::new());
      let release = Arc::new(Notify::new());
      let packet = DrainTestPacket {
        bytes: b"complete frame".to_vec(),
        write_gate: Some((started.clone(), release.clone())),
      };
      let send_task = tokio::spawn(async move { outgoing.send(packet).await });
      started.notified().await;
      metrics.retire_path(0);
      release.notify_one();
      let received = QuicBytesPacket::read_next_packet(&mut peer).await?.unwrap();
      assert_eq!(received.as_slice(), b"complete frame");
      assert!(
        QuicBytesPacket::read_next_packet(&mut peer)
          .await?
          .is_none()
      );

      QuicBytesPacket::write_packet(&mut peer, b"reverse frame".to_vec().into()).await?;
      peer.shutdown().await?;
      assert_eq!(incoming.next().await.unwrap().bytes, b"reverse frame");
      assert!(incoming.next().await.is_none());
      send_task.await??;
      anyhow::Ok(())
    })
    .await?
  }

  #[cfg(target_os = "linux")]
  #[tokio::test]
  async fn stalling_tcp_defers_new_packets_without_failing_in_flight_generation()
  -> anyhow::Result<()> {
    use crate::quic_connection::QuicBytesPacket;
    use futures::SinkExt;
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    timeout(Duration::from_secs(5), async {
      let listener = TcpListener::bind("127.0.0.1:0").await?;
      let (client, (mut peer, _)) = tokio::try_join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept(),
      )?;
      let (mut transport, _path_sender, _) = MtConnections::<QuicBytesPacket>::new(
        client,
        ConnectionSide::Client,
        MtConnectionsId::new(),
      );
      let metrics = transport.underlay_metrics();
      loop {
        if metrics.snapshot().sampled_paths == 1 {
          break;
        }
        sleep(Duration::from_millis(5)).await;
      }

      let path_id = *metrics.state.lock().unwrap().paths.keys().next().unwrap();
      let in_flight_generation = metrics.state.lock().unwrap().paths[&path_id].transport.clone();

      // Simulate an RTO stall (`ca_state = Loss`, `backoff = 1`, `unacked = 8`)
      // before the 3-RTO dead threshold: assignment pauses, but the generation
      // must NOT fail!
      metrics.update_path(
        path_id,
        MtTcpInfo {
          ca_state: MT_TCP_CA_LOSS,
          backoff: 1,
          ..saturated_tcp_info(8, 1)
        },
        Instant::now(),
      );
      assert!(!in_flight_generation.is_failed());
      assert_eq!(metrics.snapshot().active_paths, 0);
      assert_eq!(metrics.snapshot().stalling_paths, 1);

      let mut packet: QuicBytesPacket = vec![7, 8, 9].into();
      let delivery = quiche::ReliablePacket::default();
      packet.delivery = Some(delivery.clone());
      let send = transport.send(packet);
      tokio::pin!(send);
      assert!(
        timeout(Duration::from_millis(40), &mut send).await.is_err()
          || timeout(Duration::from_millis(20), QuicBytesPacket::read_next_packet(&mut peer))
            .await
            .is_err(),
      );

      // Next 50 ms real kernel `TCP_INFO` sample sees `unacked == 0` (`Clean`),
      // resuming the path on the same unbroken `ReliableTransport` generation.
      send.await?;
      let data = QuicBytesPacket::read_next_packet(&mut peer).await?.unwrap();
      assert_eq!(data.as_slice(), &[7, 8, 9]);
      assert_eq!(metrics.snapshot().active_paths, 1);
      assert_eq!(metrics.snapshot().stalling_paths, 0);
      assert!(!delivery.is_lost());
      assert!(!in_flight_generation.is_failed());
      anyhow::Ok(())
    })
    .await?
  }

  #[test]
  fn test_postcard_serialization() {
    let id = MtConnectionsId::new();

    let request_head_bytes =
      postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
        magic: MtConnectionsMagic,
        data: MtConnectionsRequestHeadData::Create,
      })
      .unwrap();

    let extend_head_bytes =
      postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
        magic: MtConnectionsMagic,
        data: MtConnectionsRequestHeadData::Extend {
          id,
          pair_id: 3,
          token: [0x5a; 32],
        },
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
    let extend_head = postcard::from_bytes::<MtConnectionsRequestHead>(&extend_head_bytes).unwrap();
    let response_head =
      postcard::from_bytes::<MtConnectionsResponseHead>(&response_head_bytes).unwrap();

    assert_eq!(request_head.data, MtConnectionsRequestHeadData::Create);
    assert_eq!(
      extend_head.data,
      MtConnectionsRequestHeadData::Extend {
        id,
        pair_id: 3,
        token: [0x5a; 32],
      }
    );
    assert_eq!(
      response_head.data,
      MtConnectionsResponseHeadData::Created(id)
    );
  }

  #[test]
  fn tiered_scheduler_prefers_tier0_overflows_to_tier1_and_rescues_on_loss() {
    use crate::quic_connection::QuicBytesPacket;

    let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
    let tier0_bucket = Arc::new(TokenBucket::new(100_000));
    metrics.configure_groups(
      vec![
        PathGroupSpec {
          id: 0,
          local_out: Some(tier0_bucket.clone()),
          peer_in: None,
        },
        PathGroupSpec {
          id: 1,
          local_out: None,
          peer_in: None,
        },
      ],
      Some(0),
      None,
    );

    let path0 = metrics.register_path_in_group(0, None, "127.0.0.1:1100".parse().unwrap());
    let path1 = metrics.register_path_in_group(1, None, "127.0.0.2:1100".parse().unwrap());
    let now = Instant::now();

    // While Tier 0 has budget, packets stay on Tier 0.
    assert!(matches!(
      metrics.try_enqueue(b"tier0-first".to_vec().into(), now),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.claim_packet(path0, now),
      ClaimOutcome::Packet(packet) if packet.as_slice() == b"tier0-first"
    ));

    // Enqueue a packet onto Tier 0 and leave it un-claimed, then exhaust Tier 0's budget.
    assert!(matches!(
      metrics.try_enqueue(b"rescue-me".to_vec().into(), now),
      EnqueueOutcome::Enqueued
    ));
    tier0_bucket.debit(100_000, now);
    assert!(!tier0_bucket.has_budget(now));

    // With Tier 0 out of budget, new packets spill to Tier 1 immediately.
    assert!(matches!(
      metrics.try_enqueue(b"tier1-overflow".to_vec().into(), now),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.claim_packet(path1, now),
      ClaimOutcome::Packet(packet) if packet.as_slice() == b"tier1-overflow"
    ));

    // When Tier 0 loses its last writable path, queued packets move back to pending for rescue.
    metrics.retire_path(path0);
    let rescued = metrics
      .pop_pending()
      .expect("Tier 0 packet should be rescued");
    assert_eq!(rescued.packet.as_slice(), b"rescue-me");
    assert!(matches!(
      metrics.try_enqueue_sequenced(rescued, now),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.claim_packet(path1, now),
      ClaimOutcome::Packet(packet) if packet.as_slice() == b"rescue-me"
    ));
  }

  #[test]
  fn rescue_refunds_debited_tokens_and_mark_closed_stops_enqueue() {
    use crate::quic_connection::QuicBytesPacket;

    let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
    let tier0_bucket = Arc::new(TokenBucket::new(100_000)); // initial burst = 15_000B
    metrics.configure_groups(
      vec![PathGroupSpec {
        id: 0,
        local_out: Some(tier0_bucket.clone()),
        peer_in: None,
      }],
      Some(0),
      None,
    );

    let path0 = metrics.register_path_in_group(0, None, "127.0.0.1:1100".parse().unwrap());
    let now = Instant::now();

    assert!(matches!(
      metrics.try_enqueue(vec![0xaa; 16_000].into(), now),
      EnqueueOutcome::Enqueued
    ));
    assert!(!tier0_bucket.has_budget(now));

    // Retiring the sole path rescues the packet and refunds its pre-charged tokens.
    metrics.retire_path(path0);
    assert!(tier0_bucket.has_budget(now));
    assert_eq!(metrics.group_enqueued_bytes(0), 0);

    let rescued = metrics
      .pop_pending()
      .expect("rescued packet should sit in pending");
    assert_eq!(rescued.packet.len(), 16_000);

    metrics.mark_closed();
    assert!(matches!(
      metrics.try_enqueue_sequenced(rescued, now),
      EnqueueOutcome::Closed
    ));
  }

  fn saturated_tcp_info(unacked: u32, bytes_acked: u64) -> MtTcpInfo {
    MtTcpInfo {
      ca_state: 0,
      probes: 0,
      backoff: 0,
      rtt: Duration::from_millis(50),
      rttvar: Duration::from_millis(5),
      rto: Duration::from_millis(200),
      snd_mss: ESTIMATED_TCP_MSS_BYTES as u32,
      unacked,
      notsent_bytes: 0,
      retrans: 0,
      total_retrans: 0,
      bytes_acked,
      delivered: bytes_acked as u32,
    }
  }

  #[test]
  fn express_lane_isolates_express_packets_from_saturated_and_retransmitting_bulk_paths() {
    use crate::quic_connection::QuicBytesPacket;

    let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
    let paths: Vec<u64> = (0..4)
      .map(|index| metrics.register_path(None, format!("127.0.0.1:{}", 1100 + index).parse().unwrap()))
      .collect();
    let t0 = Instant::now();

    metrics.update_path(paths[0], saturated_tcp_info(0, 1), t0);
    for &path in &paths[1..] {
      metrics.update_path(path, saturated_tcp_info(300, 1), t0);
    }

    let make_pkt = |len: usize, express: bool| {
      let mut pkt: QuicBytesPacket = vec![0x11; len].into();
      pkt.express = express;
      pkt.delivery = Some(quiche::ReliablePacket::default());
      pkt
    };

    // Enqueue 16 KiB bulk + a 400 B bulk tail fragment (`express = false`), mixed with
    // a 200 B CONNECT and a 2,400 B post-quantum TLS ClientHello (`express = true`).
    assert!(matches!(
      metrics.try_enqueue(make_pkt(MAX_DATAGRAM_SIZE, false), t0),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.try_enqueue(make_pkt(400, false), t0),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.try_enqueue(make_pkt(200, true), t0),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.try_enqueue(make_pkt(2400, true), t0),
      EnqueueOutcome::Enqueued
    ));

    // Dedicated Express path (p0) claims ONLY `express = true` packets (both 200 B and 2,400 B),
    // and never touches either the 16 KiB bulk packet or the 400 B bulk tail fragment!
    assert!(matches!(
      metrics.claim_packet(paths[0], t0),
      ClaimOutcome::Packet(packet) if packet.len() == 200
    ));
    assert!(matches!(
      metrics.claim_packet(paths[0], t0),
      ClaimOutcome::Packet(packet) if packet.len() == 2400
    ));
    assert!(matches!(metrics.claim_packet(paths[0], t0), ClaimOutcome::Wait));

    // Bulk siblings drain both bulk packets in FIFO order.
    assert!(matches!(
      metrics.claim_packet(paths[1], t0),
      ClaimOutcome::Packet(packet) if packet.len() == MAX_DATAGRAM_SIZE
    ));
    assert!(matches!(
      metrics.claim_packet(paths[2], t0),
      ClaimOutcome::Packet(packet) if packet.len() == 400
    ));

    // Even when ALL bulk siblings enter TCP Recovery (`retrans = 1`), they remain writable
    // (`Clean` health), so p0 MUST NOT swallow bulk and contaminate the Express lane!
    let t1 = t0 + Duration::from_secs(30);
    metrics.update_path(paths[0], saturated_tcp_info(0, 2), t1);
    for &path in &paths[1..] {
      metrics.update_path(
        path,
        MtTcpInfo {
          retrans: 1,
          ..saturated_tcp_info(300, 2)
        },
        t1,
      );
    }
    assert!(matches!(
      metrics.try_enqueue(make_pkt(MAX_DATAGRAM_SIZE, false), t1),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(metrics.claim_packet(paths[0], t1), ClaimOutcome::Wait));
    assert!(matches!(
      metrics.claim_packet(paths[1], t1),
      ClaimOutcome::Packet(packet) if packet.len() == MAX_DATAGRAM_SIZE
    ));

    // Only when all bulk siblings actually stall (`Stalling` / non-writable, leaving
    // `writable_paths == 1`) does the sole surviving path serve both queues (Express first).
    for &path in &paths[1..] {
      metrics.update_path(
        path,
        MtTcpInfo {
          ca_state: MT_TCP_CA_LOSS,
          backoff: 1,
          ..saturated_tcp_info(300, 2)
        },
        t1,
      );
    }
    let early_bulk = make_pkt(MAX_DATAGRAM_SIZE, false);
    let early_bulk_delivery = early_bulk.delivery.clone().unwrap();
    assert!(matches!(
      metrics.try_enqueue(early_bulk, t1),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.try_enqueue(make_pkt(180, true), t1),
      EnqueueOutcome::Enqueued
    ));
    // Express packet (`seq=7`) cuts ahead on sole surviving `paths[0]`, cleanly failing
    // `early_bulk` (`seq=6 < 7`) so quiche re-emits it at a monotonic `seq=8`!
    assert!(matches!(
      metrics.claim_packet(paths[0], t1),
      ClaimOutcome::Packet(packet) if packet.len() == 180
    ));
    assert!(matches!(metrics.claim_packet(paths[0], t1), ClaimOutcome::Wait));
    assert!(early_bulk_delivery.is_lost());

    assert!(matches!(
      metrics.try_enqueue(make_pkt(MAX_DATAGRAM_SIZE, false), t1),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.claim_packet(paths[0], t1),
      ClaimOutcome::Packet(packet) if packet.len() == MAX_DATAGRAM_SIZE
    ));
  }

  #[test]
  fn stranded_reliable_packets_fail_cleanly_on_sibling_loss_or_cross_tier_overflow() {
    use crate::quic_connection::QuicBytesPacket;

    // 1. Within-group stranding: p0 jumps ahead to seq=2 on Express, then p1 retires before claiming seq=1.
    let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
    let p0 = metrics.register_path(None, "127.0.0.1:1200".parse().unwrap());
    let p1 = metrics.register_path(None, "127.0.0.1:1201".parse().unwrap());
    let now = Instant::now();

    metrics.update_path(p0, saturated_tcp_info(0, 1), now);
    metrics.update_path(p1, saturated_tcp_info(300, 1), now);

    let mut bulk: QuicBytesPacket = vec![0xaa; MAX_DATAGRAM_SIZE].into();
    let bulk_delivery = quiche::ReliablePacket::default();
    bulk.delivery = Some(bulk_delivery.clone());

    let mut small: QuicBytesPacket = vec![0xbb; 120].into();
    small.express = true;
    let small_delivery = quiche::ReliablePacket::default();
    small.delivery = Some(small_delivery.clone());

    assert!(matches!(metrics.try_enqueue(bulk, now), EnqueueOutcome::Enqueued));
    assert!(matches!(metrics.try_enqueue(small, now), EnqueueOutcome::Enqueued));

    // p0 claims small (seq=2), leaving bulk (seq=1) for p1.
    assert!(matches!(
      metrics.claim_packet(p0, now),
      ClaimOutcome::Packet(packet) if packet.len() == 120
    ));
    assert!(!small_delivery.is_lost());
    assert!(!bulk_delivery.is_lost());

    // Now p1 retires before claiming seq=1: p0 (last_claimed_seq=2) can never send seq=1,
    // so reconcile_stranded_group_packets immediately marks bulk_delivery lost for QUIC recovery!
    metrics.retire_path(p1);
    assert!(bulk_delivery.is_lost());

    // 2. Cross-tier overflow rescue: Tier 0 holds seq=1, Tier 1 sends seq=2, then Tier 0 retires.
    let tiered = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
    let tier0_bucket = Arc::new(TokenBucket::new(100_000));
    tiered.configure_groups(
      vec![
        PathGroupSpec {
          id: 0,
          local_out: Some(tier0_bucket.clone()),
          peer_in: None,
        },
        PathGroupSpec {
          id: 1,
          local_out: None,
          peer_in: None,
        },
      ],
      Some(0),
      None,
    );
    let g0_path = tiered.register_path_in_group(0, None, "127.0.0.1:1300".parse().unwrap());
    let g1_path = tiered.register_path_in_group(1, None, "127.0.0.2:1300".parse().unwrap());

    let mut t0_pkt: QuicBytesPacket = b"tier0-queued".to_vec().into();
    let t0_delivery = quiche::ReliablePacket::default();
    t0_pkt.delivery = Some(t0_delivery.clone());
    assert!(matches!(tiered.try_enqueue(t0_pkt, now), EnqueueOutcome::Enqueued));
    tier0_bucket.debit(100_000, now);

    let mut t1_pkt: QuicBytesPacket = b"tier1-newer".to_vec().into();
    let t1_delivery = quiche::ReliablePacket::default();
    t1_pkt.delivery = Some(t1_delivery.clone());
    assert!(matches!(tiered.try_enqueue(t1_pkt, now), EnqueueOutcome::Enqueued));
    assert!(matches!(tiered.claim_packet(g1_path, now), ClaimOutcome::Packet(_)));
    assert!(!t1_delivery.is_lost());

    // Retiring Tier 0 rescues seq=1, which cannot be sent on g1_path (last_claimed_seq=2);
    // re-enqueueing immediately marks t0_delivery lost so QUIC retransmits it at a fresh pn!
    tiered.retire_path(g0_path);
    let rescued = tiered.pop_pending().expect("rescued packet expected");
    assert!(matches!(
      tiered.try_enqueue_sequenced(rescued, now),
      EnqueueOutcome::Enqueued
    ));
    assert!(t0_delivery.is_lost());
  }

  #[tokio::test]
  async fn ineligible_fast_bulk_path_never_self_wakes_and_wakes_eligible_sibling() {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use crate::quic_connection::QuicBytesPacket;

    let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
    let p_fast = metrics.register_path(None, "127.0.0.1:1400".parse().unwrap());
    let p_mid = metrics.register_path(None, "127.0.0.1:1401".parse().unwrap());
    let p_slow = metrics.register_path(None, "127.0.0.1:1402".parse().unwrap());
    let t0 = Instant::now();

    let info_with_rtt = |rtt_ms: u64, ca_state: u8, backoff: u8, bytes_acked: u64| MtTcpInfo {
      rtt: Duration::from_millis(rtt_ms),
      ca_state,
      backoff,
      ..saturated_tcp_info(10, bytes_acked)
    };

    metrics.update_path(p_fast, info_with_rtt(10, 0, 0, 1), t0);
    metrics.update_path(p_mid, info_with_rtt(20, 0, 0, 1), t0);
    metrics.update_path(p_slow, info_with_rtt(50, 0, 0, 1), t0);

    let make_pkt = |len: usize, express: bool| {
      let mut pkt: QuicBytesPacket = vec![0xcd; len].into();
      pkt.express = express;
      pkt.delivery = Some(quiche::ReliablePacket::default());
      pkt
    };

    // Enqueue bulk seq=1 and seq=2, then Express seq=3 which p_fast claims (last_claimed_seq = 3).
    assert!(matches!(
      metrics.try_enqueue(make_pkt(MAX_DATAGRAM_SIZE, false), t0),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.try_enqueue(make_pkt(MAX_DATAGRAM_SIZE, false), t0),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.try_enqueue(make_pkt(120, true), t0),
      EnqueueOutcome::Enqueued
    ));
    assert!(matches!(
      metrics.claim_packet(p_fast, t0),
      ClaimOutcome::Packet(packet) if packet.len() == 120
    ));

    // p_fast briefly stalls (promoting p_mid to express_path_id), then recovers Clean and
    // rejoins the bulk pool with last_claimed_seq=3 > bulk seq=1,2 and lower RTT (10ms < 50ms).
    let t1 = t0 + Duration::from_millis(100);
    metrics.update_path(p_fast, info_with_rtt(10, MT_TCP_CA_LOSS, 1, 1), t1);
    let t2 = t1 + Duration::from_millis(100);
    metrics.update_path(p_fast, info_with_rtt(10, 0, 0, 2), t2);

    // 1. Both p_fast (seq=3, ineligible) and p_slow (seq=0, eligible) are idle:
    //    when p_fast fails to claim, it must NOT wake itself and MUST wake p_slow.
    let fast_notify = metrics.worker_notify(p_fast).unwrap();
    let slow_notify = metrics.worker_notify(p_slow).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    // Drain any permit stored during earlier setup enqueues before arming the worker wait.
    let _ = Pin::new(&mut Box::pin(fast_notify.notified())).poll(&mut cx);
    let _ = Pin::new(&mut Box::pin(slow_notify.notified())).poll(&mut cx);

    let mut fast_fut = Box::pin(fast_notify.notified());
    let mut slow_fut = Box::pin(slow_notify.notified());
    assert!(matches!(Pin::as_mut(&mut fast_fut).poll(&mut cx), Poll::Pending));
    assert!(matches!(Pin::as_mut(&mut slow_fut).poll(&mut cx), Poll::Pending));

    assert!(matches!(metrics.claim_packet(p_fast, t2), ClaimOutcome::Wait));
    assert!(
      matches!(Pin::as_mut(&mut fast_fut).poll(&mut cx), Poll::Pending),
      "ineligible bulk path must never self-wake into a livelock"
    );
    assert!(
      matches!(Pin::as_mut(&mut slow_fut).poll(&mut cx), Poll::Ready(())),
      "eligible higher-RTT sibling must be woken instead"
    );

    // 2. Now p_slow claims seq=1 and stays busy writing (writing_bytes > 0), leaving seq=2
    //    queued while p_fast (last_claimed_seq=3) is still ineligible: p_fast still must not self-wake.
    assert!(matches!(
      metrics.claim_packet(p_slow, t2),
      ClaimOutcome::Packet(packet) if packet.len() == MAX_DATAGRAM_SIZE
    ));
    let mut fast_fut_busy = Box::pin(fast_notify.notified());
    assert!(matches!(Pin::as_mut(&mut fast_fut_busy).poll(&mut cx), Poll::Pending));
    assert!(matches!(metrics.claim_packet(p_fast, t2), ClaimOutcome::Wait));
    assert!(
      matches!(Pin::as_mut(&mut fast_fut_busy).poll(&mut cx), Poll::Pending),
      "ineligible bulk path must sleep cleanly while eligible sibling is mid-write"
    );

    // Once p_slow finishes writing seq=1, its next claim_packet call drains seq=2 cleanly.
    assert!(matches!(
      metrics.claim_packet(p_slow, t2),
      ClaimOutcome::Packet(packet) if packet.len() == MAX_DATAGRAM_SIZE
    ));
    assert!(matches!(metrics.claim_packet(p_slow, t2), ClaimOutcome::Wait));
  }
}
