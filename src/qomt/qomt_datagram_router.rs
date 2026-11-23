use std::{
  collections::HashMap,
  sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
  },
  time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::{
  mt_connections::{
    TokenBucket, add_precharged_bytes, refund_pair, revert_precharged_bytes, try_take_pair,
  },
  quic_connection::{QuicDatagramSendError, QuicDatagramSocket, QuicPathMetrics},
};

const QOMT_DATAGRAM_WIRE_VERSION: u8 = 1;
const QOMT_DATAGRAM_ASSOCIATION_ID_SIZE: usize = size_of::<u64>();
pub(crate) const QOMT_DATAGRAM_ENVELOPE_SIZE: usize = 1 + QOMT_DATAGRAM_ASSOCIATION_ID_SIZE;
const QOMT_DATAGRAM_ASSOCIATION_QUEUE_CAPACITY: usize = 512;
const QOMT_MAX_DATAGRAM_ASSOCIATIONS: usize = 4096;
const QOMT_DATAGRAM_WIRE_OVERHEAD_BYTES: usize = 64;

const BUDGET_SAMPLE_INTERVAL: Duration = Duration::from_millis(200);
const UDP_HEADROOM_FACTOR: f64 = 0.70;
const UDP_STEP_UP_HEADROOM_CAP: f64 = 0.75;
const UDP_INITIAL_SAFE_CEILING_BPS: f64 = 1024.0 * 1024.0;
const UDP_MIN_SAFE_CEILING_BPS: f64 = 32.0 * 1024.0;
const UDP_MAX_SAFE_CEILING_BPS: f64 = 32.0 * 1024.0 * 1024.0;
const UDP_BURST_WINDOW_SECS: f64 = 0.030;
const UDP_MIN_BURST_BYTES: f64 = 12.0 * 1024.0;
const UDP_MAX_BURST_BYTES: f64 = 24.0 * 1024.0;
const UDP_MAX_SEND_QUEUE_BYTES: usize = 24 * 1024;
const UDP_RTT_INFLATION_MIN: Duration = Duration::from_millis(40);
const UDP_PAUSE_BASE_COOLDOWN: Duration = Duration::from_secs(10);
const UDP_PAUSE_MAX_COOLDOWN: Duration = Duration::from_secs(120);
const UDP_UTILIZED_CLEAN_STEP_UP_WINDOW: Duration = Duration::from_secs(10);
const UDP_IDLE_RELAX_GRACE: Duration = Duration::from_secs(180);
const UDP_IDLE_RELAX_INTERVAL: Duration = Duration::from_secs(60);
const UDP_LOG_MIN_INTERVAL: Duration = Duration::from_secs(10);
const UDP_SEVERE_LOSS_MIN_SENT: usize = 12;
const UDP_SEVERE_LOSS_MIN_LOST: usize = 3;
const UDP_SEVERE_LOSS_DENOMINATOR: usize = 10;
const UDP_MODERATE_LOSS_MIN_SENT: usize = 16;
const UDP_MODERATE_LOSS_DENOMINATOR: usize = 50;

struct DatagramRoute {
  sender: mpsc::Sender<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QomtDatagramStats {
  pub sent: u64,
  pub offloaded_bottlenecked: u64,
  pub dropped_send_queue_full: u64,
  pub received: u64,
  pub dropped_unknown_association: u64,
  pub dropped_receive_queue_full: u64,
  pub dropped_malformed: u64,
}

#[derive(Default)]
struct QomtDatagramAtomicStats {
  sent: AtomicU64,
  offloaded_bottlenecked: AtomicU64,
  dropped_send_queue_full: AtomicU64,
  received: AtomicU64,
  dropped_unknown_association: AtomicU64,
  dropped_receive_queue_full: AtomicU64,
  dropped_malformed: AtomicU64,
}

impl QomtDatagramAtomicStats {
  fn snapshot(&self) -> QomtDatagramStats {
    QomtDatagramStats {
      sent: self.sent.load(Ordering::Relaxed),
      offloaded_bottlenecked: self.offloaded_bottlenecked.load(Ordering::Relaxed),
      dropped_send_queue_full: self.dropped_send_queue_full.load(Ordering::Relaxed),
      received: self.received.load(Ordering::Relaxed),
      dropped_unknown_association: self.dropped_unknown_association.load(Ordering::Relaxed),
      dropped_receive_queue_full: self.dropped_receive_queue_full.load(Ordering::Relaxed),
      dropped_malformed: self.dropped_malformed.load(Ordering::Relaxed),
    }
  }
}

struct SampleSnapshot {
  sampled_at: Instant,
  dgram_sent: usize,
  dgram_lost: usize,
  bbr_bps: f64,
  queue_congested: bool,
}

struct AdaptiveUdpBudget {
  safe_ceiling_bps: f64,
  effective_bps: f64,
  tokens: f64,
  last_refill: Option<Instant>,
  window_sent_bytes: u64,
  clean_utilized_duration: Duration,
  last_decrease_at: Option<Instant>,
  last_idle_relax_at: Option<Instant>,
  last_logged_at: Option<Instant>,
  last_logged_ceiling_bps: f64,
  paused_until: Option<Instant>,
  backoff_shift: u32,
  last_sample: Option<SampleSnapshot>,
}

impl Default for AdaptiveUdpBudget {
  fn default() -> Self {
    let initial_effective = UDP_INITIAL_SAFE_CEILING_BPS;
    let initial_burst = Self::burst_capacity_for(initial_effective);

    Self {
      safe_ceiling_bps: UDP_INITIAL_SAFE_CEILING_BPS,
      effective_bps: initial_effective,
      tokens: initial_burst,
      last_refill: None,
      window_sent_bytes: 0,
      clean_utilized_duration: Duration::ZERO,
      last_decrease_at: None,
      last_idle_relax_at: None,
      last_logged_at: None,
      last_logged_ceiling_bps: UDP_INITIAL_SAFE_CEILING_BPS,
      paused_until: None,
      backoff_shift: 0,
      last_sample: None,
    }
  }
}

impl AdaptiveUdpBudget {
  fn burst_capacity_for(effective_bps: f64) -> f64 {
    (effective_bps * UDP_BURST_WINDOW_SECS).clamp(UDP_MIN_BURST_BYTES, UDP_MAX_BURST_BYTES)
  }

  fn bbr_reference_bps(metrics: &QuicPathMetrics) -> f64 {
    let rtt_secs = metrics.rtt.as_secs_f64().max(0.001);
    let cwnd_bps = (metrics.cwnd as f64) / rtt_secs;

    (metrics.delivery_rate as f64).max(cwnd_bps)
  }

  fn is_paused(&self, now: Instant) -> bool {
    self.paused_until.is_some_and(|until| now < until)
  }

  fn enter_severe_loss_pause(&mut self, pair_id: u16, reason: &str, now: Instant) {
    let shift = self.backoff_shift.min(4);
    let pause = (UDP_PAUSE_BASE_COOLDOWN * (1_u32 << shift)).min(UDP_PAUSE_MAX_COOLDOWN);
    self.safe_ceiling_bps = (self.safe_ceiling_bps * 0.50).max(UDP_MIN_SAFE_CEILING_BPS);
    self.effective_bps = self.effective_bps.min(self.safe_ceiling_bps);
    self.tokens = 0.0;
    self.last_refill = Some(now);
    self.window_sent_bytes = 0;
    self.clean_utilized_duration = Duration::ZERO;
    self.last_decrease_at = Some(now);
    self.last_idle_relax_at = Some(now);
    self.paused_until = Some(now + pause);
    self.backoff_shift = (self.backoff_shift + 1).min(4);
    self.last_sample = None;

    log::info!(
      "QomT UDP pair {pair_id} paused for {pause:?} ({reason}), safe_ceiling_kbps={:.0}",
      self.safe_ceiling_bps * 8.0 / 1000.0,
    );
  }

  fn tighten_ceiling(&mut self, pair_id: u16, reference_bps: f64, reason: &str, now: Instant) {
    if self
      .last_decrease_at
      .is_some_and(|last| now.saturating_duration_since(last) < BUDGET_SAMPLE_INTERVAL)
    {
      self.tokens = 0.0;
      self.last_refill = Some(now);
      return;
    }

    let candidate = (self.safe_ceiling_bps.min(reference_bps) * 0.65)
      .clamp(UDP_MIN_SAFE_CEILING_BPS, UDP_MAX_SAFE_CEILING_BPS);
    self.safe_ceiling_bps = candidate;
    self.effective_bps = self.effective_bps.min(candidate);
    self.tokens = 0.0;
    self.last_refill = Some(now);
    self.clean_utilized_duration = Duration::ZERO;
    self.last_decrease_at = Some(now);
    self.last_idle_relax_at = Some(now);

    let significant_change = (self.last_logged_ceiling_bps - candidate).abs()
      >= self.last_logged_ceiling_bps * 0.25;
    let log_ready = self
      .last_logged_at
      .is_none_or(|last| now.saturating_duration_since(last) >= UDP_LOG_MIN_INTERVAL);
    if significant_change && log_ready {
      self.last_logged_at = Some(now);
      self.last_logged_ceiling_bps = candidate;
      log::info!(
        "QomT UDP pair {pair_id} lowered safe headroom to {:.0} KB/s ({reason})",
        candidate / 1024.0,
      );
    } else {
      log::debug!(
        "QomT UDP pair {pair_id} lowered safe headroom to {:.0} KB/s ({reason})",
        candidate / 1024.0,
      );
    }
  }

  fn refresh_sample(
    &mut self,
    pair_id: u16,
    now: Instant,
    sample: impl FnOnce() -> Option<QuicPathMetrics>,
  ) -> bool {
    if let Some(until) = self.paused_until {
      if now < until {
        return false;
      }

      self.paused_until = None;
      self.last_refill = Some(now);
      self.tokens = UDP_MIN_BURST_BYTES;
      self.window_sent_bytes = 0;
      self.last_sample = None;
      log::debug!(
        "QomT UDP pair {pair_id} pause elapsed, resuming capped UDP headroom ({:.0} KB/s)",
        self.safe_ceiling_bps / 1024.0,
      );
    }

    let should_sample = self.last_sample.as_ref().is_none_or(|prev| {
      now.saturating_duration_since(prev.sampled_at) >= BUDGET_SAMPLE_INTERVAL
    });
    if !should_sample {
      return !self
        .last_sample
        .as_ref()
        .is_some_and(|prev| prev.queue_congested);
    }

    let Some(metrics) = sample() else {
      return false;
    };

    let bbr_bps = Self::bbr_reference_bps(&metrics);
    let queue_congested = metrics.dgram_send_queue_bytes >= UDP_MAX_SEND_QUEUE_BYTES;
    let rtt_inflated = metrics.dgram_send_queue_len > 0
      && metrics.min_rtt.is_some_and(|min_rtt| {
        metrics.rtt.saturating_sub(min_rtt) >= UDP_RTT_INFLATION_MIN.max(min_rtt / 3)
      });

    if let Some(prev) = &self.last_sample {
      let elapsed = now.saturating_duration_since(prev.sampled_at);
      let elapsed_secs = elapsed.as_secs_f64().max(0.001);
      let recent_sent_bps = (self.window_sent_bytes as f64) / elapsed_secs;
      self.window_sent_bytes = 0;

      let delta_sent = metrics.dgram_sent.saturating_sub(prev.dgram_sent);
      let delta_lost = metrics.dgram_lost.saturating_sub(prev.dgram_lost);

      if delta_sent >= UDP_SEVERE_LOSS_MIN_SENT
        && delta_lost >= UDP_SEVERE_LOSS_MIN_LOST
        && delta_lost.saturating_mul(UDP_SEVERE_LOSS_DENOMINATOR) >= delta_sent
      {
        self.enter_severe_loss_pause(
          pair_id,
          &format!("severe datagram loss {delta_lost}/{delta_sent}"),
          now,
        );
        return false;
      }

      let moderate_loss = delta_sent >= UDP_MODERATE_LOSS_MIN_SENT
        && delta_lost >= 1
        && delta_lost.saturating_mul(UDP_MODERATE_LOSS_DENOMINATOR) >= delta_sent;

      if moderate_loss || rtt_inflated || queue_congested {
        let reference_bps = if recent_sent_bps > 0.0 {
          recent_sent_bps.min(bbr_bps)
        } else {
          bbr_bps * UDP_HEADROOM_FACTOR
        };
        let reason = if moderate_loss {
          format!("loss {delta_lost}/{delta_sent}")
        } else if queue_congested {
          format!("queue_bytes={}", metrics.dgram_send_queue_bytes)
        } else {
          format!("rtt_ms={}", metrics.rtt.as_millis())
        };
        self.tighten_ceiling(pair_id, reference_bps, &reason, now);
      } else if metrics.dgram_send_queue_bytes < UDP_MAX_SEND_QUEUE_BYTES / 2 {
        if recent_sent_bps >= self.effective_bps * 0.40 {
          self.clean_utilized_duration += elapsed;
          if self.clean_utilized_duration >= UDP_UTILIZED_CLEAN_STEP_UP_WINDOW {
            self.clean_utilized_duration = Duration::ZERO;
            self.backoff_shift = 0;
            let bbr_cap = (bbr_bps * UDP_STEP_UP_HEADROOM_CAP)
              .clamp(UDP_INITIAL_SAFE_CEILING_BPS, UDP_MAX_SAFE_CEILING_BPS);
            self.safe_ceiling_bps = (self.safe_ceiling_bps * 1.10).min(bbr_cap);
          }
        } else if self.safe_ceiling_bps < UDP_INITIAL_SAFE_CEILING_BPS
          && self
            .last_decrease_at
            .is_some_and(|last| now.saturating_duration_since(last) >= UDP_IDLE_RELAX_GRACE)
          && self
            .last_idle_relax_at
            .is_none_or(|last| now.saturating_duration_since(last) >= UDP_IDLE_RELAX_INTERVAL)
        {
          self.last_idle_relax_at = Some(now);
          self.safe_ceiling_bps =
            (self.safe_ceiling_bps * 1.15).min(UDP_INITIAL_SAFE_CEILING_BPS);
        }
      }
    }

    self.effective_bps = (bbr_bps * UDP_HEADROOM_FACTOR)
      .min(self.safe_ceiling_bps)
      .clamp(UDP_MIN_SAFE_CEILING_BPS, UDP_MAX_SAFE_CEILING_BPS);
    let burst = Self::burst_capacity_for(self.effective_bps);
    self.tokens = self.tokens.min(burst);
    self.last_sample = Some(SampleSnapshot {
      sampled_at: now,
      dgram_sent: metrics.dgram_sent,
      dgram_lost: metrics.dgram_lost,
      bbr_bps,
      queue_congested,
    });

    !queue_congested
  }

  fn try_acquire(
    &mut self,
    pair_id: u16,
    wire_bytes: u64,
    now: Instant,
    sample: impl FnOnce() -> Option<QuicPathMetrics>,
  ) -> bool {
    if !self.refresh_sample(pair_id, now, sample) {
      return false;
    }

    let burst = Self::burst_capacity_for(self.effective_bps);
    if let Some(last_refill) = self.last_refill {
      let elapsed_secs = now.saturating_duration_since(last_refill).as_secs_f64();
      self.tokens = (self.tokens + elapsed_secs * self.effective_bps).min(burst);
    } else {
      self.tokens = burst;
    }
    self.last_refill = Some(now);

    let cost = wire_bytes as f64;
    if self.tokens < cost {
      return false;
    }

    self.tokens -= cost;
    self.window_sent_bytes = self.window_sent_bytes.saturating_add(wire_bytes);
    true
  }

  fn refund(&mut self, wire_bytes: u64) {
    let burst = Self::burst_capacity_for(self.effective_bps);
    self.tokens = (self.tokens + wire_bytes as f64).min(burst);
    self.window_sent_bytes = self.window_sent_bytes.saturating_sub(wire_bytes);
  }

  fn on_send_queue_full(&mut self, pair_id: u16, wire_bytes: u64, now: Instant) {
    self.window_sent_bytes = self.window_sent_bytes.saturating_sub(wire_bytes);
    let bbr_bps = self
      .last_sample
      .as_ref()
      .map_or(self.safe_ceiling_bps, |sample| sample.bbr_bps * UDP_HEADROOM_FACTOR);
    self.tighten_ceiling(pair_id, bbr_bps, "send queue full", now);
  }
}

pub(crate) struct DatagramTierConfig {
  pub pair_id: u16,
  pub local_out: Option<Arc<TokenBucket>>,
  pub peer_in: Option<Arc<TokenBucket>>,
  pub precharged_bytes: Arc<AtomicU64>,
}

struct ActiveDatagramSocket {
  generation: u64,
  socket: QuicDatagramSocket,
  budget: Arc<Mutex<AdaptiveUdpBudget>>,
}

struct DatagramTierSlot {
  pair_id: u16,
  active: Option<ActiveDatagramSocket>,
  local_out: Option<Arc<TokenBucket>>,
  peer_in: Option<Arc<TokenBucket>>,
  precharged_bytes: Arc<AtomicU64>,
}

pub(crate) struct QomtDatagramRouter {
  tiers: Mutex<Vec<DatagramTierSlot>>,
  next_socket_generation: AtomicU64,
  routes: Mutex<HashMap<u64, Arc<DatagramRoute>>>,
  stats: QomtDatagramAtomicStats,
}

pub(crate) struct QomtDatagramRegistration {
  association_id: u64,
  route: Arc<DatagramRoute>,
  router: Weak<QomtDatagramRouter>,
}

pub(crate) enum QomtDatagramSendOutcome {
  Queued,
  Unavailable,
  TooLarge,
  Bottlenecked,
  QueueFull,
  Failed(QuicDatagramSendError),
}

impl QomtDatagramRouter {
  pub(crate) fn new() -> Arc<Self> {
    Arc::new(Self {
      tiers: Mutex::new(Vec::new()),
      next_socket_generation: AtomicU64::new(0),
      routes: Mutex::new(HashMap::new()),
      stats: QomtDatagramAtomicStats::default(),
    })
  }

  pub(crate) fn configure_tiers(&self, configs: Vec<DatagramTierConfig>) {
    let mut tiers = self.tiers.lock().unwrap();
    *tiers = configs
      .into_iter()
      .map(|config| DatagramTierSlot {
        pair_id: config.pair_id,
        active: None,
        local_out: config.local_out,
        peer_in: config.peer_in,
        precharged_bytes: config.precharged_bytes,
      })
      .collect();
  }

  pub(crate) fn register(
    self: &Arc<Self>,
    association_id: u64,
  ) -> std::io::Result<(QomtDatagramRegistration, mpsc::Receiver<Vec<u8>>)> {
    let (sender, receiver) = mpsc::channel(QOMT_DATAGRAM_ASSOCIATION_QUEUE_CAPACITY);
    let route = Arc::new(DatagramRoute { sender });
    let mut routes = self.routes.lock().unwrap();

    if routes.contains_key(&association_id) {
      return Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("QomT datagram association {association_id} is already registered"),
      ));
    }

    if routes.len() >= QOMT_MAX_DATAGRAM_ASSOCIATIONS {
      return Err(std::io::Error::other(format!(
        "QomT datagram association limit reached ({QOMT_MAX_DATAGRAM_ASSOCIATIONS})"
      )));
    }

    routes.insert(association_id, route.clone());
    drop(routes);

    Ok((
      QomtDatagramRegistration {
        association_id,
        route,
        router: Arc::downgrade(self),
      },
      receiver,
    ))
  }

  pub(crate) async fn run_tier(self: Arc<Self>, pair_id: u16, socket: QuicDatagramSocket) {
    let generation = self.next_socket_generation.fetch_add(1, Ordering::Relaxed);

    {
      let mut tiers = self.tiers.lock().unwrap();
      if let Some(tier) = tiers.iter_mut().find(|tier| tier.pair_id == pair_id) {
        tier.precharged_bytes.store(0, Ordering::Release);
        tier.active = Some(ActiveDatagramSocket {
          generation,
          socket: socket.clone(),
          budget: Arc::new(Mutex::new(AdaptiveUdpBudget::default())),
        });
      } else {
        return;
      }
    }

    while let Some(datagram) = socket.recv().await {
      self.dispatch(datagram);
    }

    let mut tiers = self.tiers.lock().unwrap();
    if let Some(tier) = tiers.iter_mut().find(|tier| tier.pair_id == pair_id)
      && tier
        .active
        .as_ref()
        .is_some_and(|active| active.generation == generation)
    {
      tier.precharged_bytes.store(0, Ordering::Release);
      tier.active = None;
    }
  }

  #[cfg(test)]
  pub(crate) fn max_payload_len(&self) -> Option<usize> {
    let sockets: Vec<QuicDatagramSocket> = self
      .tiers
      .lock()
      .unwrap()
      .iter()
      .filter_map(|tier| tier.active.as_ref().map(|active| active.socket.clone()))
      .collect();

    sockets
      .into_iter()
      .filter_map(|socket| {
        socket
          .max_writable_len()
          .and_then(|length| length.checked_sub(QOMT_DATAGRAM_ENVELOPE_SIZE))
      })
      .max()
  }

  pub(crate) fn is_tier_bottlenecked(&self, pair_id: u16, now: Instant) -> bool {
    let budget = self
      .tiers
      .lock()
      .unwrap()
      .iter()
      .find(|tier| tier.pair_id == pair_id)
      .and_then(|tier| tier.active.as_ref().map(|active| active.budget.clone()));

    budget.is_some_and(|budget| budget.lock().unwrap().is_paused(now))
  }

  pub(crate) fn deactivate(&self) {
    for tier in self.tiers.lock().unwrap().iter_mut() {
      tier.active = None;
    }
  }

  pub(crate) fn try_send(&self, association_id: u64, payload: &[u8]) -> QomtDatagramSendOutcome {
    let candidates: Vec<_> = {
      self
        .tiers
        .lock()
        .unwrap()
        .iter()
        .filter_map(|tier| {
          tier.active.as_ref().map(|active| {
            (
              tier.pair_id,
              active.socket.clone(),
              active.budget.clone(),
              tier.local_out.clone(),
              tier.peer_in.clone(),
              tier.precharged_bytes.clone(),
            )
          })
        })
        .collect()
    };

    if candidates.is_empty() {
      return QomtDatagramSendOutcome::Unavailable;
    }

    let wire_bytes =
      (QOMT_DATAGRAM_ENVELOPE_SIZE + payload.len() + QOMT_DATAGRAM_WIRE_OVERHEAD_BYTES) as u64;
    let now = Instant::now();
    let mut datagram = None;
    let mut saw_bottlenecked = false;
    let mut saw_queue_full = false;
    let mut saw_too_large = false;
    let mut first_failure = None;

    for (pair_id, socket, budget, local_out, peer_in, precharged_bytes) in candidates {
      let Some(max_payload_len) = socket
        .max_writable_len()
        .and_then(|length| length.checked_sub(QOMT_DATAGRAM_ENVELOPE_SIZE))
      else {
        continue;
      };

      if payload.len() > max_payload_len {
        saw_too_large = true;
        continue;
      }

      if try_take_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes, now).is_err() {
        continue;
      }

      let acquired_headroom = budget
        .lock()
        .unwrap()
        .try_acquire(pair_id, wire_bytes, now, || socket.path_metrics());
      if !acquired_headroom {
        refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
        saw_bottlenecked = true;
        continue;
      }

      let frame = datagram.get_or_insert_with(|| {
        let mut buffer = Vec::with_capacity(QOMT_DATAGRAM_ENVELOPE_SIZE + payload.len());
        buffer.push(QOMT_DATAGRAM_WIRE_VERSION);
        buffer.extend_from_slice(&association_id.to_be_bytes());
        buffer.extend_from_slice(payload);
        buffer
      });

      let added_precharge = add_precharged_bytes(&precharged_bytes, wire_bytes);
      match socket.try_send(frame) {
        Ok(()) => {
          self.stats.sent.fetch_add(1, Ordering::Relaxed);
          return QomtDatagramSendOutcome::Queued;
        }
        Err(QuicDatagramSendError::QueueFull) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
          budget
            .lock()
            .unwrap()
            .on_send_queue_full(pair_id, wire_bytes, now);
          saw_bottlenecked = true;
          saw_queue_full = true;
        }
        Err(QuicDatagramSendError::Unavailable) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
          budget.lock().unwrap().refund(wire_bytes);
        }
        Err(QuicDatagramSendError::TooLarge { .. }) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
          budget.lock().unwrap().refund(wire_bytes);
          saw_too_large = true;
        }
        Err(error) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
          budget.lock().unwrap().refund(wire_bytes);
          if first_failure.is_none() {
            first_failure = Some(error);
          }
        }
      }
    }

    if saw_bottlenecked {
      self
        .stats
        .offloaded_bottlenecked
        .fetch_add(1, Ordering::Relaxed);
      if saw_queue_full {
        self
          .stats
          .dropped_send_queue_full
          .fetch_add(1, Ordering::Relaxed);
      }
      QomtDatagramSendOutcome::Bottlenecked
    } else if saw_queue_full {
      self
        .stats
        .dropped_send_queue_full
        .fetch_add(1, Ordering::Relaxed);
      QomtDatagramSendOutcome::QueueFull
    } else if saw_too_large {
      QomtDatagramSendOutcome::TooLarge
    } else if let Some(error) = first_failure {
      QomtDatagramSendOutcome::Failed(error)
    } else {
      QomtDatagramSendOutcome::Unavailable
    }
  }

  pub(crate) fn stats(&self) -> QomtDatagramStats {
    self.stats.snapshot()
  }

  #[cfg(test)]
  pub(crate) fn route_count(&self) -> usize {
    self.routes.lock().unwrap().len()
  }

  #[cfg(test)]
  pub(crate) fn active_tier_count(&self) -> usize {
    self
      .tiers
      .lock()
      .unwrap()
      .iter()
      .filter(|tier| tier.active.is_some())
      .count()
  }

  fn dispatch(&self, datagram: Vec<u8>) {
    if datagram.len() < QOMT_DATAGRAM_ENVELOPE_SIZE || datagram[0] != QOMT_DATAGRAM_WIRE_VERSION {
      self.stats.dropped_malformed.fetch_add(1, Ordering::Relaxed);
      return;
    }

    let association_id =
      u64::from_be_bytes(datagram[1..QOMT_DATAGRAM_ENVELOPE_SIZE].try_into().unwrap());
    let route = self.routes.lock().unwrap().get(&association_id).cloned();

    let Some(route) = route else {
      self
        .stats
        .dropped_unknown_association
        .fetch_add(1, Ordering::Relaxed);
      return;
    };

    match route.sender.try_reserve() {
      Ok(permit) => {
        permit.send(datagram[QOMT_DATAGRAM_ENVELOPE_SIZE..].to_vec());
        self.stats.received.fetch_add(1, Ordering::Relaxed);
      }
      Err(mpsc::error::TrySendError::Full(_)) => {
        self
          .stats
          .dropped_receive_queue_full
          .fetch_add(1, Ordering::Relaxed);
      }
      Err(mpsc::error::TrySendError::Closed(_)) => {
        let mut routes = self.routes.lock().unwrap();
        if routes
          .get(&association_id)
          .is_some_and(|registered| Arc::ptr_eq(registered, &route))
        {
          routes.remove(&association_id);
        }
      }
    }
  }
}

impl Drop for QomtDatagramRegistration {
  fn drop(&mut self) {
    let Some(router) = self.router.upgrade() else {
      return;
    };

    let mut routes = router.routes.lock().unwrap();
    if routes
      .get(&self.association_id)
      .is_some_and(|route| Arc::ptr_eq(route, &self.route))
    {
      routes.remove(&self.association_id);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn encode_datagram(association_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(QOMT_DATAGRAM_ENVELOPE_SIZE + payload.len());
    datagram.push(QOMT_DATAGRAM_WIRE_VERSION);
    datagram.extend_from_slice(&association_id.to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
  }

  #[test]
  fn registration_rejects_duplicates_and_unregisters_on_drop() {
    let router = QomtDatagramRouter::new();
    let association_id = 42;
    let (registration, mut receiver) = router.register(association_id).unwrap();

    assert_eq!(router.route_count(), 1);

    let duplicate_error = match router.register(association_id) {
      Ok(_) => panic!("duplicate association registration unexpectedly succeeded"),
      Err(error) => error,
    };
    assert_eq!(duplicate_error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(router.route_count(), 1);

    let payload = b"registered association";
    router.dispatch(encode_datagram(association_id, payload));
    assert_eq!(receiver.try_recv().unwrap(), payload);
    assert_eq!(router.stats().received, 1);

    drop(registration);

    assert_eq!(router.route_count(), 0);
    assert!(matches!(
      receiver.try_recv(),
      Err(mpsc::error::TryRecvError::Disconnected)
    ));
  }

  #[test]
  fn malformed_and_unknown_datagrams_are_dropped_and_counted() {
    let router = QomtDatagramRouter::new();

    router.dispatch(Vec::new());

    let mut wrong_version = encode_datagram(7, b"payload");
    wrong_version[0] = QOMT_DATAGRAM_WIRE_VERSION.wrapping_add(1);
    router.dispatch(wrong_version);

    router.dispatch(encode_datagram(7, b"unknown association"));

    assert_eq!(
      router.stats(),
      QomtDatagramStats {
        dropped_unknown_association: 1,
        dropped_malformed: 2,
        ..QomtDatagramStats::default()
      }
    );
  }

  #[test]
  fn full_association_queue_drops_and_counts_the_excess_datagram() {
    let router = QomtDatagramRouter::new();
    let association_id = 9;
    let (_registration, receiver) = router.register(association_id).unwrap();

    for sequence in 0..=QOMT_DATAGRAM_ASSOCIATION_QUEUE_CAPACITY {
      router.dispatch(encode_datagram(association_id, &sequence.to_be_bytes()));
    }

    assert_eq!(receiver.len(), QOMT_DATAGRAM_ASSOCIATION_QUEUE_CAPACITY);
    assert_eq!(
      router.stats(),
      QomtDatagramStats {
        received: QOMT_DATAGRAM_ASSOCIATION_QUEUE_CAPACITY as u64,
        dropped_receive_queue_full: 1,
        ..QomtDatagramStats::default()
      }
    );
  }

  #[test]
  fn adaptive_udp_budget_caps_headroom_remembers_ceiling_across_idle_and_steps_up_slowly() {
    let base = Instant::now();
    // Simulate LA evening QoS: cwnd = 156 KiB @ 180ms (~887 KB/s -> 70% = ~621 KB/s).
    let evening_metrics = |sent: usize, lost: usize, queue_bytes: usize| QuicPathMetrics {
      rtt: Duration::from_millis(180),
      min_rtt: Some(Duration::from_millis(175)),
      rttvar: Duration::from_millis(8),
      cwnd: 156 * 1024,
      delivery_rate: 880 * 1024,
      dgram_sent: sent,
      dgram_recv: sent,
      dgram_lost: lost,
      dgram_send_queue_len: usize::from(queue_bytes > 0),
      dgram_send_queue_bytes: queue_bytes,
    };

    let mut budget = AdaptiveUdpBudget::default();
    assert!(budget.try_acquire(0, 1200, base, || Some(evening_metrics(10, 0, 0))));
    assert!(budget.effective_bps <= 887.0 * 1024.0 * 0.71);

    // Burst beyond the <= 24 KiB bucket must immediately decline without queueing bloat.
    let mut accepted = 1200_u64;
    while budget.try_acquire(0, 1200, base, || Some(evening_metrics(25, 0, 0))) {
      accepted += 1200;
    }
    assert!(accepted <= 24 * 1024);

    // Moderate loss (>= 2%) tightens safe_ceiling_bps (at most once per 200ms)
    // and MUST NOT reset after 2-10s of idle traffic.
    let t1 = base + Duration::from_millis(250);
    assert!(!budget.try_acquire(0, 1200, t1, || Some(evening_metrics(50, 1, 0))));
    let tightened_ceiling = budget.safe_ceiling_bps;
    assert!(tightened_ceiling < UDP_INITIAL_SAFE_CEILING_BPS);

    for step in 1..=25_u64 {
      let now = t1 + Duration::from_millis(step * 250);
      let _ = budget.try_acquire(0, 120, now, || Some(evening_metrics(50 + step as usize, 1, 0)));
    }
    assert_eq!(
      budget.safe_ceiling_bps, tightened_ceiling,
      "light/idle traffic must never reset or inflate safe_ceiling_bps",
    );

    // Sustained clean utilization (>= 40% of effective_bps for >= 10s) gently nudges ceiling up.
    let mut t = t1 + Duration::from_secs(10);
    let mut sent = 100_usize;
    for _ in 0..55 {
      t += Duration::from_millis(250);
      let quota = (budget.effective_bps * 0.25 * 0.60) as u64;
      let mut pushed = 0_u64;
      while pushed < quota && budget.try_acquire(0, 1200, t, || Some(evening_metrics(sent, 1, 0))) {
        pushed += 1200;
        sent += 1;
      }
    }
    assert!(budget.safe_ceiling_bps > tightened_ceiling);

    // Severe loss (>= 10%) enters a pause cooldown (10s base) so ISP policers can clear.
    let t_severe = t + Duration::from_millis(300);
    assert!(!budget.try_acquire(
      0,
      1200,
      t_severe,
      || Some(evening_metrics(sent + 20, 5, 0)),
    ));
    assert!(budget.is_paused(t_severe + Duration::from_secs(9)));
    assert!(!budget.is_paused(t_severe + Duration::from_secs(10)));
  }
}
