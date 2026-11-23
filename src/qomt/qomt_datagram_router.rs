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

const HEALTH_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
const UDP_BASE_COOLDOWN: Duration = Duration::from_secs(5);
const UDP_MAX_COOLDOWN: Duration = Duration::from_secs(30);
const UDP_RECOVERY_CLEAN_WINDOW: Duration = Duration::from_secs(2);
const UDP_MIN_CWND_FLOOR_BYTES: usize = 10 * 1436;
const UDP_QUEUE_PRESSURE_MIN_BYTES: usize = 32 * 1024;
const UDP_QUEUE_PRESSURE_DELAY: Duration = Duration::from_millis(120);
const UDP_PRESSURE_SUSTAIN: Duration = Duration::from_millis(400);
const UDP_RTT_INFLATION_MIN: Duration = Duration::from_millis(50);
const UDP_LOSS_MIN_SENT_DELTA: usize = 16;
const UDP_LOSS_MIN_LOST_DELTA: usize = 2;
const UDP_LOSS_RATIO_DENOMINATOR: usize = 20;

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

#[derive(Default)]
struct UdpTierHealth {
  cooldown_until: Option<Instant>,
  backoff_shift: u32,
  resumed_at: Option<Instant>,
  pressure_since: Option<Instant>,
  last_sample: Option<(Instant, usize, usize, bool)>,
}

impl UdpTierHealth {
  fn is_cooling_down(&self, now: Instant) -> bool {
    self.cooldown_until.is_some_and(|until| now < until)
  }

  fn enter_cooldown(&mut self, pair_id: u16, reason: &str, now: Instant) {
    let shift = self.backoff_shift.min(3);
    let cooldown = (UDP_BASE_COOLDOWN * (1_u32 << shift)).min(UDP_MAX_COOLDOWN);
    self.cooldown_until = Some(now + cooldown);
    self.backoff_shift = (self.backoff_shift + 1).min(3);
    self.resumed_at = None;
    self.pressure_since = None;
    self.last_sample = None;

    log::info!(
      "QomT UDP pair {pair_id} bottlenecked ({reason}), offloading packet traffic to mTCP for {cooldown:?}"
    );
  }

  fn allow_udp(
    &mut self,
    pair_id: u16,
    now: Instant,
    sample: impl FnOnce() -> Option<QuicPathMetrics>,
  ) -> bool {
    if let Some(until) = self.cooldown_until {
      if now < until {
        return false;
      }

      self.cooldown_until = None;
      self.resumed_at = Some(now);
      self.pressure_since = None;
      self.last_sample = None;
      log::debug!("QomT UDP pair {pair_id} cooldown elapsed, probing UDP datagram path");
    }

    if let Some((sampled_at, _, _, cached_allow)) = self.last_sample
      && now.saturating_duration_since(sampled_at) < HEALTH_SAMPLE_INTERVAL
    {
      return cached_allow;
    }

    let Some(metrics) = sample() else {
      return false;
    };

    if let Some((_, prev_sent, prev_lost, _)) = self.last_sample {
      let delta_sent = metrics.dgram_sent.saturating_sub(prev_sent);
      let delta_lost = metrics.dgram_lost.saturating_sub(prev_lost);
      if delta_sent >= UDP_LOSS_MIN_SENT_DELTA
        && delta_lost >= UDP_LOSS_MIN_LOST_DELTA
        && delta_lost.saturating_mul(UDP_LOSS_RATIO_DENOMINATOR) >= delta_sent
      {
        self.enter_cooldown(
          pair_id,
          &format!("datagram loss {delta_lost}/{delta_sent}"),
          now,
        );
        return false;
      }
    }

    let cwnd_floor = metrics.cwnd.max(UDP_MIN_CWND_FLOOR_BYTES) as u128;
    let queue_pressure = metrics.dgram_send_queue_bytes >= UDP_QUEUE_PRESSURE_MIN_BYTES
      && (metrics.dgram_send_queue_bytes as u128) * metrics.rtt.as_micros()
        >= cwnd_floor * UDP_QUEUE_PRESSURE_DELAY.as_micros();

    let rtt_pressure = metrics.dgram_send_queue_len > 0
      && metrics.min_rtt.is_some_and(|min_rtt| {
        metrics.rtt.saturating_sub(min_rtt) >= UDP_RTT_INFLATION_MIN.max(min_rtt / 2)
      });

    if queue_pressure || rtt_pressure {
      let since = *self.pressure_since.get_or_insert(now);
      if now.saturating_duration_since(since) >= UDP_PRESSURE_SUSTAIN {
        self.enter_cooldown(
          pair_id,
          &format!(
            "sustained queue/rtt pressure: queue_bytes={} cwnd={} rtt_ms={}",
            metrics.dgram_send_queue_bytes,
            metrics.cwnd,
            metrics.rtt.as_millis()
          ),
          now,
        );
        return false;
      }
    } else {
      self.pressure_since = None;
      if let Some(resumed_at) = self.resumed_at
        && metrics.dgram_sent > 0
        && now.saturating_duration_since(resumed_at) >= UDP_RECOVERY_CLEAN_WINDOW
      {
        self.backoff_shift = 0;
        self.resumed_at = None;
        log::info!("QomT UDP pair {pair_id} recovered, staying on UDP datagram path");
      }
    }

    self.last_sample = Some((now, metrics.dgram_sent, metrics.dgram_lost, true));
    true
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
  health: Arc<Mutex<UdpTierHealth>>,
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
          health: Arc::new(Mutex::new(UdpTierHealth::default())),
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
    let health = self
      .tiers
      .lock()
      .unwrap()
      .iter()
      .find(|tier| tier.pair_id == pair_id)
      .and_then(|tier| tier.active.as_ref().map(|active| active.health.clone()));

    health.is_some_and(|health| health.lock().unwrap().is_cooling_down(now))
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
              active.health.clone(),
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

    for (pair_id, socket, health, local_out, peer_in, precharged_bytes) in candidates {
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

      let allow_udp = health
        .lock()
        .unwrap()
        .allow_udp(pair_id, now, || socket.path_metrics());
      if !allow_udp {
        saw_bottlenecked = true;
        continue;
      }

      if try_take_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes, now).is_err() {
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
          health
            .lock()
            .unwrap()
            .enter_cooldown(pair_id, "send queue full", now);
          saw_bottlenecked = true;
          saw_queue_full = true;
        }
        Err(QuicDatagramSendError::Unavailable) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
        }
        Err(QuicDatagramSendError::TooLarge { .. }) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
          saw_too_large = true;
        }
        Err(error) => {
          revert_precharged_bytes(&precharged_bytes, added_precharge);
          refund_pair(local_out.as_deref(), peer_in.as_deref(), wire_bytes);
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
  fn udp_tier_health_tolerates_transient_burst_and_cools_down_on_sustained_pressure_or_loss() {
    let base = Instant::now();
    let healthy_metrics = |sent: usize, lost: usize| QuicPathMetrics {
      rtt: Duration::from_millis(180),
      min_rtt: Some(Duration::from_millis(175)),
      rttvar: Duration::from_millis(8),
      cwnd: 64 * 1024,
      delivery_rate: 512 * 1024,
      dgram_sent: sent,
      dgram_recv: sent,
      dgram_lost: lost,
      dgram_send_queue_len: 0,
      dgram_send_queue_bytes: 0,
    };

    let mut health = UdpTierHealth::default();
    assert!(health.allow_udp(0, base, || Some(healthy_metrics(10, 0))));

    // Transient cold-start queue buildup (< 400ms) must keep UDP open so BBRv2
    // can probe bandwidth over 1-2 WAN RTTs, then clear cleanly once drained.
    let pressured = QuicPathMetrics {
      cwnd: 32 * 1024,
      dgram_send_queue_len: 40,
      dgram_send_queue_bytes: 48 * 1024,
      ..healthy_metrics(50, 0)
    };
    assert!(health.allow_udp(0, base + Duration::from_millis(150), || Some(pressured)));
    assert!(health.allow_udp(0, base + Duration::from_millis(450), || Some(pressured)));
    assert!(health.allow_udp(
      0,
      base + Duration::from_millis(600),
      || Some(healthy_metrics(90, 0)),
    ));
    assert!(!health.is_cooling_down(base + Duration::from_millis(600)));

    // Sustained (>= 400ms) queue pressure triggers the initial 5s cooldown.
    let t1 = base + Duration::from_secs(1);
    assert!(health.allow_udp(0, t1, || Some(pressured)));
    assert!(!health.allow_udp(0, t1 + Duration::from_millis(450), || Some(pressured)));
    assert!(health.is_cooling_down(t1 + Duration::from_millis(5_449)));
    assert!(!health.is_cooling_down(t1 + Duration::from_millis(5_450)));

    // After the 5s cooldown elapses, immediate >= 5% packet loss escalates to 10s.
    let t2 = t1 + Duration::from_millis(5_500);
    assert!(health.allow_udp(0, t2, || Some(healthy_metrics(100, 0))));
    assert!(!health.allow_udp(
      0,
      t2 + Duration::from_millis(150),
      || Some(healthy_metrics(120, 2)),
    ));
    assert!(health.is_cooling_down(t2 + Duration::from_millis(10_149)));
    assert!(!health.is_cooling_down(t2 + Duration::from_millis(10_150)));

    // Once cooldown expires and UDP stays clean for >= 2s, backoff resets to 5s.
    let t3 = t2 + Duration::from_millis(10_200);
    assert!(health.allow_udp(0, t3, || Some(healthy_metrics(150, 2))));
    assert!(health.allow_udp(
      0,
      t3 + Duration::from_millis(2_100),
      || Some(healthy_metrics(200, 2)),
    ));
    assert_eq!(health.backoff_shift, 0);
  }
}
