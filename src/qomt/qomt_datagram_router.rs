use std::{
  collections::HashMap,
  sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
  },
};

use tokio::sync::mpsc;

use crate::quic_connection::{QuicDatagramSendError, QuicDatagramSocket, QuicPathMetrics};

const QOMT_DATAGRAM_WIRE_VERSION: u8 = 1;
const QOMT_DATAGRAM_ASSOCIATION_ID_SIZE: usize = size_of::<u64>();
pub(crate) const QOMT_DATAGRAM_ENVELOPE_SIZE: usize = 1 + QOMT_DATAGRAM_ASSOCIATION_ID_SIZE;
const QOMT_DATAGRAM_ASSOCIATION_QUEUE_CAPACITY: usize = 32;
const QOMT_MAX_DATAGRAM_ASSOCIATIONS: usize = 4096;

struct DatagramRoute {
  sender: mpsc::Sender<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QomtDatagramStats {
  pub sent: u64,
  pub dropped_send_queue_full: u64,
  pub received: u64,
  pub dropped_unknown_association: u64,
  pub dropped_receive_queue_full: u64,
  pub dropped_malformed: u64,
}

#[derive(Default)]
struct QomtDatagramAtomicStats {
  sent: AtomicU64,
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
      dropped_send_queue_full: self.dropped_send_queue_full.load(Ordering::Relaxed),
      received: self.received.load(Ordering::Relaxed),
      dropped_unknown_association: self.dropped_unknown_association.load(Ordering::Relaxed),
      dropped_receive_queue_full: self.dropped_receive_queue_full.load(Ordering::Relaxed),
      dropped_malformed: self.dropped_malformed.load(Ordering::Relaxed),
    }
  }
}

struct ActiveDatagramSocket {
  generation: u64,
  socket: QuicDatagramSocket,
}

pub(crate) struct QomtDatagramRouter {
  active_socket: Mutex<Option<ActiveDatagramSocket>>,
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
  QueueFull,
  Failed(QuicDatagramSendError),
}

impl QomtDatagramRouter {
  pub(crate) fn new() -> Arc<Self> {
    Arc::new(Self {
      active_socket: Mutex::new(None),
      next_socket_generation: AtomicU64::new(0),
      routes: Mutex::new(HashMap::new()),
      stats: QomtDatagramAtomicStats::default(),
    })
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

  pub(crate) async fn run(self: Arc<Self>, socket: QuicDatagramSocket) {
    let generation = self.next_socket_generation.fetch_add(1, Ordering::Relaxed);

    *self.active_socket.lock().unwrap() = Some(ActiveDatagramSocket {
      generation,
      socket: socket.clone(),
    });

    while let Some(datagram) = socket.recv().await {
      self.dispatch(datagram);
    }

    let mut active_socket = self.active_socket.lock().unwrap();
    if active_socket
      .as_ref()
      .is_some_and(|active| active.generation == generation)
    {
      *active_socket = None;
    }
  }

  pub(crate) fn max_payload_len(&self) -> Option<usize> {
    self
      .active_socket
      .lock()
      .unwrap()
      .as_ref()?
      .socket
      .max_writable_len()
      .and_then(|length| length.checked_sub(QOMT_DATAGRAM_ENVELOPE_SIZE))
  }

  pub(crate) fn path_metrics(&self) -> Option<QuicPathMetrics> {
    self
      .active_socket
      .lock()
      .unwrap()
      .as_ref()?
      .socket
      .path_metrics()
  }

  pub(crate) fn deactivate(&self) {
    *self.active_socket.lock().unwrap() = None;
  }

  pub(crate) fn try_send(&self, association_id: u64, payload: &[u8]) -> QomtDatagramSendOutcome {
    let socket = match self.active_socket.lock().unwrap().as_ref() {
      Some(active) => active.socket.clone(),
      None => return QomtDatagramSendOutcome::Unavailable,
    };

    let Some(max_payload_len) = socket
      .max_writable_len()
      .and_then(|length| length.checked_sub(QOMT_DATAGRAM_ENVELOPE_SIZE))
    else {
      return QomtDatagramSendOutcome::Unavailable;
    };

    if payload.len() > max_payload_len {
      return QomtDatagramSendOutcome::TooLarge;
    }

    let mut datagram = Vec::with_capacity(QOMT_DATAGRAM_ENVELOPE_SIZE + payload.len());
    datagram.push(QOMT_DATAGRAM_WIRE_VERSION);
    datagram.extend_from_slice(&association_id.to_be_bytes());
    datagram.extend_from_slice(payload);

    match socket.try_send(&datagram) {
      Ok(()) => {
        self.stats.sent.fetch_add(1, Ordering::Relaxed);
        QomtDatagramSendOutcome::Queued
      }
      Err(QuicDatagramSendError::Unavailable) => QomtDatagramSendOutcome::Unavailable,
      Err(QuicDatagramSendError::TooLarge { .. }) => QomtDatagramSendOutcome::TooLarge,
      Err(QuicDatagramSendError::QueueFull) => {
        self
          .stats
          .dropped_send_queue_full
          .fetch_add(1, Ordering::Relaxed);
        QomtDatagramSendOutcome::QueueFull
      }
      Err(error) => QomtDatagramSendOutcome::Failed(error),
    }
  }

  pub(crate) fn stats(&self) -> QomtDatagramStats {
    self.stats.snapshot()
  }

  #[cfg(test)]
  pub(crate) fn route_count(&self) -> usize {
    self.routes.lock().unwrap().len()
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
}
