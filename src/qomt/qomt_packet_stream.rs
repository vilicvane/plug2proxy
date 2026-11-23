use std::{
  future::Future,
  marker::PhantomData,
  pin::Pin,
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  task::{Context, Poll},
};

use futures::{Sink, Stream};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  sync::{mpsc, oneshot, watch},
  task::JoinSet,
  time::timeout,
};

use super::{QomtConnection, QomtDatagramRegistration, QomtDatagramSendOutcome, QomtStream};
use crate::{
  mt_connections::MT_CONNECTIONS_HANDSHAKE_TIMEOUT, quic_connection::MAX_DATAGRAM_SIZE,
  udp_forwarder::UdpPacketStreamError,
};

const QOMT_PACKET_STREAM_READY: &[u8; 4] = b"QPS1";
const QOMT_RELIABLE_PACKET_QUEUE_CAPACITY: usize = 1024;
const QOMT_INCOMING_PACKET_QUEUE_CAPACITY: usize = 1024;
const QOMT_RELIABLE_WRITE_BATCH_BYTES: usize = 16 * 1024;
// Preserve the existing UdpPacketStream logical frame limit. The real UDP
// DATAGRAM limit is lower and dynamic; packets exceeding MTU or hitting UDP
// QoS bottlenecks fall back cleanly to the reliable mTCP lane.
const MAX_QOMT_PACKET_FRAME_SIZE: usize = MAX_DATAGRAM_SIZE;
const MAX_MALFORMED_DATAGRAMS_PER_POLL: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QomtPacketDelivery {
  Reliable,
  BestEffort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QomtPacketDropReason {
  UdpQueueFull,
  ReliableFallbackQueueFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QomtPacketSendOutcome {
  ReliableQueued,
  DatagramQueued,
  Dropped(QomtPacketDropReason),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QomtPacketStreamStats {
  pub reliable_queued: u64,
  pub datagram_queued: u64,
  pub dropped_udp_queue_full: u64,
  pub dropped_reliable_queue_full: u64,
  pub received_reliable: u64,
  pub received_datagram: u64,
  pub dropped_incoming_datagram_queue_full: u64,
  pub dropped_malformed_datagram: u64,
}

#[derive(Default)]
struct AtomicPacketStreamStats {
  reliable_queued: AtomicU64,
  datagram_queued: AtomicU64,
  dropped_udp_queue_full: AtomicU64,
  dropped_reliable_queue_full: AtomicU64,
  received_reliable: AtomicU64,
  received_datagram: AtomicU64,
  dropped_incoming_datagram_queue_full: AtomicU64,
  dropped_malformed_datagram: AtomicU64,
}

impl AtomicPacketStreamStats {
  fn snapshot(&self) -> QomtPacketStreamStats {
    QomtPacketStreamStats {
      reliable_queued: self.reliable_queued.load(Ordering::Relaxed),
      datagram_queued: self.datagram_queued.load(Ordering::Relaxed),
      dropped_udp_queue_full: self.dropped_udp_queue_full.load(Ordering::Relaxed),
      dropped_reliable_queue_full: self.dropped_reliable_queue_full.load(Ordering::Relaxed),
      received_reliable: self.received_reliable.load(Ordering::Relaxed),
      received_datagram: self.received_datagram.load(Ordering::Relaxed),
      dropped_incoming_datagram_queue_full: self
        .dropped_incoming_datagram_queue_full
        .load(Ordering::Relaxed),
      dropped_malformed_datagram: self.dropped_malformed_datagram.load(Ordering::Relaxed),
    }
  }
}

#[derive(Clone, Copy)]
enum IncomingLane {
  Reliable,
  Datagram,
}

struct IncomingPacket {
  lane: IncomingLane,
  encoded: Vec<u8>,
}

struct ReliableFrame {
  encoded: Vec<u8>,
  completion: Option<oneshot::Sender<Result<(), std::io::Error>>>,
}

enum ReliableCommand {
  Frame(ReliableFrame),
  Close(oneshot::Sender<Result<(), std::io::Error>>),
}

enum ReliableCloseState {
  Open,
  Enqueueing {
    future:
      Pin<Box<dyn Future<Output = Result<(), flume::SendError<ReliableCommand>>> + Send + 'static>>,
    completion: Option<oneshot::Receiver<Result<(), std::io::Error>>>,
  },
  Waiting(oneshot::Receiver<Result<(), std::io::Error>>),
  Closed,
}

/// Association-scoped packet transport.
///
/// The reliable lane is one main QomT stream. The optional best-effort lane
/// is a handle registered with the connection-level UDP DATAGRAM router; the
/// underlying UDP QUIC connection remains exclusively owned by
/// [`QomtConnection`].
pub struct QomtPacketStream<TSend: 'static, TReceive: 'static> {
  connection: Arc<QomtConnection>,
  association_id: u64,
  reliable_sender: Option<flume::Sender<ReliableCommand>>,
  reliable_close_state: ReliableCloseState,
  send_closed: Arc<AtomicBool>,
  incoming_receiver: mpsc::Receiver<IncomingPacket>,
  close_sender: watch::Sender<bool>,
  datagram_registration: Arc<Mutex<Option<QomtDatagramRegistration>>>,
  stats: Arc<AtomicPacketStreamStats>,
  read_closed: bool,
  _join_set: JoinSet<()>,
  packet_types: PhantomData<fn(TSend, TReceive)>,
}

impl<TSend, TReceive> QomtPacketStream<TSend, TReceive>
where
  TSend: Serialize + Send + 'static,
  TReceive: DeserializeOwned + Send + 'static,
{
  pub async fn connect(
    connection: Arc<QomtConnection>,
    mut stream: QomtStream,
  ) -> Result<Self, UdpPacketStreamError> {
    if stream.is_udp_bypass() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "QomT packet stream control must use a main connection stream",
        )
        .into(),
      );
    }
    let association_id = stream.id();
    let (registration, datagram_receiver) =
      connection.register_datagram_association(association_id)?;

    let mut ready = [0; QOMT_PACKET_STREAM_READY.len()];
    timeout(
      MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
      stream.read_exact(&mut ready),
    )
    .await
    .map_err(|_| {
      std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out waiting for QomT packet stream ready acknowledgement",
      )
    })??;

    if &ready != QOMT_PACKET_STREAM_READY {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          "invalid QomT packet stream ready acknowledgement",
        )
        .into(),
      );
    }

    Ok(Self::new(
      connection,
      stream,
      association_id,
      registration,
      datagram_receiver,
    ))
  }

  pub async fn accept(
    connection: Arc<QomtConnection>,
    mut stream: QomtStream,
  ) -> Result<Self, UdpPacketStreamError> {
    if stream.is_udp_bypass() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "QomT packet stream control must use a main connection stream",
        )
        .into(),
      );
    }
    let association_id = stream.id();
    let (registration, datagram_receiver) =
      connection.register_datagram_association(association_id)?;

    // Register before acknowledging readiness so a DATAGRAM sent immediately
    // after the ACK can never overtake route installation.
    stream.write_all(QOMT_PACKET_STREAM_READY).await?;
    stream.flush().await?;

    Ok(Self::new(
      connection,
      stream,
      association_id,
      registration,
      datagram_receiver,
    ))
  }

  fn new(
    connection: Arc<QomtConnection>,
    stream: QomtStream,
    association_id: u64,
    registration: QomtDatagramRegistration,
    mut datagram_receiver: mpsc::Receiver<Vec<u8>>,
  ) -> Self {
    let (mut reliable_read, mut reliable_write) = tokio::io::split(stream);
    let (reliable_sender, reliable_receiver) =
      flume::bounded::<ReliableCommand>(QOMT_RELIABLE_PACKET_QUEUE_CAPACITY);
    let (incoming_sender, incoming_receiver) =
      mpsc::channel::<IncomingPacket>(QOMT_INCOMING_PACKET_QUEUE_CAPACITY);
    let (close_sender, close_receiver) = watch::channel(false);
    let send_closed = Arc::new(AtomicBool::new(false));
    let datagram_registration = Arc::new(Mutex::new(Some(registration)));
    let stats = Arc::new(AtomicPacketStreamStats::default());

    let reliable_writer = {
      let close_sender = close_sender.clone();
      let mut close_receiver = close_receiver.clone();
      let send_closed = send_closed.clone();
      let datagram_registration = datagram_registration.clone();

      async move {
        let mut terminal = true;
        let mut write_buf = Vec::with_capacity(QOMT_RELIABLE_WRITE_BATCH_BYTES);
        let mut completions = Vec::new();

        loop {
          let command = tokio::select! {
            command = reliable_receiver.recv_async() => match command {
              Ok(command) => command,
              Err(_) => {
                reliable_write.shutdown().await.ok();
                break;
              }
            },
            changed = close_receiver.changed() => {
              if changed.is_err() || *close_receiver.borrow() {
                break;
              }
              continue;
            }
          };

          let frame = match command {
            ReliableCommand::Frame(frame) => frame,
            ReliableCommand::Close(completion) => {
              let result = reliable_write.shutdown().await;
              terminal = result.is_err();
              if terminal {
                close_sender.send(true).ok();
              }
              completion.send(result).ok();
              break;
            }
          };

          write_buf.clear();
          completions.clear();
          write_buf.extend_from_slice(&(frame.encoded.len() as u32).to_be_bytes());
          write_buf.extend_from_slice(&frame.encoded);
          if let Some(completion) = frame.completion {
            completions.push(completion);
          }

          let mut pending_close = None;
          while write_buf.len() < QOMT_RELIABLE_WRITE_BATCH_BYTES {
            match reliable_receiver.try_recv() {
              Ok(ReliableCommand::Frame(next)) => {
                write_buf.extend_from_slice(&(next.encoded.len() as u32).to_be_bytes());
                write_buf.extend_from_slice(&next.encoded);
                if let Some(completion) = next.completion {
                  completions.push(completion);
                }
              }
              Ok(ReliableCommand::Close(close_tx)) => {
                pending_close = Some(close_tx);
                break;
              }
              Err(_) => break,
            }
          }

          match reliable_write.write_all(&write_buf).await {
            Ok(()) => {
              for completion in completions.drain(..) {
                completion.send(Ok(())).ok();
              }
              if let Some(close_tx) = pending_close {
                let result = reliable_write.shutdown().await;
                terminal = result.is_err();
                if terminal {
                  close_sender.send(true).ok();
                }
                close_tx.send(result).ok();
                break;
              }
            }
            Err(error) => {
              log::debug!("QomT reliable packet writer stopped: {error}");
              let kind = error.kind();
              let message = error.to_string();
              for completion in completions.drain(..) {
                completion
                  .send(Err(std::io::Error::new(kind, message.clone())))
                  .ok();
              }
              if let Some(close_tx) = pending_close {
                close_tx.send(Err(error)).ok();
              }
              close_sender.send(true).ok();
              break;
            }
          }
        }

        send_closed.store(true, Ordering::Release);
        if terminal {
          datagram_registration.lock().unwrap().take();
        }
      }
    };

    let reliable_reader = {
      let incoming_sender = incoming_sender.clone();
      let close_sender = close_sender.clone();
      let mut close_receiver = close_receiver.clone();
      let send_closed = send_closed.clone();
      let datagram_registration = datagram_registration.clone();

      async move {
        loop {
          let frame = tokio::select! {
            result = async {
              let mut length_bytes = [0; size_of::<u32>()];
              if reliable_read.read(&mut length_bytes[..1]).await? == 0 {
                return Ok(None);
              }
              reliable_read.read_exact(&mut length_bytes[1..]).await?;

              let length = u32::from_be_bytes(length_bytes) as usize;
              if length > MAX_QOMT_PACKET_FRAME_SIZE {
                return Err(std::io::Error::new(
                  std::io::ErrorKind::InvalidData,
                  format!("QomT reliable packet frame is too large: {length}"),
                ));
              }

              let mut encoded = vec![0; length];
              reliable_read.read_exact(&mut encoded).await?;
              Ok(Some(encoded))
            } => result,
            changed = close_receiver.changed() => {
              if changed.is_err() || *close_receiver.borrow() {
                break;
              }
              continue;
            }
          };

          let encoded = match frame {
            Ok(Some(encoded)) => encoded,
            Ok(None) => break,
            Err(error) => {
              log::debug!("QomT reliable packet reader stopped: {error}");
              break;
            }
          };

          let incoming = IncomingPacket {
            lane: IncomingLane::Reliable,
            encoded,
          };
          tokio::select! {
            result = incoming_sender.send(incoming) => {
              if result.is_err() {
                break;
              }
            }
            changed = close_receiver.changed() => {
              if changed.is_err() || *close_receiver.borrow() {
                break;
              }
            }
          }
        }

        send_closed.store(true, Ordering::Release);
        datagram_registration.lock().unwrap().take();
        close_sender.send(true).ok();
      }
    };

    let datagram_reader = {
      let incoming_sender = incoming_sender.clone();
      let mut close_receiver = close_receiver.clone();
      let stats = stats.clone();

      async move {
        loop {
          let encoded = tokio::select! {
            encoded = datagram_receiver.recv() => match encoded {
              Some(encoded) => encoded,
              None => break,
            },
            changed = close_receiver.changed() => {
              if changed.is_err() || *close_receiver.borrow() {
                break;
              }
              continue;
            }
          };

          match incoming_sender.try_send(IncomingPacket {
            lane: IncomingLane::Datagram,
            encoded,
          }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
              stats
                .dropped_incoming_datagram_queue_full
                .fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => break,
          }
        }
      }
    };

    let mut join_set = JoinSet::new();
    join_set.spawn(reliable_writer);
    join_set.spawn(reliable_reader);
    join_set.spawn(datagram_reader);

    Self {
      connection,
      association_id,
      reliable_sender: Some(reliable_sender),
      reliable_close_state: ReliableCloseState::Open,
      send_closed,
      incoming_receiver,
      close_sender,
      datagram_registration,
      stats,
      read_closed: false,
      _join_set: join_set,
      packet_types: PhantomData,
    }
  }

  pub fn association_id(&self) -> u64 {
    self.association_id
  }

  pub fn stats(&self) -> QomtPacketStreamStats {
    self.stats.snapshot()
  }

  pub async fn send_packet(
    &mut self,
    packet: TSend,
    delivery: QomtPacketDelivery,
  ) -> Result<QomtPacketSendOutcome, UdpPacketStreamError> {
    if self.is_send_closed() {
      return Err(UdpPacketStreamError::Closed);
    }

    let encoded = Self::encode(packet)?;

    match delivery {
      QomtPacketDelivery::Reliable => {
        let Some(sender) = &self.reliable_sender else {
          return Err(UdpPacketStreamError::Closed);
        };

        let (completion_sender, completion_receiver) = oneshot::channel();

        sender
          .send_async(ReliableCommand::Frame(ReliableFrame {
            encoded,
            completion: Some(completion_sender),
          }))
          .await
          .map_err(|_| UdpPacketStreamError::Closed)?;
        self.stats.reliable_queued.fetch_add(1, Ordering::Relaxed);
        completion_receiver
          .await
          .map_err(|_| UdpPacketStreamError::Closed)??;
        Ok(QomtPacketSendOutcome::ReliableQueued)
      }
      QomtPacketDelivery::BestEffort => self.send_best_effort(encoded),
    }
  }

  fn encode(packet: TSend) -> Result<Vec<u8>, UdpPacketStreamError> {
    let encoded = postcard::to_allocvec(&packet)?;

    if encoded.len() > MAX_QOMT_PACKET_FRAME_SIZE {
      return Err(UdpPacketStreamError::FrameTooLarge(encoded.len()));
    }

    Ok(encoded)
  }

  fn send_best_effort(
    &mut self,
    encoded: Vec<u8>,
  ) -> Result<QomtPacketSendOutcome, UdpPacketStreamError> {
    if self.is_send_closed() {
      return Err(UdpPacketStreamError::Closed);
    }

    match self
      .connection
      .try_send_association_datagram(self.association_id, &encoded)
    {
      QomtDatagramSendOutcome::Queued => {
        self.stats.datagram_queued.fetch_add(1, Ordering::Relaxed);
        return Ok(QomtPacketSendOutcome::DatagramQueued);
      }
      QomtDatagramSendOutcome::Unavailable
      | QomtDatagramSendOutcome::TooLarge
      | QomtDatagramSendOutcome::Bottlenecked => {}
      QomtDatagramSendOutcome::QueueFull => {
        self
          .stats
          .dropped_udp_queue_full
          .fetch_add(1, Ordering::Relaxed);
      }
      QomtDatagramSendOutcome::Failed(error) => {
        log::debug!("QomT UDP DATAGRAM send failed, falling back to reliable lane: {error}");
      }
    }

    let Some(sender) = &self.reliable_sender else {
      return Err(UdpPacketStreamError::Closed);
    };

    match sender.try_send(ReliableCommand::Frame(ReliableFrame {
      encoded,
      completion: None,
    })) {
      Ok(()) => {
        self.stats.reliable_queued.fetch_add(1, Ordering::Relaxed);
        Ok(QomtPacketSendOutcome::ReliableQueued)
      }
      Err(flume::TrySendError::Full(_)) => {
        self
          .stats
          .dropped_reliable_queue_full
          .fetch_add(1, Ordering::Relaxed);
        Ok(QomtPacketSendOutcome::Dropped(
          QomtPacketDropReason::ReliableFallbackQueueFull,
        ))
      }
      Err(flume::TrySendError::Disconnected(_)) => Err(UdpPacketStreamError::Closed),
    }
  }

  fn is_send_closed(&self) -> bool {
    self.send_closed.load(Ordering::Acquire)
      || !matches!(&self.reliable_close_state, ReliableCloseState::Open)
      || self
        .reliable_sender
        .as_ref()
        .is_none_or(flume::Sender::is_disconnected)
  }
}

impl<TSend, TReceive> Sink<TSend> for QomtPacketStream<TSend, TReceive>
where
  TSend: Serialize + Send + 'static,
  TReceive: DeserializeOwned + Send + 'static,
{
  type Error = UdpPacketStreamError;

  fn poll_ready(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    let this = self.get_mut();
    if this.is_send_closed() {
      Poll::Ready(Err(UdpPacketStreamError::Closed))
    } else {
      Poll::Ready(Ok(()))
    }
  }

  fn start_send(self: Pin<&mut Self>, packet: TSend) -> Result<(), Self::Error> {
    let this = self.get_mut();
    let encoded = Self::encode(packet)?;
    this.send_best_effort(encoded)?;
    Ok(())
  }

  fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    // Sink<T> is the compatibility surface for BestEffort packets. A frame is
    // considered flushed once it has been routed to UDP or accepted by the
    // bounded reliable fallback queue; waiting for the main stream here would
    // reintroduce head-of-line blocking into the path selector. Call
    // send_packet(..., Reliable) when write completion is required.
    Poll::Ready(Ok(()))
  }

  fn poll_close(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    let this = self.as_mut().get_mut();

    loop {
      match &mut this.reliable_close_state {
        ReliableCloseState::Open => {
          this.send_closed.store(true, Ordering::Release);
          let Some(sender) = this.reliable_sender.take() else {
            this.reliable_close_state = ReliableCloseState::Closed;
            return Poll::Ready(Ok(()));
          };
          let (completion_sender, completion_receiver) = oneshot::channel();
          this.reliable_close_state = ReliableCloseState::Enqueueing {
            future: Box::pin(sender.into_send_async(ReliableCommand::Close(completion_sender))),
            completion: Some(completion_receiver),
          };
        }
        ReliableCloseState::Enqueueing { future, completion } => {
          match future.as_mut().poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => {
              this.reliable_close_state = ReliableCloseState::Closed;
              return Poll::Ready(Err(UdpPacketStreamError::Closed));
            }
            Poll::Ready(Ok(())) => {
              let completion = completion.take().unwrap();
              this.reliable_close_state = ReliableCloseState::Waiting(completion);
            }
          }
        }
        ReliableCloseState::Waiting(completion) => match Pin::new(completion).poll(context) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Ok(Ok(()))) => {
            this.reliable_close_state = ReliableCloseState::Closed;
            return Poll::Ready(Ok(()));
          }
          Poll::Ready(Ok(Err(error))) => {
            this.reliable_close_state = ReliableCloseState::Closed;
            return Poll::Ready(Err(error.into()));
          }
          Poll::Ready(Err(_)) => {
            this.reliable_close_state = ReliableCloseState::Closed;
            return Poll::Ready(Err(UdpPacketStreamError::Closed));
          }
        },
        ReliableCloseState::Closed => return Poll::Ready(Ok(())),
      }
    }
  }
}

impl<TSend, TReceive> Stream for QomtPacketStream<TSend, TReceive>
where
  TSend: Serialize + Send + 'static,
  TReceive: DeserializeOwned + Send + 'static,
{
  type Item = TReceive;

  fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    if self.read_closed {
      return Poll::Ready(None);
    }

    for _ in 0..MAX_MALFORMED_DATAGRAMS_PER_POLL {
      let incoming = match self.incoming_receiver.poll_recv(context) {
        Poll::Ready(Some(incoming)) => incoming,
        Poll::Ready(None) => {
          self.read_closed = true;
          return Poll::Ready(None);
        }
        Poll::Pending => return Poll::Pending,
      };

      match postcard::from_bytes(&incoming.encoded) {
        Ok(packet) => {
          match incoming.lane {
            IncomingLane::Reliable => {
              self.stats.received_reliable.fetch_add(1, Ordering::Relaxed);
            }
            IncomingLane::Datagram => {
              self.stats.received_datagram.fetch_add(1, Ordering::Relaxed);
            }
          }
          return Poll::Ready(Some(packet));
        }
        Err(error) => match incoming.lane {
          IncomingLane::Reliable => {
            log::debug!("QomT reliable packet decode failed: {error}");
            self.send_closed.store(true, Ordering::Release);
            self.datagram_registration.lock().unwrap().take();
            self.close_sender.send(true).ok();
            self.read_closed = true;
            return Poll::Ready(None);
          }
          IncomingLane::Datagram => {
            self
              .stats
              .dropped_malformed_datagram
              .fetch_add(1, Ordering::Relaxed);
            log::trace!("dropping malformed QomT DATAGRAM payload: {error}");
          }
        },
      }
    }

    context.waker().wake_by_ref();
    Poll::Pending
  }
}

impl<TSend: 'static, TReceive: 'static> Drop for QomtPacketStream<TSend, TReceive> {
  fn drop(&mut self) {
    // JoinSet cancellation may be observed asynchronously by its tasks; drop
    // the route synchronously so a stale association ID cannot receive a
    // datagram after the public packet stream has gone away.
    self.datagram_registration.lock().unwrap().take();
  }
}
