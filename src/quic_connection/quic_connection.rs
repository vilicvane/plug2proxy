use std::{
  collections::HashMap,
  sync::{
    Arc, Mutex,
    atomic::{self, AtomicBool, AtomicU64, AtomicUsize},
  },
};

use colored::Colorize;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lits::bytes;
use lowkit::{DropCallback, SelfWrapExt, tokio_join_set};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, simplex},
  sync::{Notify, mpsc, watch},
  task::JoinSet,
  time::{Duration, sleep, sleep_until},
};

use crate::{
  constants::SERVER_COMMON_NAME,
  primitives::ConnectionSide,
  quic_connection::{MAX_DATAGRAM_SIZE, QuicBytesPacket, QuicStream, UNSPECIFIED_SOCKET_ADDRESS},
  utils::task::reap_finished_tasks,
};

const READ_WRITE_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

const SIMPLEX_MAX_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

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
  state_updater: Arc<StateUpdater>,
}

impl ConnectionSignals {
  fn new(state_updater: Arc<StateUpdater>) -> Self {
    Self {
      connection_send: Notify::new(),
      streams: Mutex::new(HashMap::new()),
      transport_closed: AtomicBool::new(false),
      driver_failed: AtomicBool::new(false),
      state_updater,
    }
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

pub struct QuicConnection {
  connection: Arc<Mutex<quiche::Connection>>,
  id: quiche::ConnectionId<'static>,
  next_stream_id_index: AtomicU64,
  side: ConnectionSide,
  state_updater: Arc<StateUpdater>,
  connection_signals: Arc<ConnectionSignals>,
  create_stream: Arc<dyn Fn(ConnectionSide, u64) -> QuicStream + Send + Sync>,
  stream_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<QuicStream>>,
  _join_set: JoinSet<()>,
}

impl QuicConnection {
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
      underlying_sink,
      underlying_stream,
    )
  }

  fn create<TSink, TStream>(
    connection: quiche::Connection,
    id: quiche::ConnectionId<'static>,
    side: ConnectionSide,
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

    let (stream_sender, stream_receiver) = mpsc::unbounded_channel();

    let create_stream = {
      let connection = connection.clone();
      let connection_signals = connection_signals.clone();
      let join_set = JoinSet::new().mutex().arc();

      move |side: ConnectionSide, id: u64| {
        log::debug!("{side} {id}: quic stream create");

        let (external_read, mut write) = simplex(SIMPLEX_MAX_BUFFER_SIZE);
        let (mut read, external_write) = simplex(SIMPLEX_MAX_BUFFER_SIZE);

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
              let read_result = tokio::select! {
                result = read.read(&mut buffer) => result,
                _ = connection_signals.state_updater.wait(State::Closed) => break,
              };

              match read_result {
                Ok(total_length) => {
                  log::debug!("{side} {id}: stream send read {total_length} bytes");

                  let mut offset = 0;

                  loop {
                    log::debug!("{side} {id}: stream send {offset}..{total_length}");

                    let stream_send_result = connection.lock().unwrap().stream_send(
                      id,
                      &buffer[offset..total_length],
                      total_length == 0,
                    );

                    match stream_send_result {
                      Ok(length) => {
                        stream_signals
                          .created
                          .store(true, atomic::Ordering::Release);
                        stream_signals.recv.notify_one();
                        connection_signals.connection_send.notify_one();

                        offset += length;

                        log::debug!(
                          "{side} {id}: {stream_send} {offset}/{total_length}",
                          stream_send = "stream send".on_green(),
                        );

                        if offset == total_length {
                          break;
                        }
                      }
                      Err(quiche::Error::Done) => {
                        log::debug!("{side} {id}: stream send done");

                        tokio::select! {
                          _ = stream_signals.send.notified() => {}
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

              if !stream_signals.created.load(atomic::Ordering::Acquire) {
                tokio::select! {
                  _ = stream_signals.recv.notified() => continue,
                  _ = connection_signals.state_updater.wait(State::Closed) => break,
                }
              }

              let stream_recv_result = {
                log::debug!(
                  "{side} {id}: {stream_recv}",
                  stream_recv = "stream recv".on_red()
                );

                let mut connection = connection.lock().unwrap();

                connection.stream_recv(id, &mut buffer)
              };

              match stream_recv_result {
                Ok((length, finished)) => {
                  connection_signals.connection_send.notify_one();

                  log::debug!("{side} {id}: stream recv {length} {finished}");

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
                    log::debug!("{side} {id}: stream recv done");

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
              log::debug!("{side} {send}", send = "send".green());

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

                  log::debug!("{side} send {packet_count} packets, {byte_count} bytes");

                  tokio::select! {
                    _ = sleep_until(send_info.at.into()) => {}
                    _ = state_updater.wait(State::Closed) => break,
                  }

                  let send_result = tokio::select! {
                    result = underlying_sink.send(buffer[..length].to_vec().into()) => Some(result),
                    _ = state_updater.wait(State::Closed) => None,
                  };

                  match send_result {
                    Some(Ok(())) => {}
                    Some(Err(error)) => {
                      log::warn!("error sending packet to underlying sink: {error}");
                      connection_signals.mark_transport_closed();
                      break;
                    }
                    None => break,
                  }
                }
                Err(quiche::Error::Done) => {
                  log::debug!("{side} send done");

                  let timeout_instant = connection.lock().unwrap().timeout_instant();

                  if let Some(timeout_instant) = timeout_instant {
                    tokio::select! {
                      _ = connection_signals.connection_send.notified() => {}
                      _ = sleep_until(timeout_instant.into()) => {
                        let mut connection = connection.lock().unwrap();
                        connection.on_timeout();
                        state_updater.update(&connection);
                      }
                      _ = state_updater.wait(State::Closed) => break,
                    }
                  } else {
                    tokio::select! {
                      _ = connection_signals.connection_send.notified() => {}
                      _ = state_updater.wait(State::Closed) => break,
                    }
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

            'recv_loop: loop {
              let mut packet = tokio::select! {
                packet = underlying_stream.next() => {
                  let Some(packet) = packet else {
                    connection_signals.mark_transport_closed();
                    break;
                  };

                  packet
                }
                _ = state_updater.wait(State::Closed) => break,
              };

              packet_count += 1;
              byte_count += packet.len();

              log::debug!("{side} underlying read {packet_count} packets, {byte_count} bytes");

              let recv_result = {
                log::debug!("{side} {} {}", "recv".red(), packet.len());

                let mut connection = connection.lock().unwrap();

                let result = connection.recv(&mut packet, receive_info);

                state_updater.update(&connection);

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

                  log::debug!("{side} recv ok");

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
                    log::debug!("{side} {id}: stream recv readable");

                    if let Some(signals) =
                      connection_signals.streams.lock().unwrap().get(&id).cloned()
                    {
                      signals.recv.notify_one();
                    } else {
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

        tokio_join_set!(send_loop, recv_loop, finished_stream_reconciliation_loop)
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
