use std::{
  collections::HashMap,
  sync::{
    Arc,
    atomic::{self, AtomicBool},
  },
  time::Instant,
};

use colored::Colorize;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lits::bytes;
use lowkit::{DropCallback, SelfWrapExt, tokio_join_set};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, simplex},
  sync::{Notify, mpsc},
  task::JoinSet,
  time::sleep_until,
};

use crate::{
  constants::SERVER_COMMON_NAME,
  mt_connections::MtBytesPacket,
  primitives::ConnectionSide,
  quic_connection::{MAX_DATAGRAM_SIZE, QuicStream, UNSPECIFIED_SOCKET_ADDRESS},
};

const READ_WRITE_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

const SIMPLEX_MAX_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

pub struct QuicConnection<'a> {
  id: quiche::ConnectionId<'a>,
  next_stream_id_index: u64,
  side: ConnectionSide,
  established: Arc<AtomicBool>,
  established_notify: Arc<Notify>,
  create_stream: Arc<dyn Fn(u64, bool) -> QuicStream>,
  stream_receiver: mpsc::UnboundedReceiver<QuicStream>,
  _join_set: JoinSet<()>,
}

impl<'a> QuicConnection<'a> {
  pub fn connect<TStream>(
    connection_id: &quiche::ConnectionId<'a>,
    quiche_config: &mut quiche::Config,
    underlying_stream: TStream,
  ) -> Self
  where
    TStream: Sink<MtBytesPacket> + Stream<Item = MtBytesPacket> + Unpin + Send + 'static,
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
    connection_id: &quiche::ConnectionId<'a>,
    quiche_config: &mut quiche::Config,
    underlying_sink: TSink,
    underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<MtBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = MtBytesPacket> + Unpin + Send + 'static,
  {
    let quiche_connection = quiche::connect(
      SERVER_COMMON_NAME.some(),
      connection_id,
      *UNSPECIFIED_SOCKET_ADDRESS,
      *UNSPECIFIED_SOCKET_ADDRESS,
      quiche_config,
    )
    .unwrap_or_else(|error| panic!("failed to connect to quiche connection: {}", error));

    Self::create(
      quiche_connection,
      connection_id.clone(),
      ConnectionSide::Client,
      underlying_sink,
      underlying_stream,
    )
  }

  pub fn accept<TStream>(
    connection_id: &quiche::ConnectionId<'a>,
    quiche_config: &mut quiche::Config,
    underlying_stream: TStream,
  ) -> Self
  where
    TStream: Sink<MtBytesPacket> + Stream<Item = MtBytesPacket> + Unpin + Send + 'static,
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
    connection_id: &quiche::ConnectionId<'a>,
    quiche_config: &mut quiche::Config,
    underlying_sink: TSink,
    underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<MtBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = MtBytesPacket> + Unpin + Send + 'static,
  {
    let quiche_connection = quiche::accept(
      connection_id,
      None,
      *UNSPECIFIED_SOCKET_ADDRESS,
      *UNSPECIFIED_SOCKET_ADDRESS,
      quiche_config,
    )
    .unwrap_or_else(|error| panic!("failed to accept quiche connection: {}", error));

    Self::create(
      quiche_connection,
      connection_id.clone(),
      ConnectionSide::Server,
      underlying_sink,
      underlying_stream,
    )
  }

  fn create<TSink, TStream>(
    quiche_connection: quiche::Connection,
    id: quiche::ConnectionId<'a>,
    side: ConnectionSide,
    mut underlying_sink: TSink,
    mut underlying_stream: TStream,
  ) -> Self
  where
    TSink: Sink<MtBytesPacket> + Unpin + Send + 'static,
    TSink::Error: std::fmt::Display,
    TStream: Stream<Item = MtBytesPacket> + Unpin + Send + 'static,
  {
    let quiche_connection = quiche_connection.mutex().arc();

    let established = AtomicBool::new(false).arc();
    let established_notify = Notify::new().arc();

    let quiche_stream_send_continue_notify = Notify::new().arc();
    let quiche_connection_send_continue_notify = Notify::new().arc();

    let quiche_stream_recv_continue_notify_map = HashMap::<u64, Arc<Notify>>::new().mutex().arc();

    let (stream_sender, stream_receiver) = mpsc::unbounded_channel();

    let create_stream = {
      let quiche_connection = quiche_connection.clone();
      let quiche_stream_send_continue_notify = quiche_stream_send_continue_notify.clone();
      let quiche_stream_recv_continue_notify_map = quiche_stream_recv_continue_notify_map.clone();
      let quiche_connection_send_continue_notify = quiche_connection_send_continue_notify.clone();
      let join_set = JoinSet::new().mutex().arc();

      move |id: u64, recv_immediately: bool| {
        log::debug!("{side} {id}: quic stream create");

        let (external_read, mut write) = simplex(SIMPLEX_MAX_BUFFER_SIZE);
        let (mut read, external_write) = simplex(SIMPLEX_MAX_BUFFER_SIZE);

        let quiche_stream_recv_continue_notify = Notify::new().arc();

        assert!(
          quiche_stream_recv_continue_notify_map
            .lock()
            .unwrap()
            .insert(id, quiche_stream_recv_continue_notify.clone())
            .is_none()
        );

        let mut join_set = join_set.lock().unwrap();

        // stream send loop
        join_set.spawn({
          let quiche_connection = quiche_connection.clone();
          let quiche_stream_send_continue_notify = quiche_stream_send_continue_notify.clone();
          let quiche_connection_send_continue_notify =
            quiche_connection_send_continue_notify.clone();

          async move {
            let mut buffer = [0; READ_WRITE_BUFFER_SIZE];

            'outer: loop {
              match read.read(&mut buffer).await {
                Ok(total_length) => {
                  log::debug!("{side} {id}: stream send read {total_length} bytes");

                  let mut offset = 0;

                  loop {
                    log::debug!("{side} {id}: stream send {offset}..{total_length}");

                    let stream_send_result = quiche_connection.lock().unwrap().stream_send(
                      id,
                      &buffer[offset..total_length],
                      total_length == 0,
                    );

                    match stream_send_result {
                      Ok(length) => {
                        quiche_connection_send_continue_notify.notify_waiters();

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

                        quiche_stream_send_continue_notify.notified().await;
                      }
                      Err(error) => {
                        log::warn!("error writing to quic stream: {error}");
                        break 'outer;
                      }
                    }
                  }

                  if total_length == 0 {
                    break;
                  }
                }
                Err(error) => {
                  log::warn!("error reading from quic stream: {error}");

                  loop {
                    let stream_send_result = quiche_connection.lock().unwrap().stream_shutdown(
                      id,
                      quiche::Shutdown::Write,
                      0,
                    );

                    match stream_send_result {
                      Ok(_) => {
                        break;
                      }
                      Err(error) => {
                        log::warn!("error shutting down quic stream: {error}");
                      }
                    }
                  }

                  break;
                }
              }
            }

            log::debug!("{side} {id}: stream send loop ended");
          }
        });

        // stream recv loop
        join_set.spawn({
          let quiche_connection = quiche_connection.clone();
          let quiche_connection_send_continue_notify =
            quiche_connection_send_continue_notify.clone();

          async move {
            let mut buffer = vec![0; READ_WRITE_BUFFER_SIZE];

            if !recv_immediately {
              quiche_stream_recv_continue_notify.notified().await;
            }

            loop {
              let stream_recv_result = {
                log::debug!(
                  "{side} {id}: {stream_recv}",
                  stream_recv = "stream recv".on_red()
                );

                let mut quiche_connection = quiche_connection.lock().unwrap();

                if quiche_connection.stream_finished(id) {
                  log::debug!("{side} {id}: stream recv break");
                  break;
                }

                quiche_connection.stream_recv(id, &mut buffer)
              };

              match stream_recv_result {
                Ok((length, finished)) => {
                  quiche_connection_send_continue_notify.notify_waiters();

                  log::debug!("{side} {id}: stream recv {length} {finished}");

                  if length > 0 {
                    if write
                      .write_all(&buffer[..length])
                      .await
                      .inspect_err(|error| {
                        log::warn!("error writing packet to stream: {}", error);
                      })
                      .is_err()
                    {
                      break;
                    }
                  }

                  if finished {
                    write
                      .shutdown()
                      .await
                      .inspect_err(|error| {
                        log::warn!("error shutting down stream: {}", error);
                      })
                      .ok();

                    break;
                  }
                }
                Err(quiche::Error::Done) => {
                  log::debug!("{side} {id}: stream recv done");

                  quiche_stream_recv_continue_notify.notified().await;
                }
                Err(error) => {
                  log::warn!("error receiving packet from quiche stream: {}", error);
                  break;
                }
              }
            }

            log::debug!("{side} {id}: stream recv loop ended");
          }
        });

        let drop_callback = DropCallback::new({
          let quiche_stream_recv_continue_notify_map =
            quiche_stream_recv_continue_notify_map.clone();

          Box::new(move || {
            quiche_stream_recv_continue_notify_map
              .lock()
              .unwrap()
              .remove(&id);
          }) as Box<dyn Fn() + Send>
        });

        QuicStream::new(external_read, external_write, drop_callback)
      }
    }
    .arc();

    Self {
      id,
      side,
      established: established.clone(),
      established_notify: established_notify.clone(),
      create_stream: create_stream.clone(),
      next_stream_id_index: 0,
      stream_receiver,
      _join_set: {
        let (timeout_sender, mut timeout_receiver) = mpsc::channel::<Instant>(1);

        let timeout_loop = {
          let quiche_connection = quiche_connection.clone();
          let quiche_connection_send_continue_notify =
            quiche_connection_send_continue_notify.clone();

          async move {
            'no_active_timeout_loop: loop {
              let Some(mut last_timeout_instant) = timeout_receiver.recv().await else {
                break 'no_active_timeout_loop;
              };

              'active_timeout_loop: loop {
                tokio::select! {
                  timeout_instant = timeout_receiver.recv() => {
                    let Some(timeout_instant) = timeout_instant else {
                      break 'no_active_timeout_loop;
                    };

                    last_timeout_instant = timeout_instant;
                  }
                  _ = sleep_until(last_timeout_instant.into()) => {
                    quiche_connection.lock().unwrap().on_timeout();
                    quiche_connection_send_continue_notify.notify_waiters();
                    break 'active_timeout_loop;
                  }
                }
              }
            }
          }
        };

        let send_loop = {
          let quiche_connection = quiche_connection.clone();
          let quiche_connection_send_continue_notify =
            quiche_connection_send_continue_notify.clone();

          async move {
            let mut buffer = [0; MAX_DATAGRAM_SIZE];

            let mut packet_count = 0;
            let mut byte_count = 0;

            loop {
              log::debug!("{side} {send}", send = "send".green());

              let send_result = quiche_connection.lock().unwrap().send(&mut buffer);

              quiche_stream_send_continue_notify.notify_waiters();

              match send_result {
                Ok((length, _)) => {
                  packet_count += 1;
                  byte_count += length;

                  log::debug!("{side} send {packet_count} packets, {byte_count} bytes");

                  if underlying_sink
                    .send(buffer[..length].to_vec().into())
                    .await
                    .inspect_err(|error| {
                      log::warn!("error sending packet to underlying sink: {}", error)
                    })
                    .is_err()
                  {
                    break;
                  }
                }
                Err(quiche::Error::Done) => {
                  log::debug!("{side} send done");

                  let timeout_instant = quiche_connection.lock().unwrap().timeout_instant();

                  if let Some(timeout_instant) = timeout_instant {
                    if timeout_sender.send(timeout_instant).await.is_err() {
                      break;
                    }
                  }

                  quiche_connection_send_continue_notify.notified().await;
                }
                Err(error) => {
                  log::warn!("error sending packet to quiche connection: {}", error);
                  break;
                }
              }
            }

            log::debug!("{side} send loop ended");
          }
        };

        let recv_loop = {
          async move {
            // Read from the underlying multiple TCP connections.

            let receive_info: quiche::RecvInfo = quiche::RecvInfo {
              from: *UNSPECIFIED_SOCKET_ADDRESS,
              to: *UNSPECIFIED_SOCKET_ADDRESS,
            };

            let mut packet_count = 0;
            let mut byte_count = 0;

            'recv_loop: while let Some(mut packet) = underlying_stream.next().await {
              packet_count += 1;
              byte_count += packet.len();

              log::debug!("{side} underlying read {packet_count} packets, {byte_count} bytes");

              let recv_result = {
                log::debug!("{side} {} {}", "recv".red(), packet.len());

                let mut quiche_connection = quiche_connection.lock().unwrap();

                let result = quiche_connection.recv(&mut packet, receive_info);

                if quiche_connection.is_established()
                  && !established.load(atomic::Ordering::Relaxed)
                {
                  established.store(true, atomic::Ordering::Relaxed);
                  established_notify.notify_waiters();
                }

                result
              };

              match recv_result {
                Ok(_) => {
                  log::debug!("{side} recv ok");

                  // Source code suggests that recv always return the length of the packet if Ok.

                  quiche_connection_send_continue_notify.notify_waiters();

                  let readable = quiche_connection.lock().unwrap().readable();

                  for id in readable {
                    log::debug!("{side} {id}: stream recv readable");

                    if let Some(notify) = quiche_stream_recv_continue_notify_map
                      .lock()
                      .unwrap()
                      .get(&id)
                    {
                      notify.notify_waiters();
                    } else {
                      let stream = create_stream(id, true);

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
                  break 'recv_loop;
                }
              }
            }

            log::debug!("{side} recv loop ended");
          }
        };

        tokio_join_set!(timeout_loop, send_loop, recv_loop)
      },
    }
  }

  pub fn generate_connection_id() -> quiche::ConnectionId<'a> {
    quiche::ConnectionId::from_vec(rand::random::<[u8; 20]>().to_vec())
  }

  pub fn is_established(&self) -> bool {
    self.established.load(atomic::Ordering::Relaxed)
  }

  pub async fn established(&self) {
    if self.is_established() {
      return;
    }

    self.established_notify.notified().await;
  }

  pub fn id(&self) -> &quiche::ConnectionId<'a> {
    &self.id
  }

  pub async fn accept_stream(&mut self) -> Option<QuicStream> {
    self.stream_receiver.recv().await
  }

  pub fn open_stream(&mut self) -> QuicStream {
    let stream_id = self.next_stream_id_index << 2 | self.side.stream_id_bits();

    self.next_stream_id_index += 1;

    (self.create_stream)(stream_id, false)
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

#[derive(thiserror::Error, Debug)]
pub enum QuicConnectionError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}
