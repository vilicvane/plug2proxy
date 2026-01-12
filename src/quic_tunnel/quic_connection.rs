use std::{
  collections::HashMap,
  sync::{
    Arc,
    atomic::{self, AtomicBool},
  },
};

use colored::Colorize;
use futures::{Sink, SinkExt, Stream, StreamExt};
use lits::bytes;
use lowkit::{DropCallback, SelfWrapExt, tokio_join_set};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, SimplexStream, WriteHalf, simplex},
  spawn,
  sync::{Notify, mpsc},
  task::JoinSet,
  time::sleep_until,
};

use crate::{
  constants::SERVER_COMMON_NAME,
  mt_connections::MtBytesPacket,
  quic_tunnel::{MAX_DATAGRAM_SIZE, QuicStream, UNSPECIFIED_SOCKET_ADDRESS},
};

const READ_WRITE_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

const SIMPLEX_MAX_BUFFER_SIZE: usize = bytes!("8 KiB") as usize;

// TODO:
// - stream drop should release related resources.
// - rename to QuicConnection.

// recv loop
//   - read from transport -> recv()
//     - NOTIFY to send (ack)
//   - readable() + stream_recv()
//     - ASYNC
//       - write to quic stream
//       - NOTIFY to send (flow control)
// send loop
//   - send()
//   - timeout()
//     - ASYNC
//       - on_timeout()
//       - NOTIFY to send (?)
// external
//   - write to quic stream -> stream_send()
//   - NOTIFY to send (data)

pub struct QuicConnection<'a> {
  id: quiche::ConnectionId<'a>,
  next_stream_id_index: u64,
  side: QuicConnectionSide,
  established: Arc<AtomicBool>,
  established_notify: Arc<Notify>,
  create_stream: Arc<
    dyn Fn(
      u64,
    ) -> (
      QuicStream,
      Arc<tokio::sync::Mutex<WriteHalf<SimplexStream>>>,
    ),
  >,
  stream_receiver: mpsc::UnboundedReceiver<QuicStream>,
  _task_set: JoinSet<()>,
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
      QuicConnectionSide::Client,
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
      QuicConnectionSide::Server,
      underlying_sink,
      underlying_stream,
    )
  }

  fn create<TSink, TStream>(
    quiche_connection: quiche::Connection,
    id: quiche::ConnectionId<'a>,
    side: QuicConnectionSide,
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

    let (stream_sender, stream_receiver) = mpsc::unbounded_channel();

    let stream_write_map = HashMap::<u64, Arc<tokio::sync::Mutex<_>>>::new()
      .mutex()
      .arc();

    let create_stream = {
      let quiche_connection = quiche_connection.clone();
      let quiche_stream_send_continue_notify = quiche_stream_send_continue_notify.clone();
      let quiche_connection_send_continue_notify = quiche_connection_send_continue_notify.clone();
      let stream_write_map = stream_write_map.clone();
      let task_set = JoinSet::new().mutex().arc();

      move |id: u64| {
        log::debug!("{side:?} {id}: quic stream create");

        let (external_read, write) = simplex(SIMPLEX_MAX_BUFFER_SIZE);
        let (mut read, external_write) = simplex(SIMPLEX_MAX_BUFFER_SIZE);

        task_set.lock().unwrap().spawn({
          let quiche_connection = quiche_connection.clone();
          let quiche_stream_send_continue_notify = quiche_stream_send_continue_notify.clone();
          let quiche_connection_send_continue_notify =
            quiche_connection_send_continue_notify.clone();

          async move {
            let mut buffer = [0; READ_WRITE_BUFFER_SIZE];

            'outer: while let Ok(total_length) = read.read(&mut buffer).await {
              log::debug!("{side:?} {id}: stream send read {total_length} bytes");

              if total_length > 0 {
                let mut offset = 0;

                while offset < total_length {
                  log::debug!("{side:?} {id}: stream send {offset}..{total_length}");

                  let stream_send_result = quiche_connection.lock().unwrap().stream_send(
                    id,
                    &buffer[offset..total_length],
                    false,
                  );

                  quiche_connection_send_continue_notify.notify_waiters();

                  match stream_send_result {
                    Ok(length) => {
                      assert_ne!(length, 0);

                      offset += length;

                      log::debug!(
                        "{side:?} {id}: {stream_send} {offset}/{total_length}",
                        stream_send = "stream send".on_green(),
                      );
                    }
                    Err(quiche::Error::Done) => {
                      log::debug!("{side:?} {id}: quiche stream send done");

                      quiche_stream_send_continue_notify.notified().await;
                    }
                    Err(error) => {
                      log::warn!("error sending packet to quiche stream: {}", error);
                      break 'outer;
                    }
                  }
                }
              } else {
                let stream_send_result =
                  quiche_connection.lock().unwrap().stream_send(id, &[], true);

                match stream_send_result {
                  Ok(_) => {
                    log::debug!(
                      "{side:?} {id}: {stream_send} finished",
                      stream_send = "stream send".on_green()
                    );

                    break;
                  }
                  Err(quiche::Error::Done) => {
                    quiche_stream_send_continue_notify.notified().await;
                  }
                  Err(error) => {
                    log::warn!(
                      "error sending packet (finished) to quiche stream: {}",
                      error
                    );
                    break;
                  }
                }
              }
            }

            log::debug!("{side:?} {id}: quic stream read finished");
          }
        });

        let write = write.tokio_mutex().arc();

        stream_write_map.lock().unwrap().insert(id, write.clone());

        let drop_callback = DropCallback::new({
          let stream_write_map = stream_write_map.clone();

          Box::new(move || {
            stream_write_map.lock().unwrap().remove(&id);
          }) as Box<dyn Fn() + Send>
        });

        (
          QuicStream::new(external_read, external_write, drop_callback),
          write,
        )
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
      _task_set: {
        let quiche_connection_recv_future = {
          let quiche_connection = quiche_connection.clone();
          let quiche_connection_send_continue_notify =
            quiche_connection_send_continue_notify.clone();

          async move {
            // Read from the underlying multiple TCP connections.

            let receive_info: quiche::RecvInfo = quiche::RecvInfo {
              from: *UNSPECIFIED_SOCKET_ADDRESS,
              to: *UNSPECIFIED_SOCKET_ADDRESS,
            };

            let mut stream_recv_join_set = JoinSet::new();

            let mut packet_count = 0;
            let mut byte_count = 0;

            'outer: while let Some(mut packet) = underlying_stream.next().await {
              packet_count += 1;
              byte_count += packet.len();

              log::debug!("{side:?} underlying read {packet_count} packets, {byte_count} bytes");

              let receive_result = {
                log::debug!("{side:?} {} {}", "recv".red(), packet.len());

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

              match receive_result {
                Ok(_) => {
                  log::debug!("{side:?} quiche recv ok");

                  // Source code suggests that recv always return the length of the packet if Ok.

                  quiche_connection_send_continue_notify.notify_waiters();

                  let readable = quiche_connection.lock().unwrap().readable();

                  for id in readable {
                    let stream_write =
                      if let Some(write) = stream_write_map.lock().unwrap().get(&id) {
                        write.clone()
                      } else {
                        let (stream, write) = create_stream(id);

                        if stream_sender
                          .send(stream)
                          .inspect_err(|error| {
                            log::warn!("error sending stream to stream sender: {}", error)
                          })
                          .is_err()
                        {
                          break 'outer;
                        }

                        write
                      };

                    let Ok(mut stream_write) = stream_write.try_lock_owned() else {
                      // Stream could still be written to by previously triggered task.
                      log::debug!("{side:?} {id}: stream recv blocked by other task");
                      continue;
                    };

                    log::debug!("{side:?} {id}: stream recv spawn");

                    let quiche_connection = quiche_connection.clone();
                    let quiche_connection_send_continue_notify =
                      quiche_connection_send_continue_notify.clone();

                    stream_recv_join_set.spawn(async move {
                      let mut buffer = vec![0; READ_WRITE_BUFFER_SIZE];

                      loop {
                        let stream_receive_result = {
                          log::debug!(
                            "{side:?} {id}: {stream_recv}",
                            stream_recv = "stream recv".on_red()
                          );

                          let mut quiche_connection = quiche_connection.lock().unwrap();

                          if quiche_connection.stream_finished(id) {
                            log::debug!("{side:?} {id}: stream recv break");
                            break;
                          }

                          quiche_connection.stream_recv(id, &mut buffer)
                        };

                        match stream_receive_result {
                          Ok((length, finished)) => {
                            log::debug!("{side:?} {id}: stream recv {length} {finished}");

                            quiche_connection_send_continue_notify.notify_waiters();

                            if length > 0 {
                              if stream_write
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
                              stream_write
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
                            log::debug!("{side:?} {id}: stream recv done");
                            break;
                          }
                          Err(error) => {
                            log::warn!("error receiving packet from quiche stream: {}", error);
                            break;
                          }
                        }
                      }
                    });
                  }
                }
                Err(quiche::Error::Done) => continue,
                Err(error) => {
                  log::warn!("error receiving packet from quiche connection: {}", error);
                  break;
                }
              }
            }
          }
        };

        let quiche_connection_send_future = {
          async move {
            let mut buffer = [0; MAX_DATAGRAM_SIZE];

            let mut packet_count = 0;
            let mut byte_count = 0;

            loop {
              log::debug!("{side:?} {send}", send = "send".green());

              let send_result = quiche_connection.lock().unwrap().send(&mut buffer);

              match send_result {
                Ok((length, _)) => {
                  packet_count += 1;
                  byte_count += length;

                  log::debug!("{side:?} quiche send {packet_count} packets, {byte_count} bytes");

                  quiche_stream_send_continue_notify.notify_waiters();

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
                  let timeout_instant = quiche_connection.lock().unwrap().timeout_instant();

                  if let Some(timeout_instant) = timeout_instant {
                    spawn({
                      let quiche_connection = quiche_connection.clone();
                      let quiche_connection_send_continue_notify =
                        quiche_connection_send_continue_notify.clone();

                      async move {
                        sleep_until(timeout_instant.into()).await;
                        quiche_connection.lock().unwrap().on_timeout();
                        quiche_connection_send_continue_notify.notify_waiters();
                      }
                    });
                  }

                  quiche_connection_send_continue_notify.notified().await;
                }
                Err(error) => {
                  log::warn!("error sending packet to quiche connection: {}", error);
                  break;
                }
              }
            }

            log::debug!("{side:?} quiche connection send loop ended");
          }
        };

        tokio_join_set!(quiche_connection_recv_future, quiche_connection_send_future)
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

    let (stream, _) = (self.create_stream)(stream_id);

    stream
  }
}

#[derive(Clone, Copy, Debug)]
pub enum QuicConnectionSide {
  Client,
  Server,
}

impl QuicConnectionSide {
  pub fn stream_id_bits(&self) -> u64 {
    match self {
      QuicConnectionSide::Client => 0b00,
      QuicConnectionSide::Server => 0b01,
    }
  }
}

#[derive(thiserror::Error, Debug)]
pub enum QuicConnectionError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}
