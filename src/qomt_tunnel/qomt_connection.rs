use std::{
  collections::HashMap,
  net::{IpAddr, Ipv4Addr, SocketAddr},
  sync::Arc,
};

use futures::{SinkExt, StreamExt};
use lits::{bytes, duration};
use lowkit::{SelfWrapExt, tokio_join_set};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, SimplexStream, duplex, simplex},
  sync::{Notify, mpsc},
  task::JoinSet,
  time::sleep,
};

use crate::qomt_tunnel::{
  MtConnections, MtConnectionsPacket, QomtStream, bytes_packet::BytesPacket,
};

/// Though the underlying transport is TCP and we could have larger datagrams,
/// but we'll stick with smaller ones in case it would affect performance like latency.
const MAX_DATAGRAM_SIZE: usize = 1500;

const READ_WRITE_BUFFER_SIZE: usize = bytes!("16 KiB") as usize;
const STREAM_MAX_BUFFER_SIZE: usize = bytes!("256 KiB") as usize;

pub struct QomtConnection {
  quiche_connection: Arc<tokio::sync::Mutex<quiche::Connection>>,
  stream_receiver: mpsc::UnboundedReceiver<QomtStream>,
  task_set: JoinSet<()>,
}

impl QomtConnection {
  pub fn new(
    quiche_connection: quiche::Connection,
    mut mt_connections: MtConnections<BytesPacket>,
  ) -> Self {
    let quiche_connection = quiche_connection.tokio_mutex().arc();
    let (stream_sender, stream_receiver) = mpsc::unbounded_channel();

    Self {
      quiche_connection: quiche_connection.clone(),
      stream_receiver,
      task_set: {
        let (mut mt_sink, mut mt_stream) = mt_connections.split();

        let quiche_connection_send_notify = Notify::new().arc();
        let quiche_stream_send_notify = Notify::new().arc();

        let get_or_create_stream = {
          let quiche_connection = quiche_connection.clone();
          let quiche_connection_send_notify = quiche_connection_send_notify.clone();
          let quiche_stream_send_notify = quiche_stream_send_notify.clone();

          let stream_write_map = HashMap::<u64, Arc<tokio::sync::Mutex<_>>>::new()
            .tokio_mutex()
            .arc();

          let task_set = JoinSet::new().mutex().arc();

          move |id: u64| {
            let quiche_connection = quiche_connection.clone();
            let quiche_connection_send_notify = quiche_connection_send_notify.clone();
            let quiche_stream_send_notify = quiche_stream_send_notify.clone();
            let task_set = task_set.clone();
            let stream_sender = stream_sender.clone();
            let stream_write_map = stream_write_map.clone();

            async move {
              if let Some(write) = stream_write_map.lock().await.get(&id) {
                return write.clone();
              }

              let (external_read, write) = simplex(STREAM_MAX_BUFFER_SIZE);
              let (mut read, external_write) = simplex(STREAM_MAX_BUFFER_SIZE);

              stream_sender
                .send(QomtStream {
                  read: external_read,
                  write: external_write,
                })
                .inspect_err(|error| log::warn!("error sending stream to stream sender: {}", error))
                .ok();

              task_set.lock().unwrap().spawn(async move {
                let mut buffer = vec![0; READ_WRITE_BUFFER_SIZE];

                'outer: while let Ok(total_length) = read.read(&mut buffer).await {
                  if total_length > 0 {
                    let mut offset = 0;

                    while offset < total_length {
                      let stream_send_result = quiche_connection.lock().await.stream_send(
                        id,
                        &buffer[offset..total_length],
                        false,
                      );

                      match stream_send_result {
                        Ok(length) => {
                          assert_ne!(length, 0);

                          quiche_stream_send_notify.notify_waiters();

                          offset += length;
                        }
                        Err(quiche::Error::Done) => {
                          quiche_connection_send_notify.notified().await;
                        }
                        Err(error) => {
                          log::warn!("error sending packet to quiche connection: {}", error);
                          break 'outer;
                        }
                      }
                    }
                  } else {
                    let stream_send_result =
                      quiche_connection.lock().await.stream_send(id, &[], true);

                    match stream_send_result {
                      Ok(_) => {
                        break;
                      }
                      Err(quiche::Error::Done) => {
                        quiche_connection_send_notify.notified().await;
                      }
                      Err(error) => {
                        log::warn!("error sending packet to quiche connection: {}", error);
                        break;
                      }
                    }
                  }
                }
              });

              let write = write.tokio_mutex().arc();

              stream_write_map.lock().await.insert(id, write.clone());

              write
            }
          }
        };

        let mt_to_quiche_future = {
          let quiche_connection = quiche_connection.clone();

          async move {
            // Read from the underlying multiple TCP connections.

            let receive_info: quiche::RecvInfo = quiche::RecvInfo {
              from: SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
              to: SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            };

            let mut write_task_set = JoinSet::new();

            while let Some(mut packet) = mt_stream.next().await {
              let receive_result = quiche_connection
                .lock()
                .await
                .recv(&mut packet, receive_info);

              match receive_result {
                Ok(_) => {
                  // Source code suggests that recv always return the length of the packet if Ok.

                  let readable = quiche_connection.lock().await.readable();

                  for id in readable {
                    let stream_write = get_or_create_stream(id).await;

                    let quiche_connection = quiche_connection.clone();

                    write_task_set.spawn(async move {
                      let Ok(mut stream_write) = stream_write.try_lock() else {
                        // Stream could still be written to by previously triggered task.
                        return;
                      };

                      let mut buffer = vec![0; READ_WRITE_BUFFER_SIZE];

                      loop {
                        let stream_receive_result =
                          quiche_connection.lock().await.stream_recv(id, &mut buffer);

                        match stream_receive_result {
                          Ok((length, finished)) => {
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
                          Err(quiche::Error::Done) => break,
                          Err(error) => {
                            log::warn!("error receiving packet from quiche connection: {}", error);
                            break;
                          }
                        }
                      }
                    });
                  }
                }
                Err(quiche::Error::Done) => continue,
                Err(error) => {
                  log::warn!("error sending packet to quiche connection: {}", error);
                  break;
                }
              }
            }
          }
        };

        let quiche_to_mt_future = {
          async move {
            let mut buffer = vec![0; READ_WRITE_BUFFER_SIZE];

            loop {
              let send_result = quiche_connection.lock().await.send(&mut buffer);

              match send_result {
                Ok((length, _)) => {
                  quiche_connection_send_notify.notify_waiters();

                  if mt_sink
                    .send(buffer[..length].to_vec().into())
                    .await
                    .inspect_err(|error| {
                      log::warn!("error sending packet to mt connections: {}", error)
                    })
                    .is_err()
                  {
                    break;
                  }
                }
                Err(quiche::Error::Done) => {
                  quiche_stream_send_notify.notified().await;
                }
                Err(error) => {
                  log::warn!("error receiving packet from quiche connection: {}", error);
                  break;
                }
              }
            }
          }
        };

        tokio_join_set!(mt_to_quiche_future, quiche_to_mt_future)
      },
    }
  }

  pub async fn accept(&mut self) -> Option<QomtStream> {
    self.stream_receiver.recv().await
  }
}

#[derive(thiserror::Error, Debug)]
pub enum QomtConnectionError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}
