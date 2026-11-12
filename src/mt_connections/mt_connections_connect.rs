use std::net::SocketAddr;

use lits::duration;
use tokio::{
  io::AsyncWriteExt,
  net::TcpStream,
  sync::oneshot,
  time::{Instant, MissedTickBehavior, interval_at, sleep, timeout},
};

use crate::{
  mt_connections::{
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE,
    MT_CONNECTIONS_ROTATION_INTERVAL, MtConnections, MtConnectionsMagic, MtConnectionsPacket,
    MtConnectionsRequestHead, MtConnectionsRequestHeadData, MtConnectionsResponseHead,
    MtConnectionsResponseHeadData, configure_mt_tcp_stream,
  },
  primitives::ConnectionSide,
  utils::postcard::{PostcardStreamError, postcard_read_stream},
};

pub async fn mt_connections_connect<TPacket>(
  address: SocketAddr,
  target_connections: usize,
) -> Result<(MtConnections<TPacket>, oneshot::Sender<()>), MtConnectionsConnectError>
where
  TPacket: MtConnectionsPacket,
{
  let mut tcp_stream = timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    TcpStream::connect(address),
  )
  .await
  .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

  configure_mt_tcp_stream(&tcp_stream)?;

  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Create),
  )
  .await
  .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

  let id = {
    let response_head = timeout(
      MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
      postcard_read_stream::<MtConnectionsResponseHead>(&mut tcp_stream),
    )
    .await
    .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

    match response_head.data {
      MtConnectionsResponseHeadData::Created(id) => id,
      _ => return Err(MtConnectionsConnectError::InvalidResponseHead),
    }
  };

  let (mut mt_connections, tcp_stream_sender, mut tcp_stream_close_receiver) =
    MtConnections::<TPacket>::new(tcp_stream, ConnectionSide::Client, id);

  let (extend_signal_sender, extend_signal_receiver) = oneshot::channel();
  let underlay_metrics = mt_connections.underlay_metrics();

  mt_connections.spawn(async move {
    let add_tcp_stream = || async {
      let tcp_stream = loop {
        let connect = async {
          let mut tcp_stream = timeout(
            MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
            TcpStream::connect(address),
          )
          .await
          .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

          configure_mt_tcp_stream(&tcp_stream)?;

          timeout(
            MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
            send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Extend(id)),
          )
          .await
          .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

          let response_head = timeout(
            MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
            postcard_read_stream::<MtConnectionsResponseHead>(&mut tcp_stream),
          )
          .await
          .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

          match response_head.data {
            MtConnectionsResponseHeadData::Extended => Ok(tcp_stream),
            _ => Err(MtConnectionsConnectError::InvalidResponseHead),
          }
        };
        let result = tokio::select! {
          _ = tcp_stream_sender.closed() => return false,
          result = connect => result,
        };
        if let Ok(tcp_stream) = result.inspect_err(|error| {
          log::warn!("error connecting to address {}: {}", address, error);
        }) {
          break tcp_stream;
        }

        sleep(duration!("5s")).await;
      };

      tcp_stream_sender
        .send(tcp_stream)
        .inspect_err(|error| {
          log::warn!("error adding tcp stream to mt connections: {}", error);
        })
        .is_ok()
    };

    let mut managed_connections = 1;
    match extend_signal_receiver.await {
      Ok(()) => {
        for _ in 1..target_connections {
          if !add_tcp_stream().await {
            return;
          }
          managed_connections += 1;
        }
      }
      Err(_) => {
        // Sender dropped, no more connections to extend. Also no need to reopen
        // after close, as the MtConnections will be closed if the only
        // tcp_stream is closed.
        return;
      }
    }

    let mut rotation = interval_at(
      Instant::now() + MT_CONNECTIONS_ROTATION_INTERVAL,
      MT_CONNECTIONS_ROTATION_INTERVAL,
    );
    rotation.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut desired_connections = managed_connections;

    'outer: loop {
      let closed = tokio::select! {
        biased;
        closed = tcp_stream_close_receiver.recv() => closed,
        _ = rotation.tick(), if cfg!(target_os = "linux") => {
          desired_connections = target_connections.max(1) + 1;
          if underlay_metrics.available_path_count() <= target_connections.max(1) {
            if !add_tcp_stream().await {
              break;
            }
            managed_connections += 1;
          } else {
            // The normal close notification starts the replacement only after
            // both halves of the selected TCP connection have drained.
            underlay_metrics.retire_worst_path(target_connections, std::time::Instant::now());
          }
          continue;
        }
      };
      if closed.is_none() {
        break;
      }

      let mut connections_to_extend = 1;

      loop {
        match timeout(duration!("1s"), tcp_stream_close_receiver.recv()).await {
          // another close within 1 second.
          Ok(Some(())) => connections_to_extend += 1,
          // all connections closed.
          Ok(None) => break 'outer,
          // nothing new in 1 second, time to handle the batch.
          Err(_) => break,
        }
      }

      // Count accepted additions here rather than relying on asynchronous
      // path registration. A cycle may have added a spare while another path
      // was draining, in which case its close must not add a second spare.
      managed_connections -= connections_to_extend;
      for _ in managed_connections..desired_connections {
        if tcp_stream_close_receiver.is_closed() {
          break 'outer;
        }

        if !add_tcp_stream().await {
          break 'outer;
        }
        managed_connections += 1;
      }
    }
  });

  Ok((mt_connections, extend_signal_sender))
}

#[derive(thiserror::Error, Debug)]
pub enum MtConnectionsConnectError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Postcard deserialization error: {0}")]
  PostcardDeserialization(postcard::Error),
  #[error("mTCP handshake timed out")]
  HandshakeTimeout,
  #[error("Invalid response head")]
  InvalidResponseHead,
}

impl From<PostcardStreamError> for MtConnectionsConnectError {
  fn from(error: PostcardStreamError) -> Self {
    match error {
      PostcardStreamError::Io(error) => Self::Io(error),
      PostcardStreamError::Deserialization(error) => Self::PostcardDeserialization(error),
    }
  }
}

async fn send_request_head(
  stream: &mut TcpStream,
  data: MtConnectionsRequestHeadData,
) -> Result<(), MtConnectionsConnectError> {
  let bytes =
    postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
      magic: MtConnectionsMagic,
      data,
    })
    .unwrap();

  stream.write_all(&bytes).await?;

  Ok(())
}
