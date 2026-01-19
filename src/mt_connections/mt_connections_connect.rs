use std::net::SocketAddr;

use lits::duration;
use tokio::{
  io::AsyncWriteExt,
  net::TcpStream,
  sync::oneshot,
  time::{sleep, timeout},
};

use crate::{
  mt_connections::{
    MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE, MtConnections, MtConnectionsMagic,
    MtConnectionsPacket, MtConnectionsRequestHead, MtConnectionsRequestHeadData,
    MtConnectionsResponseHead, MtConnectionsResponseHeadData,
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
  let mut tcp_stream = TcpStream::connect(address).await?;

  tcp_stream.set_nodelay(true)?;

  send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Create).await?;

  let id = {
    let response_head = postcard_read_stream::<MtConnectionsResponseHead>(&mut tcp_stream).await?;

    match response_head.data {
      MtConnectionsResponseHeadData::Created(id) => id,
      _ => return Err(MtConnectionsConnectError::InvalidResponseHead),
    }
  };

  let (mut mt_connections, tcp_stream_sender, mut tcp_stream_close_receiver) =
    MtConnections::<TPacket>::new(tcp_stream, ConnectionSide::Client);

  let (extend_signal_sender, extend_signal_receiver) = oneshot::channel();

  mt_connections.spawn(async move {
    let add_tcp_stream = || async {
      let tcp_stream = loop {
        if let Ok(tcp_stream) = async {
          let mut tcp_stream = TcpStream::connect(address).await?;

          send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Extend(id)).await?;

          let response_head =
            postcard_read_stream::<MtConnectionsResponseHead>(&mut tcp_stream).await?;

          match response_head.data {
            MtConnectionsResponseHeadData::Extended => Ok(tcp_stream),
            _ => Err(MtConnectionsConnectError::InvalidResponseHead),
          }
        }
        .await
        .inspect_err(|error| {
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

    match extend_signal_receiver.await {
      Ok(()) => {
        for _ in 1..target_connections {
          add_tcp_stream().await;
        }
      }
      Err(_) => {
        // Sender dropped, no more connections to extend. Also no need to reopen
        // after close, as the MtConnections will be closed if the only
        // tcp_stream is closed.
        return;
      }
    }

    'outer: loop {
      if tcp_stream_close_receiver.recv().await.is_none() {
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

      for _ in 1..connections_to_extend {
        let tcp_stream = loop {
          if let Ok(tcp_stream) = TcpStream::connect(address).await.inspect_err(|error| {
            log::warn!("error connecting to address {}: {}", address, error);
          }) {
            break tcp_stream;
          }

          sleep(duration!("5s")).await;
        };

        if tcp_stream_close_receiver.is_closed() {
          break 'outer;
        }

        tcp_stream.set_nodelay(true).unwrap();

        if tcp_stream_sender
          .send(tcp_stream)
          .inspect_err(|error| {
            log::warn!("error extending tcp stream to mt connections: {}", error);
          })
          .is_err()
        {
          break 'outer;
        }
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
