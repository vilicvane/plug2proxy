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
  utils::postcard::{ReadPostcardFromStreamError, read_postcard_from_stream},
};

pub async fn mt_connections_connect<TPacket>(
  address: SocketAddr,
  target_connections: usize,
) -> Result<(MtConnections<TPacket>, oneshot::Sender<()>), MtConnectionsConnectError>
where
  TPacket: MtConnectionsPacket,
{
  let mut tcp_stream = TcpStream::connect(address).await?;

  send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Create).await?;

  let id = {
    let response_head =
      read_postcard_from_stream::<MtConnectionsResponseHead>(&mut tcp_stream).await?;

    match response_head.data {
      MtConnectionsResponseHeadData::Created(id) => id,
      _ => return Err(MtConnectionsConnectError::InvalidResponseHead),
    }
  };

  let (mut mt_connections, tcp_stream_sender, mut tcp_stream_close_receiver) =
    MtConnections::<TPacket>::new(tcp_stream);

  let (extend_signal_sender, extend_signal_receiver) = oneshot::channel();

  mt_connections.spawn(async move {
    let add_tcp_stream = || async {
      let tcp_stream = loop {
        if let Ok(tcp_stream) = async {
          let mut tcp_stream = TcpStream::connect(address).await?;

          send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Extend(id)).await?;

          let response_head =
            read_postcard_from_stream::<MtConnectionsResponseHead>(&mut tcp_stream).await?;

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

    if extend_signal_receiver
      .await
      .inspect_err(|error| {
        log::warn!("error receiving extend signal: {}", error);
      })
      .is_ok()
    {
      for _ in 1..target_connections {
        add_tcp_stream().await;
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

impl From<ReadPostcardFromStreamError> for MtConnectionsConnectError {
  fn from(error: ReadPostcardFromStreamError) -> Self {
    match error {
      ReadPostcardFromStreamError::Io(error) => Self::Io(error),
      ReadPostcardFromStreamError::Deserialization(error) => Self::PostcardDeserialization(error),
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
