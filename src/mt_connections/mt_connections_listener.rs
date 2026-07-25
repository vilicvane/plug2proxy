use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use lowkit::SelfWrapExt;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc, time::timeout};

use crate::{
  mt_connections::{
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE, MtConnections,
    MtConnectionsId, MtConnectionsMagic, MtConnectionsPacket, MtConnectionsRequestHead,
    MtConnectionsRequestHeadData, MtConnectionsResponseHead, MtConnectionsResponseHeadData,
    configure_mt_tcp_stream,
  },
  primitives::ConnectionSide,
  utils::postcard::{PostcardStreamError, postcard_read_stream},
};

pub struct MtConnectionsListener<TPacket>
where
  TPacket: MtConnectionsPacket,
{
  listener: Arc<tokio::net::TcpListener>,
  tcp_stream_sender_map: HashMap<MtConnectionsId, mpsc::UnboundedSender<TcpStream>>,
  _type_hint: PhantomData<TPacket>,
}

impl<TPacket> MtConnectionsListener<TPacket>
where
  TPacket: MtConnectionsPacket,
{
  pub fn new(listener: tokio::net::TcpListener) -> Self {
    Self {
      listener: listener.arc(),
      tcp_stream_sender_map: HashMap::new(),
      _type_hint: PhantomData,
    }
  }

  pub async fn accept(&mut self) -> Result<MtConnections<TPacket>, MtConnectionsListenerError> {
    loop {
      let (mut stream, _) = self.listener.accept().await?;

      if configure_mt_tcp_stream(&stream)
        .inspect_err(|error| {
          log::warn!("error configuring incoming mTCP connection: {error}");
        })
        .is_err()
      {
        continue;
      }

      let Ok(request_head_result) = timeout(
        MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
        postcard_read_stream::<MtConnectionsRequestHead>(&mut stream),
      )
      .await
      else {
        log::warn!("timed out reading request head from incoming mTCP connection");
        continue;
      };

      let Ok(request_head) = request_head_result.inspect_err(|error| {
        log::warn!("error reading request head from incoming mTCP connections: {error}")
      }) else {
        continue;
      };

      match request_head.data {
        MtConnectionsRequestHeadData::Create => {
          let id = MtConnectionsId::new();

          if send_response_head_with_timeout(
            &mut stream,
            MtConnectionsResponseHeadData::Created(id),
          )
          .await
          .inspect_err(|error| {
            log::warn!(
              "error sending response head (created) to incoming mTCP connections: {error}"
            )
          })
          .is_err()
          {
            continue;
          }

          let (mt_connections, tcp_stream_sender, _) =
            MtConnections::new(stream, ConnectionSide::Server);

          self
            .tcp_stream_sender_map
            .retain(|_, tcp_stream_sender| !tcp_stream_sender.is_closed());

          self.tcp_stream_sender_map.insert(id, tcp_stream_sender);

          return Ok(mt_connections);
        }
        MtConnectionsRequestHeadData::Extend(id) => {
          if let Some(tcp_stream_sender) = self.tcp_stream_sender_map.get(&id) {
            if send_response_head_with_timeout(&mut stream, MtConnectionsResponseHeadData::Extended)
              .await
              .inspect_err(|error| {
                log::warn!(
                  "error sending response head (extended) to incoming mTCP connections: {error}"
                )
              })
              .is_err()
            {
              continue;
            }

            tcp_stream_sender.send(stream).ok();
          } else {
            if send_response_head_with_timeout(
              &mut stream,
              MtConnectionsResponseHeadData::AlreadyClosed,
            )
            .await
            .inspect_err(|error| {
              log::warn!(
                "error sending response head (already closed) to incoming mTCP connections: {error}"
              )
            })
            .is_err()
            {
              continue;
            }
          }
        }
      }
    }
  }
}

#[derive(thiserror::Error, Debug)]
pub enum MtConnectionsListenerError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Postcard deserialization error: {0}")]
  PostcardDeserialization(postcard::Error),
  #[error("mTCP handshake timed out")]
  HandshakeTimeout,
}

impl From<PostcardStreamError> for MtConnectionsListenerError {
  fn from(error: PostcardStreamError) -> Self {
    match error {
      PostcardStreamError::Io(error) => Self::Io(error),
      PostcardStreamError::Deserialization(error) => Self::PostcardDeserialization(error),
    }
  }
}

async fn send_response_head(
  stream: &mut TcpStream,
  data: MtConnectionsResponseHeadData,
) -> Result<(), MtConnectionsListenerError> {
  let bytes =
    postcard::to_vec::<_, MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE>(&MtConnectionsResponseHead {
      magic: MtConnectionsMagic,
      data,
    })
    .unwrap();

  stream.write_all(&bytes).await?;

  Ok(())
}

async fn send_response_head_with_timeout(
  stream: &mut TcpStream,
  data: MtConnectionsResponseHeadData,
) -> Result<(), MtConnectionsListenerError> {
  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    send_response_head(stream, data),
  )
  .await
  .map_err(|_| MtConnectionsListenerError::HandshakeTimeout)?
}
