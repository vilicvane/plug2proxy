use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use lowkit::SelfWrapExt;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc};

use crate::{
  mt_connections::{
    MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE, MtConnections, MtConnectionsId, MtConnectionsMagic,
    MtConnectionsPacket, MtConnectionsRequestHead, MtConnectionsRequestHeadData,
    MtConnectionsResponseHead, MtConnectionsResponseHeadData,
  },
  primitives::ConnectionSide,
  utils::postcard::{ReadPostcardFromStreamError, read_postcard_from_stream},
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

      let request_head = read_postcard_from_stream::<MtConnectionsRequestHead>(&mut stream).await?;

      match request_head.data {
        MtConnectionsRequestHeadData::Create => {
          let id = MtConnectionsId::new();

          send_response_head(&mut stream, MtConnectionsResponseHeadData::Created(id)).await?;

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
            send_response_head(&mut stream, MtConnectionsResponseHeadData::Extended).await?;

            tcp_stream_sender.send(stream).ok();
          } else {
            send_response_head(&mut stream, MtConnectionsResponseHeadData::AlreadyClosed).await?;
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
}

impl From<ReadPostcardFromStreamError> for MtConnectionsListenerError {
  fn from(error: ReadPostcardFromStreamError) -> Self {
    match error {
      ReadPostcardFromStreamError::Io(error) => Self::Io(error),
      ReadPostcardFromStreamError::Deserialization(error) => Self::PostcardDeserialization(error),
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
