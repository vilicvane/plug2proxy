use std::{
  pin::Pin,
  task::{Context, Poll},
};

use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
  sync::mpsc,
  task::JoinSet,
};
use uuid::{Uuid, serde::compact};

const PACKET_CHANNEL_CAPACITY: usize = 1024;

pub struct MtConnections {
  packet_sink: flume::r#async::SendSink<'static, Vec<u8>>,
  packet_stream: flume::r#async::RecvStream<'static, Vec<u8>>,
  task_set: JoinSet<()>,
}

impl MtConnections {
  pub fn new(
    initial_tcp_stream: TcpStream,
  ) -> (
    Self,
    mpsc::UnboundedSender<TcpStream>,
    mpsc::UnboundedReceiver<()>,
  ) {
    let (tcp_stream_sender, mut tcp_stream_receiver) = mpsc::unbounded_channel();
    let (tcp_stream_close_sender, tcp_stream_close_receiver) = mpsc::unbounded_channel();

    let (external_packet_sender, packet_receiver) =
      flume::bounded::<Vec<u8>>(PACKET_CHANNEL_CAPACITY);
    let (packet_sender, external_packet_receiver) =
      flume::bounded::<Vec<u8>>(PACKET_CHANNEL_CAPACITY);

    let mut task_set = JoinSet::new();

    task_set.spawn(async move {
      let pipe_bidirectional = |tcp_stream: TcpStream| {
        let tcp_stream_close_sender = tcp_stream_close_sender.clone();

        let packet_sender = packet_sender.clone();
        let packet_receiver = packet_receiver.clone();

        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

        async move {
          tokio::try_join!(
            async move {
              while let Ok(packet) = packet_receiver.recv_async().await {
                tcp_write.write_u32(packet.len() as u32).await?;
                tcp_write.write_all(&packet).await?;
              }

              anyhow::Ok(())
            },
            async move {
              while let Ok(length) = tcp_read.read_u32().await {
                let mut packet = vec![0; length as usize];
                tcp_read.read_exact(&mut packet).await?;
                packet_sender.send_async(packet).await?;
              }

              anyhow::Ok(())
            },
          )
          .inspect_err(|error| {
            log::warn!("error copying bidirectional stream: {}", error);
          })
          .ok();

          tcp_stream_close_sender.send(()).ok();
        }
      };

      let mut join_set = JoinSet::new();

      join_set.spawn(pipe_bidirectional(initial_tcp_stream));

      while let Some(tcp_stream) = tcp_stream_receiver.recv().await {
        join_set.spawn(pipe_bidirectional(tcp_stream));
      }
    });

    (
      Self {
        packet_sink: external_packet_sender.into_sink(),
        packet_stream: external_packet_receiver.into_stream(),
        task_set,
      },
      tcp_stream_sender,
      tcp_stream_close_receiver,
    )
  }

  pub fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
    self.task_set.spawn(task);
  }
}

impl Stream for MtConnections {
  type Item = Vec<u8>;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(cx)
  }
}

impl Sink<Vec<u8>> for MtConnections {
  type Error = flume::SendError<Vec<u8>>;

  fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_ready(cx)
  }

  fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink).start_send(item)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_flush(cx)
  }

  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_close(cx)
  }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct MtConnectionsId(#[serde(with = "compact")] Uuid);

impl MtConnectionsId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }
}

pub const MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE: usize = 4 + 1 + 16;
pub const MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE: usize = 4 + 1 + 16;

const MAGIC: u32 = u32::from_be_bytes(*b"QomT");

pub struct MtConnectionsMagic;

impl<'de> Deserialize<'de> for MtConnectionsMagic {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: serde::Deserializer<'de>,
  {
    let magic = <[u8; 4]>::deserialize(deserializer)?;

    if magic != MAGIC.to_be_bytes() {
      return Err(serde::de::Error::custom("Bad magic"));
    }

    Ok(MtConnectionsMagic)
  }
}

impl Serialize for MtConnectionsMagic {
  fn serialize<TSerializer>(
    &self,
    serializer: TSerializer,
  ) -> Result<TSerializer::Ok, TSerializer::Error>
  where
    TSerializer: serde::Serializer,
  {
    MAGIC.to_be_bytes().serialize(serializer)
  }
}

#[derive(Serialize, Deserialize)]
pub struct MtConnectionsRequestHead {
  pub magic: MtConnectionsMagic,
  pub data: MtConnectionsRequestHeadData,
}

#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub enum MtConnectionsRequestHeadData {
  Create,
  Extend(MtConnectionsId),
}

#[derive(Serialize, Deserialize)]
pub struct MtConnectionsResponseHead {
  pub magic: MtConnectionsMagic,
  pub data: MtConnectionsResponseHeadData,
}

#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub enum MtConnectionsResponseHeadData {
  Created(MtConnectionsId),
  Extended,
  AlreadyClosed,
}

#[derive(thiserror::Error, Debug)]
pub enum MtConnectionsError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_postcard_serialization() {
    let id = MtConnectionsId::new();

    let request_head_bytes =
      postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
        magic: MtConnectionsMagic,
        data: MtConnectionsRequestHeadData::Create,
      })
      .unwrap();

    let response_head_bytes =
      postcard::to_vec::<_, MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE>(&MtConnectionsResponseHead {
        magic: MtConnectionsMagic,
        data: MtConnectionsResponseHeadData::Created(id),
      })
      .unwrap();

    let request_head =
      postcard::from_bytes::<MtConnectionsRequestHead>(&request_head_bytes).unwrap();
    let response_head =
      postcard::from_bytes::<MtConnectionsResponseHead>(&response_head_bytes).unwrap();

    assert_eq!(request_head.data, MtConnectionsRequestHeadData::Create);
    assert_eq!(
      response_head.data,
      MtConnectionsResponseHeadData::Created(id)
    );
  }
}
