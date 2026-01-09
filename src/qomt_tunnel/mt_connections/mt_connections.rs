use std::{
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
};

use lowkit::{AutoAbortHandle, AutoAbortHandleExt, SelfWrapExt};
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, copy_bidirectional, duplex},
  net::TcpStream,
  spawn,
  sync::mpsc,
  task::{JoinHandle, JoinSet},
};
use uuid::{Uuid, serde::compact};

use crate::utils::{MpmcStream, postcard::read_postcard_from_stream};

pub struct MtConnections {
  read_stream: MpmcStream,
  write_stream: MpmcStream,
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
    let (tcp_stream_close_sender, mut tcp_stream_close_receiver) = mpsc::unbounded_channel();

    let external_read_stream = MpmcStream::default();
    let external_write_stream = MpmcStream::default();

    let write_stream = external_read_stream.clone();
    let read_stream = external_write_stream.clone();

    let mut task_set = JoinSet::new();

    task_set.spawn(async move {
      let copy_tcp_stream = |mut tcp_stream: TcpStream| {
        let mut stream = tokio::io::join(read_stream.clone(), write_stream.clone());
        let tcp_stream_close_sender = tcp_stream_close_sender.clone();

        async move {
          tokio::io::copy_bidirectional(&mut stream, &mut tcp_stream)
            .await
            .inspect_err(|error| {
              log::warn!("error copying bidirectional stream: {}", error);
            })
            .ok();

          tcp_stream_close_sender.send(()).ok();
        }
      };

      let mut join_set = JoinSet::new();

      join_set.spawn(copy_tcp_stream(initial_tcp_stream));

      while let Some(tcp_stream) = tcp_stream_receiver.recv().await {
        join_set.spawn(copy_tcp_stream(tcp_stream));
      }
    });

    (
      Self {
        read_stream: external_read_stream,
        write_stream: external_write_stream,
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

impl AsyncRead for MtConnections {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    MpmcStream::poll_read(Pin::new(&mut self.read_stream), cx, buf)
  }
}

impl AsyncWrite for MtConnections {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    MpmcStream::poll_write(Pin::new(&mut self.write_stream), cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    MpmcStream::poll_flush(Pin::new(&mut self.write_stream), cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    MpmcStream::poll_shutdown(Pin::new(&mut self.write_stream), cx)
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

    println!("id: {:?}", id);

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

    println!("request head bytes: {:?}", request_head_bytes);
    println!("response head bytes: {:?}", response_head_bytes);

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
