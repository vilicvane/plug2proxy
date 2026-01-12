use std::{
  pin::Pin,
  sync::{
    Arc,
    atomic::{self, AtomicUsize},
  },
  task::{Context, Poll},
};

use futures::{Sink, Stream};
use lowkit::{SelfWrapExt, TurnArcWeak, tokio_join_set};
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncRead, AsyncWrite},
  net::TcpStream,
  sync::mpsc,
  task::JoinSet,
};
use uuid::{Uuid, serde::compact};

use crate::primitives::ConnectionSide;

pub struct MtConnections<TPacket>
where
  TPacket: 'static,
{
  packet_sink: flume::r#async::SendSink<'static, TPacket>,
  packet_stream: flume::r#async::RecvStream<'static, TPacket>,
  connection_count: Arc<AtomicUsize>,
  join_set: JoinSet<()>,
}

impl<TPacket> MtConnections<TPacket>
where
  TPacket: MtConnectionsPacket,
{
  pub fn new(
    initial_tcp_stream: TcpStream,
    side: ConnectionSide,
  ) -> (
    Self,
    mpsc::UnboundedSender<TcpStream>,
    mpsc::UnboundedReceiver<()>,
  ) {
    let (tcp_stream_sender, mut tcp_stream_receiver) = mpsc::unbounded_channel();
    let (tcp_stream_close_sender, tcp_stream_close_receiver) = mpsc::unbounded_channel();

    let (external_packet_sender, packet_receiver) = flume::bounded::<TPacket>(0);
    let (packet_sender, external_packet_receiver) = flume::bounded::<TPacket>(0);

    let connection_count = Arc::new(AtomicUsize::new(0));

    let mt_connections = Self {
      packet_sink: external_packet_sender.into_sink(),
      packet_stream: external_packet_receiver.into_stream(),
      connection_count: connection_count.clone(),
      join_set: tokio_join_set!(async move {
        let (all_connections_closed_sender, mut all_connections_closed_receiver) = mpsc::channel(1);

        let packet_sender = TurnArcWeak::new(packet_sender).mutex().arc();

        let pipe_bidirectional = |tcp_stream: TcpStream| {
          let tcp_stream_close_sender = tcp_stream_close_sender.clone();

          let packet_sender = packet_sender.clone();
          let packet_receiver = packet_receiver.clone();

          let connection_count = connection_count.clone();

          let all_connections_closed_sender = all_connections_closed_sender.clone();

          async move {
            let Some(packet_sender) = packet_sender.lock().unwrap().get_arc() else {
              return;
            };

            let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

            connection_count.fetch_add(1, atomic::Ordering::Relaxed);

            tokio::try_join!(
              async move {
                loop {
                  match packet_receiver.recv_async().await {
                    Ok(packet) => {
                      TPacket::write_packet(&mut tcp_write, packet).await?;
                    }
                    Err(flume::RecvError::Disconnected) => {
                      break;
                    }
                  }
                }

                log::debug!("{side} write tcp stream loop ended");

                anyhow::Ok(())
              },
              async move {
                while let Some(packet) = TPacket::read_next_packet(&mut tcp_read).await? {
                  packet_sender.send_async(packet).await?;
                }

                log::debug!("{side} read tcp stream loop ended");

                anyhow::Ok(())
              },
            )
            .inspect_err(|error| {
              log::warn!("error copying bidirectional packet stream: {}", error);
            })
            .ok();

            let all_connections_closed =
              connection_count.fetch_sub(1, atomic::Ordering::Relaxed) == 1;

            if all_connections_closed {
              all_connections_closed_sender.send(()).await.ok();
            } else {
              tcp_stream_close_sender.send(()).ok();
            }
          }
        };

        let mut join_set = JoinSet::new();

        join_set.spawn(pipe_bidirectional(initial_tcp_stream));

        while let Some(tcp_stream) = tokio::select!(
          tcp_stream = tcp_stream_receiver.recv() => tcp_stream,
          _ = all_connections_closed_receiver.recv() => None,
        ) {
          join_set.spawn(pipe_bidirectional(tcp_stream));
        }
      }),
    };

    (mt_connections, tcp_stream_sender, tcp_stream_close_receiver)
  }

  pub fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
    self.join_set.spawn(task);
  }

  pub fn connection_count(&self) -> usize {
    self.connection_count.load(atomic::Ordering::Relaxed)
  }
}

impl<TPacket> Stream for MtConnections<TPacket> {
  type Item = TPacket;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(cx)
  }
}

impl<TPacket> Sink<TPacket> for MtConnections<TPacket> {
  type Error = flume::SendError<TPacket>;

  fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_ready(cx)
  }

  fn start_send(mut self: Pin<&mut Self>, item: TPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink).start_send(item)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_flush(cx)
  }

  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_close(cx)
  }
}

pub trait MtConnectionsPacket: Sized + Send + Sync + 'static {
  fn len(&self) -> usize;

  fn is_empty(&self) -> bool {
    self.len() == 0
  }

  fn read_next_packet(
    stream: &mut (dyn AsyncRead + Unpin + Send),
  ) -> impl Future<Output = Result<Option<Self>, std::io::Error>> + Send;

  fn write_packet(
    stream: &mut (dyn AsyncWrite + Unpin + Send),
    packet: Self,
  ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct MtConnectionsId(#[serde(with = "compact")] Uuid);

impl MtConnectionsId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }
}

impl Default for MtConnectionsId {
  fn default() -> Self {
    Self::new()
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
