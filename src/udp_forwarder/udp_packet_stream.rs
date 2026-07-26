use std::{
  pin::Pin,
  task::{Context, Poll},
};

use futures::{Sink, Stream};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
  primitives::BidiStream,
  udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket},
};

const MAX_UDP_PACKET_FRAME_SIZE: usize = 128 * 1024;

pub trait InboundUdpPacketStream:
  Sink<IncomingUdpPacket, Error = UdpPacketStreamError>
  + Stream<Item = OutgoingUdpPacket>
  + Send
  + Unpin
{
}

impl<T> InboundUdpPacketStream for T where
  T: Sink<IncomingUdpPacket, Error = UdpPacketStreamError>
    + Stream<Item = OutgoingUdpPacket>
    + Send
    + Unpin
{
}

pub trait OutboundUdpPacketStream:
  Sink<OutgoingUdpPacket, Error = UdpPacketStreamError>
  + Stream<Item = IncomingUdpPacket>
  + Send
  + Unpin
{
}

impl<T> OutboundUdpPacketStream for T where
  T: Sink<OutgoingUdpPacket, Error = UdpPacketStreamError>
    + Stream<Item = IncomingUdpPacket>
    + Send
    + Unpin
{
}

pub struct UdpPacketStream<TSend: 'static, TReceive: 'static> {
  packet_sink: flume::r#async::SendSink<'static, TSend>,
  packet_stream: flume::r#async::RecvStream<'static, TReceive>,
}

impl<TSend, TReceive> UdpPacketStream<TSend, TReceive>
where
  TSend: Serialize + Send + Sync + 'static,
  TReceive: DeserializeOwned + Send + 'static,
{
  pub fn new(stream: Box<dyn BidiStream>) -> Self {
    let (outgoing_sender, outgoing_receiver) = flume::unbounded::<TSend>();
    let (incoming_sender, incoming_receiver) = flume::unbounded::<TReceive>();
    let (mut read, mut write) = tokio::io::split(stream);

    tokio::spawn(async move {
      while let Ok(packet) = outgoing_receiver.recv_async().await {
        if let Err(error) = write_packet_frame(&mut write, &packet).await {
          log::debug!("UDP packet stream writer stopped: {error}");
          return;
        }
      }

      write.shutdown().await.ok();
    });

    tokio::spawn(async move {
      loop {
        match read_packet_frame(&mut read).await {
          Ok(Some(packet)) => {
            if incoming_sender.send_async(packet).await.is_err() {
              break;
            }
          }
          Ok(None) => break,
          Err(error) => {
            log::debug!("UDP packet stream reader stopped: {error}");
            break;
          }
        }
      }
    });

    Self {
      packet_sink: outgoing_sender.into_sink(),
      packet_stream: incoming_receiver.into_stream(),
    }
  }
}

impl<TSend: 'static, TReceive: 'static> Sink<TSend> for UdpPacketStream<TSend, TReceive> {
  type Error = UdpPacketStreamError;

  fn poll_ready(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_ready(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn start_send(mut self: Pin<&mut Self>, packet: TSend) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink)
      .start_send(packet)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_flush(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_close(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_close(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }
}

impl<TSend: 'static, TReceive: 'static> Stream for UdpPacketStream<TSend, TReceive> {
  type Item = TReceive;

  fn poll_next(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(context)
  }
}

async fn write_packet_frame<T>(
  writer: &mut (impl AsyncWrite + Unpin),
  packet: &T,
) -> Result<(), UdpPacketStreamError>
where
  T: Serialize,
{
  let encoded = postcard::to_allocvec(packet)?;

  if encoded.len() > MAX_UDP_PACKET_FRAME_SIZE {
    return Err(UdpPacketStreamError::FrameTooLarge(encoded.len()));
  }

  writer.write_u32(encoded.len() as u32).await?;
  writer.write_all(&encoded).await?;
  writer.flush().await?;

  Ok(())
}

async fn read_packet_frame<T>(
  reader: &mut (impl AsyncRead + Unpin),
) -> Result<Option<T>, UdpPacketStreamError>
where
  T: DeserializeOwned,
{
  let length = match reader.read_u32().await {
    Ok(length) => length as usize,
    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
    Err(error) => return Err(error.into()),
  };

  if length > MAX_UDP_PACKET_FRAME_SIZE {
    return Err(UdpPacketStreamError::FrameTooLarge(length));
  }

  let mut encoded = vec![0; length];
  reader.read_exact(&mut encoded).await?;

  Ok(Some(postcard::from_bytes(&encoded)?))
}

#[derive(Debug, thiserror::Error)]
pub enum UdpPacketStreamError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("postcard error: {0}")]
  Postcard(#[from] postcard::Error),
  #[error("UDP packet stream closed")]
  Closed,
  #[error("UDP packet frame is too large: {0} bytes")]
  FrameTooLarge(usize),
}

#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use tokio::io::duplex;

  use super::*;
  use crate::{
    node::NodeId,
    primitives::{SocketDestination, SocketDestinationHost},
    udp_forwarder::UdpPacketSource,
  };

  #[tokio::test]
  async fn transports_udp_packets_in_both_directions() {
    let (left, right) = duplex(MAX_UDP_PACKET_FRAME_SIZE * 2);
    let mut outbound = UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(left));
    let mut inbound = UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(right));
    let source = UdpPacketSource {
      via: vec![NodeId::new()],
      address: "127.0.0.1:12345".parse().unwrap(),
    };
    let outgoing = OutgoingUdpPacket {
      source: source.clone(),
      destination: SocketDestination {
        host: SocketDestinationHost::DomainName("example.com".to_owned()),
        port: 53,
      },
      payload: b"query".to_vec(),
    };

    outbound.send(outgoing.clone()).await.unwrap();
    let received = inbound.next().await.unwrap();
    assert_eq!(received.source, outgoing.source);
    assert_eq!(received.destination, outgoing.destination);
    assert_eq!(received.payload, outgoing.payload);

    let incoming = IncomingUdpPacket {
      source,
      destination: "203.0.113.7:53".parse().unwrap(),
      payload: b"response".to_vec(),
    };

    inbound.send(incoming.clone()).await.unwrap();
    let received = outbound.next().await.unwrap();
    assert_eq!(received.source, incoming.source);
    assert_eq!(received.destination, incoming.destination);
    assert_eq!(received.payload, incoming.payload);
  }
}
