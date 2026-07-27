use std::{
  marker::PhantomData,
  pin::Pin,
  task::{Context, Poll},
};

use futures::{Sink, Stream};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::ReadBuf;

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

struct PendingFrame {
  encoded: Vec<u8>,
  written: usize,
}

enum ReadState {
  Length {
    encoded: [u8; size_of::<u32>()],
    read: usize,
  },
  Payload {
    encoded: Vec<u8>,
    read: usize,
  },
}

impl ReadState {
  fn length() -> Self {
    Self::Length {
      encoded: [0; size_of::<u32>()],
      read: 0,
    }
  }
}

pub struct UdpPacketStream<TSend: 'static, TReceive: 'static> {
  stream: Box<dyn BidiStream>,
  pending_frame: Option<PendingFrame>,
  read_state: ReadState,
  read_closed: bool,
  packet_types: PhantomData<fn(TSend, TReceive)>,
}

impl<TSend: 'static, TReceive: 'static> UdpPacketStream<TSend, TReceive> {
  pub fn new(stream: Box<dyn BidiStream>) -> Self {
    Self {
      stream,
      pending_frame: None,
      read_state: ReadState::length(),
      read_closed: false,
      packet_types: PhantomData,
    }
  }

  fn poll_write_pending(
    &mut self,
    context: &mut Context,
  ) -> Poll<Result<(), UdpPacketStreamError>> {
    while let Some(frame) = &mut self.pending_frame {
      let written =
        match Pin::new(&mut *self.stream).poll_write(context, &frame.encoded[frame.written..]) {
          Poll::Ready(Ok(0)) => {
            return Poll::Ready(Err(
              std::io::Error::from(std::io::ErrorKind::WriteZero).into(),
            ));
          }
          Poll::Ready(Ok(written)) => written,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
          Poll::Pending => return Poll::Pending,
        };

      frame.written += written;

      if frame.written == frame.encoded.len() {
        self.pending_frame = None;
      }
    }

    Poll::Ready(Ok(()))
  }

  fn stop_reading(&mut self, error: impl std::fmt::Display) -> Poll<Option<TReceive>> {
    log::debug!("UDP packet stream reader stopped: {error}");
    self.read_closed = true;
    Poll::Ready(None)
  }
}

impl<TSend, TReceive> Sink<TSend> for UdpPacketStream<TSend, TReceive>
where
  TSend: Serialize + 'static,
  TReceive: 'static,
{
  type Error = UdpPacketStreamError;

  fn poll_ready(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    self.get_mut().poll_write_pending(context)
  }

  fn start_send(self: Pin<&mut Self>, packet: TSend) -> Result<(), Self::Error> {
    let this = self.get_mut();
    assert!(
      this.pending_frame.is_none(),
      "start_send called before UdpPacketStream became ready"
    );

    let payload = postcard::to_allocvec(&packet)?;

    if payload.len() > MAX_UDP_PACKET_FRAME_SIZE {
      return Err(UdpPacketStreamError::FrameTooLarge(payload.len()));
    }

    let mut encoded = Vec::with_capacity(size_of::<u32>() + payload.len());
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&payload);
    this.pending_frame = Some(PendingFrame {
      encoded,
      written: 0,
    });

    Ok(())
  }

  fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    match self.as_mut().get_mut().poll_write_pending(context) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      Poll::Pending => return Poll::Pending,
    }

    Pin::new(&mut *self.get_mut().stream)
      .poll_flush(context)
      .map_err(UdpPacketStreamError::from)
  }

  fn poll_close(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    match self.as_mut().poll_flush(context) {
      Poll::Ready(Ok(())) => {}
      Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      Poll::Pending => return Poll::Pending,
    }

    Pin::new(&mut *self.get_mut().stream)
      .poll_shutdown(context)
      .map_err(UdpPacketStreamError::from)
  }
}

impl<TSend, TReceive> Stream for UdpPacketStream<TSend, TReceive>
where
  TSend: 'static,
  TReceive: DeserializeOwned + 'static,
{
  type Item = TReceive;

  fn poll_next(self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
    let this = self.get_mut();

    if this.read_closed {
      return Poll::Ready(None);
    }

    loop {
      let (target, read) = match &mut this.read_state {
        ReadState::Length { encoded, read } => (&mut encoded[..], read),
        ReadState::Payload { encoded, read } => (&mut encoded[..], read),
      };
      let mut read_buffer = ReadBuf::new(&mut target[*read..]);

      match Pin::new(&mut *this.stream).poll_read(context, &mut read_buffer) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(error)) => return this.stop_reading(error),
        Poll::Pending => return Poll::Pending,
      }

      let read_now = read_buffer.filled().len();

      if read_now == 0 && *read < target.len() {
        if matches!(this.read_state, ReadState::Length { read: 0, .. }) {
          this.read_closed = true;
          return Poll::Ready(None);
        }

        return this.stop_reading(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
      }

      *read += read_now;

      if *read < target.len() {
        continue;
      }

      match std::mem::replace(&mut this.read_state, ReadState::length()) {
        ReadState::Length { encoded, .. } => {
          let length = u32::from_be_bytes(encoded) as usize;

          if length > MAX_UDP_PACKET_FRAME_SIZE {
            return this.stop_reading(UdpPacketStreamError::FrameTooLarge(length));
          }

          this.read_state = ReadState::Payload {
            encoded: vec![0; length],
            read: 0,
          };
        }
        ReadState::Payload { encoded, .. } => match postcard::from_bytes(&encoded) {
          Ok(packet) => return Poll::Ready(Some(packet)),
          Err(error) => return this.stop_reading(error),
        },
      }
    }
  }
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

  #[tokio::test]
  async fn reports_underlying_write_failure_to_the_sender() {
    let (stream, peer) = duplex(4096);
    let mut packet_stream =
      UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(stream));
    drop(peer);

    let result = packet_stream
      .send(OutgoingUdpPacket {
        source: UdpPacketSource {
          via: vec![],
          address: "127.0.0.1:12345".parse().unwrap(),
        },
        destination: SocketDestination {
          host: SocketDestinationHost::DomainName("example.com".to_owned()),
          port: 53,
        },
        payload: b"query".to_vec(),
      })
      .await;

    assert!(matches!(
      result,
      Err(UdpPacketStreamError::Io(error))
        if error.kind() == std::io::ErrorKind::BrokenPipe
    ));
  }
}
