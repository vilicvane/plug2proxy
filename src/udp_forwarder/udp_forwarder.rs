use std::{
  collections::HashMap,
  net::{IpAddr, SocketAddr},
  pin::Pin,
  sync::{Arc, Mutex},
  task::{Context, Poll},
};

use futures::{Sink, Stream};
use lits::duration;
use lowkit::{SelfWrapExt, tokio_join_set};
use moka::sync::Cache;
use tokio::{net::UdpSocket, task::JoinSet};

use crate::{
  primitives::SocketDestinationHost,
  udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket, UdpPacketSource},
  utils::net::SocketAddressExt,
};

pub struct UdpForwarder {
  packet_sink: flume::r#async::SendSink<'static, OutgoingUdpPacket>,
  packet_stream: flume::r#async::RecvStream<'static, IncomingUdpPacket>,
  _join_set: JoinSet<()>,
}

impl UdpForwarder {
  pub fn new() -> Self {
    let (external_packet_sender, packet_receiver) = flume::unbounded();
    let (packet_sender, external_packet_receiver) = flume::unbounded();

    let packet_sink = external_packet_sender.into_sink();
    let packet_stream = external_packet_receiver.into_stream();

    let sockets = Cache::builder()
      .max_capacity(1024 * 16)
      .time_to_idle(duration!("15m"))
      .build();

    Self {
      packet_sink,
      packet_stream,
      _join_set: tokio_join_set!(async move {
        loop {
          let Ok(packet) = packet_receiver.recv_async().await else {
            break;
          };

          Self::send_outgoing_packet(sockets.clone(), packet_sender.clone(), packet)
            .await
            .inspect_err(|error| {
              log::error!("error sending outgoing packet: {}", error);
            })
            .ok();
        }
      }),
    }
  }

  async fn send_outgoing_packet(
    sockets: Cache<UdpPacketSource, SocketTuple>,
    packet_sender: flume::Sender<IncomingUdpPacket>,
    OutgoingUdpPacket {
      source,
      destination,
      payload,
    }: OutgoingUdpPacket,
  ) -> Result<(), std::io::Error> {
    let (socket, destination_address) = {
      if let Some((socket, destination_map, _)) = sockets.get(&source) {
        if let Some(destination_ip) = destination_map.lock().unwrap().get(&destination.host) {
          (
            socket.clone(),
            SocketAddr::from((*destination_ip, destination.port)),
          )
        } else {
          let socket_ip_version = socket.local_addr()?.get_ip_version();

          let destination_addresses = destination.resolve().await?;

          let destination_address = destination_addresses
            .into_iter()
            .find(|address| address.get_ip_version() == socket_ip_version)
            .ok_or_else(|| {
              std::io::Error::other("Unable to resolve matching destination socket address")
            })?;

          destination_map
            .lock()
            .unwrap()
            .insert(destination.host.clone(), destination_address.ip());

          (socket.clone(), destination_address)
        }
      } else {
        let destination_socket_address =
          destination.resolve_connectable().await?.ok_or_else(|| {
            std::io::Error::other("Unable to resolve connectable destination socket address")
          })?;

        let socket = UdpSocket::bind(source.address.unspecified()).await?.arc();

        let mut destination_map = HashMap::new();

        destination_map.insert(destination.host.clone(), destination_socket_address.ip());

        let join_set = tokio_join_set!(Self::listen(
          packet_sender.clone(),
          source.clone(),
          socket.clone(),
        ));

        let socket_tuple = (
          socket.clone(),
          destination_map.mutex().arc(),
          join_set.arc(),
        );

        sockets.insert(source.clone(), socket_tuple);

        (socket, destination_socket_address)
      }
    };

    socket.send_to(&payload, destination_address).await?;

    Ok(())
  }

  async fn listen(
    packet_sender: flume::Sender<IncomingUdpPacket>,
    source: UdpPacketSource,
    socket: Arc<UdpSocket>,
  ) {
    let mut buffer = vec![0; 1500];

    loop {
      let Ok((length, source_socket_address)) =
        socket.recv_from(&mut buffer).await.inspect_err(|error| {
          log::error!("error receiving packet: {}", error);
        })
      else {
        break;
      };

      packet_sender
        .send_async(IncomingUdpPacket {
          source: source.clone(),
          destination: source_socket_address,
          payload: buffer[..length].to_vec(),
        })
        .await
        .inspect_err(|error| {
          log::error!("error sending incoming packet back to source: {}", error);
        })
        .ok();
    }
  }
}

type SocketTuple = (
  Arc<UdpSocket>,
  Arc<Mutex<HashMap<SocketDestinationHost, IpAddr>>>,
  Arc<JoinSet<()>>,
);

impl Sink<OutgoingUdpPacket> for UdpForwarder {
  type Error = flume::SendError<OutgoingUdpPacket>;

  fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_ready(cx)
  }

  fn start_send(mut self: Pin<&mut Self>, item: OutgoingUdpPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink).start_send(item)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_flush(cx)
  }

  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_close(cx)
  }
}

impl Stream for UdpForwarder {
  type Item = IncomingUdpPacket;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(cx)
  }
}

impl Default for UdpForwarder {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use std::net::{IpAddr, Ipv4Addr, SocketAddr};

  use futures::{SinkExt, StreamExt};
  use tokio::net::UdpSocket;

  use crate::{
    primitives::{SocketDestination, SocketDestinationHost},
    udp_forwarder::{OutgoingUdpPacket, UdpForwarder, UdpPacketSource},
  };

  fn create_source(address: SocketAddr) -> UdpPacketSource {
    UdpPacketSource {
      via: vec![],
      address,
    }
  }

  fn create_destination(address: SocketAddr) -> SocketDestination {
    SocketDestination {
      host: SocketDestinationHost::IpAddress(address.ip()),
      port: address.port(),
    }
  }

  #[tokio::test]
  async fn test_send_and_receive_packet() {
    // Create a UDP server to receive and echo back packets
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();

    // Spawn echo server
    let server_handle = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let (length, source) = server_socket.recv_from(&mut buffer).await.unwrap();
      // Echo the packet back
      server_socket
        .send_to(&buffer[..length], source)
        .await
        .unwrap();
      buffer[..length].to_vec()
    });

    // Create forwarder and send a packet
    let mut forwarder = UdpForwarder::new();

    let source_address = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345));
    let payload = b"hello, world!".to_vec();

    let packet = OutgoingUdpPacket {
      source: create_source(source_address),
      destination: create_destination(server_address),
      payload: payload.clone(),
    };

    forwarder.send(packet).await.unwrap();

    // Verify server received the correct payload
    let received_payload = server_handle.await.unwrap();
    assert_eq!(received_payload, payload);

    // Verify we receive the echo response
    let incoming_packet = forwarder.next().await.unwrap();
    assert_eq!(incoming_packet.payload, payload);
    assert_eq!(incoming_packet.destination, server_address);
    assert_eq!(incoming_packet.source.address, source_address);
  }

  #[tokio::test]
  async fn test_multiple_packets_same_source() {
    // Create a UDP server
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();

    // Spawn server that receives multiple packets
    let server_handle = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let mut received = Vec::new();

      for _ in 0..3 {
        let (length, source) = server_socket.recv_from(&mut buffer).await.unwrap();
        received.push(buffer[..length].to_vec());
        // Echo back
        server_socket
          .send_to(&buffer[..length], source)
          .await
          .unwrap();
      }

      received
    });

    let mut forwarder = UdpForwarder::new();
    let source_address = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12346));

    // Send multiple packets
    let payloads: Vec<Vec<u8>> = vec![
      b"packet1".to_vec(),
      b"packet2".to_vec(),
      b"packet3".to_vec(),
    ];

    for payload in &payloads {
      let packet = OutgoingUdpPacket {
        source: create_source(source_address),
        destination: create_destination(server_address),
        payload: payload.clone(),
      };
      forwarder.send(packet).await.unwrap();
    }

    // Verify server received all packets
    let received_payloads = server_handle.await.unwrap();
    assert_eq!(received_payloads, payloads);

    // Verify we receive all echo responses
    for expected_payload in &payloads {
      let incoming_packet = forwarder.next().await.unwrap();
      assert_eq!(&incoming_packet.payload, expected_payload);
    }
  }

  #[tokio::test]
  async fn test_different_sources_use_different_sockets() {
    // Create two UDP servers to receive packets
    let server_socket_1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address_1 = server_socket_1.local_addr().unwrap();

    let server_socket_2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address_2 = server_socket_2.local_addr().unwrap();

    // Spawn servers that capture the source port
    let server_handle_1 = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let (length, source) = server_socket_1.recv_from(&mut buffer).await.unwrap();
      server_socket_1
        .send_to(&buffer[..length], source)
        .await
        .unwrap();
      source.port()
    });

    let server_handle_2 = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let (length, source) = server_socket_2.recv_from(&mut buffer).await.unwrap();
      server_socket_2
        .send_to(&buffer[..length], source)
        .await
        .unwrap();
      source.port()
    });

    let mut forwarder = UdpForwarder::new();

    // Send from two different source addresses
    let source_address_1 = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20001));
    let source_address_2 = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20002));

    let packet_1 = OutgoingUdpPacket {
      source: create_source(source_address_1),
      destination: create_destination(server_address_1),
      payload: b"from source 1".to_vec(),
    };

    let packet_2 = OutgoingUdpPacket {
      source: create_source(source_address_2),
      destination: create_destination(server_address_2),
      payload: b"from source 2".to_vec(),
    };

    forwarder.send(packet_1).await.unwrap();
    forwarder.send(packet_2).await.unwrap();

    // Get the ports that each server saw
    let port_1 = server_handle_1.await.unwrap();
    let port_2 = server_handle_2.await.unwrap();

    // Different sources should use different local sockets (different ports)
    assert_ne!(port_1, port_2);
  }

  #[tokio::test]
  async fn test_domain_name_destination() {
    // Create a UDP server
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();

    // Spawn echo server
    let server_handle = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let (length, source) = server_socket.recv_from(&mut buffer).await.unwrap();
      server_socket
        .send_to(&buffer[..length], source)
        .await
        .unwrap();
      buffer[..length].to_vec()
    });

    let mut forwarder = UdpForwarder::new();

    let source_address = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12347));
    let payload = b"domain test".to_vec();

    // Use localhost domain name instead of IP
    let packet = OutgoingUdpPacket {
      source: create_source(source_address),
      destination: SocketDestination {
        host: SocketDestinationHost::DomainName("localhost".to_string()),
        port: server_address.port(),
      },
      payload: payload.clone(),
    };

    forwarder.send(packet).await.unwrap();

    // Verify server received the correct payload
    let received_payload = server_handle.await.unwrap();
    assert_eq!(received_payload, payload);

    // Verify we receive the echo response
    let incoming_packet = forwarder.next().await.unwrap();
    assert_eq!(incoming_packet.payload, payload);
  }

  #[tokio::test]
  async fn test_cached_destination_resolution() {
    // Create a UDP server
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();

    // Spawn server that receives two packets
    let server_handle = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let mut received = Vec::new();

      for _ in 0..2 {
        let (length, source) = server_socket.recv_from(&mut buffer).await.unwrap();
        received.push((buffer[..length].to_vec(), source.port()));
        server_socket
          .send_to(&buffer[..length], source)
          .await
          .unwrap();
      }

      received
    });

    let mut forwarder = UdpForwarder::new();
    let source_address = SocketAddr::from((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12348));

    // Send two packets to the same destination using domain name
    // The second should use cached IP resolution
    for i in 0..2 {
      let packet = OutgoingUdpPacket {
        source: create_source(source_address),
        destination: SocketDestination {
          host: SocketDestinationHost::DomainName("localhost".to_string()),
          port: server_address.port(),
        },
        payload: format!("packet {}", i).into_bytes(),
      };
      forwarder.send(packet).await.unwrap();
    }

    // Verify both packets were received from the same port (same cached socket)
    let received = server_handle.await.unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0].1, received[1].1); // Same source port means same socket
  }
}
