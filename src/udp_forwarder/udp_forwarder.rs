use std::{
  collections::HashMap,
  net::{IpAddr, SocketAddr},
  pin::Pin,
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
  },
  task::{Context, Poll},
  time::{Duration, Instant},
};

use futures::{Sink, Stream};
use lowkit::{SelfWrapExt, tokio_join_set};
use moka::sync::Cache;
#[cfg(target_os = "linux")]
use socket2::SockRef;
use tokio::{net::UdpSocket, task::JoinSet};

use crate::{
  primitives::SocketDestinationHost,
  sniff::quic_initial_client_connection_id,
  udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket, UdpPacketSource, UdpPacketStreamError},
  utils::net::SocketAddressExt,
};

const UDP_FORWARDER_QUEUE_CAPACITY: usize = 4096;
const UDP_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_QUIC_FLOWS: usize = 1024 * 16;
const UDP_SOCKET_DEBUG_REPORT_INTERVAL_MS: u64 = 30_000;
static NEXT_UDP_SOCKET_GENERATION: AtomicU64 = AtomicU64::new(1);

pub struct UdpForwarder {
  packet_sink: flume::r#async::SendSink<'static, OutgoingUdpPacket>,
  packet_stream: flume::r#async::RecvStream<'static, IncomingUdpPacket>,
  _join_set: JoinSet<()>,
}

impl UdpForwarder {
  pub fn new() -> Self {
    Self::with_interface(None)
  }

  pub fn with_interface(interface: Option<String>) -> Self {
    let (external_packet_sender, packet_receiver) = flume::bounded(UDP_FORWARDER_QUEUE_CAPACITY);
    let (packet_sender, external_packet_receiver) = flume::bounded(UDP_FORWARDER_QUEUE_CAPACITY);

    let packet_sink = external_packet_sender.into_sink();
    let packet_stream = external_packet_receiver.into_stream();

    let sockets = Cache::builder()
      .max_capacity(1024 * 16)
      .time_to_idle(UDP_SOCKET_IDLE_TIMEOUT)
      .build();

    Self {
      packet_sink,
      packet_stream,
      _join_set: tokio_join_set!(async move {
        let mut quic_flows = UdpQuicFlowTracker::default();
        loop {
          let Ok(packet) = packet_receiver.recv_async().await else {
            break;
          };
          let quic_flow_id = quic_flows.identify(&packet);

          Self::send_outgoing_packet(
            sockets.clone(),
            packet_sender.clone(),
            interface.as_deref(),
            quic_flow_id,
            packet,
          )
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
    sockets: Cache<UdpSocketKey, SocketTuple>,
    packet_sender: flume::Sender<IncomingUdpPacket>,
    interface: Option<&str>,
    quic_flow_id: Option<u64>,
    OutgoingUdpPacket {
      source,
      destination,
      response_destination,
      payload,
    }: OutgoingUdpPacket,
  ) -> Result<(), std::io::Error> {
    let socket_key = UdpSocketKey {
      source: source.clone(),
      response_destination,
      quic_flow_id,
    };
    let (socket, destination_address, metrics) = {
      if let Some((socket, destination_map, _, metrics)) = sockets.get(&socket_key) {
        if let Some(destination_ip) = destination_map.lock().unwrap().get(&destination.host) {
          (
            socket.clone(),
            SocketAddr::from((*destination_ip, destination.port)),
            metrics.clone(),
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

          (socket.clone(), destination_address, metrics.clone())
        }
      } else {
        let destination_socket_address =
          destination.resolve_connectable().await?.ok_or_else(|| {
            std::io::Error::other("Unable to resolve connectable destination socket address")
          })?;

        let socket = UdpSocket::bind(source.address.unspecified()).await?;
        bind_socket_to_interface(&socket, interface)?;
        let socket = socket.arc();
        let metrics = UdpSocketMetrics::new(socket.local_addr()?, quic_flow_id);

        log::debug!(
          "P2P_UDP_SOCKET_DEBUG action=create generation={} source={} quic_flow_id={:?} \
           local={} destination={} response_destination={response_destination:?}",
          metrics.generation,
          source.address,
          metrics.quic_flow_id,
          metrics.local_address,
          destination_socket_address,
        );

        let mut destination_map = HashMap::new();

        destination_map.insert(destination.host.clone(), destination_socket_address.ip());

        let join_set = tokio_join_set!(Self::listen(
          packet_sender.clone(),
          source.clone(),
          socket.clone(),
          response_destination,
          metrics.clone(),
        ));

        let socket_tuple = (
          socket.clone(),
          destination_map.mutex().arc(),
          join_set.arc(),
          metrics.clone(),
        );

        sockets.insert(socket_key, socket_tuple);

        (socket, destination_socket_address, metrics)
      }
    };

    log::trace!(
      "UDP outbound destination resolved: requested={destination}, actual={destination_address}, \
       response_destination={response_destination:?}"
    );
    let sent = socket.send_to(&payload, destination_address).await?;
    metrics.record_send(sent, &source, destination_address, response_destination);

    Ok(())
  }

  async fn listen(
    packet_sender: flume::Sender<IncomingUdpPacket>,
    source: UdpPacketSource,
    socket: Arc<UdpSocket>,
    response_destination: Option<SocketAddr>,
    metrics: Arc<UdpSocketMetrics>,
  ) {
    let mut buffer = vec![0; u16::MAX as usize];
    let mut dropped_packets = 0_u64;

    loop {
      let Ok((length, source_socket_address)) =
        socket.recv_from(&mut buffer).await.inspect_err(|error| {
          log::error!("error receiving packet: {}", error);
        })
      else {
        break;
      };
      metrics.record_receive(length, &source, source_socket_address, response_destination);

      match packet_sender.try_send(IncomingUdpPacket {
        source: source.clone(),
        destination: response_destination.unwrap_or(source_socket_address),
        payload: buffer[..length].to_vec(),
      }) {
        Ok(()) => {}
        Err(flume::TrySendError::Full(_)) => {
          dropped_packets = dropped_packets.wrapping_add(1);
          if dropped_packets.is_power_of_two() {
            log::warn!(
              "UDP forwarder response queue full; dropped {dropped_packets} packets for {}",
              source.address
            );
          }
        }
        Err(flume::TrySendError::Disconnected(_)) => break,
      }
    }
  }
}

#[derive(Default)]
struct UdpQuicFlowTracker {
  flows: HashMap<UdpQuicFlowKey, UdpQuicFlowState>,
  received_packets: u64,
  next_flow_id: u64,
}

impl UdpQuicFlowTracker {
  fn identify(&mut self, packet: &OutgoingUdpPacket) -> Option<u64> {
    self.received_packets = self.received_packets.wrapping_add(1);
    if self.received_packets.is_multiple_of(256) {
      self.expire();
    }

    let key = UdpQuicFlowKey {
      source: packet.source.clone(),
      destination_host: packet.destination.host.clone(),
      destination_port: packet.destination.port,
      response_destination: packet.response_destination,
    };
    let client_connection_id = quic_initial_client_connection_id(&packet.payload);
    if !self.flows.contains_key(&key) && client_connection_id.is_none() {
      return None;
    }
    let mut replaced_flow_id = None;
    if client_connection_id.as_ref().is_some_and(|connection_id| {
      self
        .flows
        .get(&key)
        .is_some_and(|state| state.client_connection_id != *connection_id)
    }) {
      replaced_flow_id = self.flows.remove(&key).map(|state| state.flow_id);
    }

    let client_connection_id = client_connection_id.unwrap_or_else(|| {
      self
        .flows
        .get(&key)
        .expect("non-Initial packet requires an existing QUIC forwarding flow")
        .client_connection_id
        .clone()
    });
    if !self.flows.contains_key(&key) {
      let flow_id = self.next_flow_id;
      self.next_flow_id = self.next_flow_id.wrapping_add(1);
      self.flows.insert(
        key.clone(),
        UdpQuicFlowState {
          client_connection_id,
          flow_id,
          last_seen: Instant::now(),
        },
      );
    }
    let state = self
      .flows
      .get_mut(&key)
      .expect("QUIC forwarding flow was inserted above");
    state.last_seen = Instant::now();
    if let Some(replaced_flow_id) = replaced_flow_id {
      log::debug!(
        "P2P_UDP_SOCKET_DEBUG action=rotate-reused-tuple source={} destination={}:{} \
         response_destination={:?} previous_quic_flow_id={replaced_flow_id} \
         quic_flow_id={}",
        key.source.address,
        key.destination_host,
        key.destination_port,
        key.response_destination,
        state.flow_id,
      );
    }
    Some(state.flow_id)
  }

  fn expire(&mut self) {
    self
      .flows
      .retain(|_, state| state.last_seen.elapsed() < UDP_SOCKET_IDLE_TIMEOUT);

    let excess = self.flows.len().saturating_sub(MAX_QUIC_FLOWS);
    if excess > 0 {
      let mut oldest = self
        .flows
        .iter()
        .map(|(key, state)| (key.clone(), state.last_seen))
        .collect::<Vec<_>>();
      oldest.sort_unstable_by_key(|(_, last_seen)| *last_seen);
      for (key, _) in oldest.into_iter().take(excess) {
        self.flows.remove(&key);
      }
    }
  }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct UdpQuicFlowKey {
  source: UdpPacketSource,
  destination_host: SocketDestinationHost,
  destination_port: u16,
  response_destination: Option<SocketAddr>,
}

struct UdpQuicFlowState {
  // The client SCID stays stable when a server Retry changes the Initial DCID,
  // so it identifies a connection without rotating its socket mid-handshake.
  client_connection_id: Vec<u8>,
  flow_id: u64,
  last_seen: Instant,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct UdpSocketKey {
  source: UdpPacketSource,
  response_destination: Option<SocketAddr>,
  quic_flow_id: Option<u64>,
}

type SocketTuple = (
  Arc<UdpSocket>,
  Arc<Mutex<HashMap<SocketDestinationHost, IpAddr>>>,
  Arc<JoinSet<()>>,
  Arc<UdpSocketMetrics>,
);

struct UdpSocketMetrics {
  generation: u64,
  quic_flow_id: Option<u64>,
  local_address: SocketAddr,
  created_at: Instant,
  sent_packets: AtomicU64,
  sent_bytes: AtomicU64,
  received_packets: AtomicU64,
  received_bytes: AtomicU64,
  last_receive_elapsed_ms: AtomicU64,
  last_report_elapsed_ms: AtomicU64,
}

impl UdpSocketMetrics {
  fn new(local_address: SocketAddr, quic_flow_id: Option<u64>) -> Arc<Self> {
    Arc::new(Self {
      generation: NEXT_UDP_SOCKET_GENERATION.fetch_add(1, Ordering::Relaxed),
      quic_flow_id,
      local_address,
      created_at: Instant::now(),
      sent_packets: AtomicU64::new(0),
      sent_bytes: AtomicU64::new(0),
      received_packets: AtomicU64::new(0),
      received_bytes: AtomicU64::new(0),
      last_receive_elapsed_ms: AtomicU64::new(0),
      last_report_elapsed_ms: AtomicU64::new(0),
    })
  }

  fn elapsed_ms(&self) -> u64 {
    u64::try_from(self.created_at.elapsed().as_millis()).unwrap_or(u64::MAX)
  }

  fn record_send(
    &self,
    length: usize,
    source: &UdpPacketSource,
    destination: SocketAddr,
    response_destination: Option<SocketAddr>,
  ) {
    self.sent_packets.fetch_add(1, Ordering::Relaxed);
    self.sent_bytes.fetch_add(length as u64, Ordering::Relaxed);

    let elapsed_ms = self.elapsed_ms();
    let last_report_ms = self.last_report_elapsed_ms.load(Ordering::Relaxed);
    if elapsed_ms.saturating_sub(last_report_ms) < UDP_SOCKET_DEBUG_REPORT_INTERVAL_MS
      || self
        .last_report_elapsed_ms
        .compare_exchange(
          last_report_ms,
          elapsed_ms,
          Ordering::Relaxed,
          Ordering::Relaxed,
        )
        .is_err()
    {
      return;
    }

    let received_packets = self.received_packets.load(Ordering::Relaxed);
    let response_idle = if received_packets == 0 {
      "never".to_owned()
    } else {
      elapsed_ms
        .saturating_sub(self.last_receive_elapsed_ms.load(Ordering::Relaxed))
        .to_string()
    };
    log::debug!(
      "P2P_UDP_SOCKET_DEBUG action=progress generation={} age_ms={elapsed_ms} source={} \
       quic_flow_id={:?} local={} destination={destination} \
       response_destination={response_destination:?} sent_packets={} sent_bytes={} \
       received_packets={received_packets} received_bytes={} response_idle_ms={response_idle}",
      self.generation,
      source.address,
      self.quic_flow_id,
      self.local_address,
      self.sent_packets.load(Ordering::Relaxed),
      self.sent_bytes.load(Ordering::Relaxed),
      self.received_bytes.load(Ordering::Relaxed),
    );
  }

  fn record_receive(
    &self,
    length: usize,
    source: &UdpPacketSource,
    remote: SocketAddr,
    response_destination: Option<SocketAddr>,
  ) {
    let received_packets = self.received_packets.fetch_add(1, Ordering::Relaxed) + 1;
    self
      .received_bytes
      .fetch_add(length as u64, Ordering::Relaxed);
    let elapsed_ms = self.elapsed_ms();
    self
      .last_receive_elapsed_ms
      .store(elapsed_ms, Ordering::Relaxed);
    if received_packets == 1 {
      log::debug!(
        "P2P_UDP_SOCKET_DEBUG action=first-response generation={} age_ms={elapsed_ms} source={} \
         quic_flow_id={:?} local={} remote={remote} \
         response_destination={response_destination:?} bytes={length}",
        self.generation,
        source.address,
        self.quic_flow_id,
        self.local_address,
      );
    }
  }
}

impl Sink<OutgoingUdpPacket> for UdpForwarder {
  type Error = UdpPacketStreamError;

  fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_ready(cx)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn start_send(mut self: Pin<&mut Self>, item: OutgoingUdpPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink)
      .start_send(item)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_flush(cx)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_close(cx)
      .map_err(|_| UdpPacketStreamError::Closed)
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

#[cfg(target_os = "linux")]
fn bind_socket_to_interface(socket: &UdpSocket, interface: Option<&str>) -> std::io::Result<()> {
  if let Some(interface) = interface {
    SockRef::from(socket).bind_device(Some(interface.as_bytes()))?;
  }

  Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bind_socket_to_interface(_: &UdpSocket, interface: Option<&str>) -> std::io::Result<()> {
  if interface.is_some() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "bind.interface is only supported on Linux",
    ));
  }

  Ok(())
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
      routing_domain: None,
      routing_protocol: None,
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
      response_destination: None,
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
  async fn remote_domain_response_uses_transparent_destination() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
      let mut buffer = vec![0u8; 1500];
      let (length, source) = server_socket.recv_from(&mut buffer).await.unwrap();
      server_socket
        .send_to(&buffer[..length], source)
        .await
        .unwrap();
    });
    let mut forwarder = UdpForwarder::new();
    let source_address = "127.0.0.1:12346".parse().unwrap();
    let transparent_destination = SocketAddr::from((
      "203.0.113.8".parse::<IpAddr>().unwrap(),
      server_address.port(),
    ));

    forwarder
      .send(OutgoingUdpPacket {
        source: create_source(source_address),
        destination: SocketDestination {
          host: SocketDestinationHost::DomainName("localhost".to_owned()),
          port: server_address.port(),
          routing_domain: None,
          routing_protocol: None,
        },
        response_destination: Some(transparent_destination),
        payload: b"remote DNS".to_vec(),
      })
      .await
      .unwrap();

    server_handle.await.unwrap();
    let incoming_packet = forwarder.next().await.unwrap();
    assert_eq!(incoming_packet.destination, transparent_destination);
    assert_eq!(incoming_packet.source.address, source_address);
    assert_eq!(incoming_packet.payload, b"remote DNS");
  }

  #[tokio::test]
  async fn test_packet_larger_than_ethernet_mtu() {
    let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();
    let payload = vec![0x5a; 4096];
    let expected_payload = payload.clone();
    let server_handle = tokio::spawn(async move {
      let mut buffer = vec![0; 8192];
      let (length, source) = server_socket.recv_from(&mut buffer).await.unwrap();
      server_socket
        .send_to(&buffer[..length], source)
        .await
        .unwrap();
    });
    let mut forwarder = UdpForwarder::new();

    forwarder
      .send(OutgoingUdpPacket {
        source: create_source("[::1]:12349".parse().unwrap()),
        destination: create_destination(server_address),
        response_destination: None,
        payload,
      })
      .await
      .unwrap();

    server_handle.await.unwrap();
    let incoming = forwarder.next().await.unwrap();
    assert_eq!(incoming.payload, expected_payload);
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
        response_destination: None,
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
      response_destination: None,
      payload: b"from source 1".to_vec(),
    };

    let packet_2 = OutgoingUdpPacket {
      source: create_source(source_address_2),
      destination: create_destination(server_address_2),
      response_destination: None,
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
  async fn new_quic_flow_on_reused_source_uses_new_socket() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server_socket.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
      let mut buffer = [0; 1500];
      let mut source_ports = Vec::new();
      for _ in 0..3 {
        let (_, source) = server_socket.recv_from(&mut buffer).await.unwrap();
        source_ports.push(source.port());
      }
      source_ports
    });

    let mut forwarder = UdpForwarder::new();
    let source_address = "127.0.0.1:20003".parse().unwrap();
    let first_initial = quic_initial(source_address, server_address, 7);
    let second_initial = quic_initial(source_address, server_address, 8);
    for payload in [first_initial.clone(), first_initial, second_initial] {
      forwarder
        .send(OutgoingUdpPacket {
          source: create_source(source_address),
          destination: create_destination(server_address),
          response_destination: None,
          payload,
        })
        .await
        .unwrap();
    }

    let source_ports = server_handle.await.unwrap();
    assert_eq!(source_ports[0], source_ports[1]);
    assert_ne!(source_ports[0], source_ports[2]);
  }

  fn quic_initial(source: SocketAddr, destination: SocketAddr, connection_id_byte: u8) -> Vec<u8> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"]).unwrap();
    let connection_id_bytes = [connection_id_byte; 16];
    let connection_id = quiche::ConnectionId::from_ref(&connection_id_bytes);
    let mut connection = quiche::connect(
      Some("socket-generation.example"),
      &connection_id,
      source,
      destination,
      &mut config,
    )
    .unwrap();
    let mut packet = vec![0; 1350];
    let (length, _) = connection.send(&mut packet).unwrap();
    packet.truncate(length);
    packet
  }

  #[tokio::test]
  async fn server_cid_change_keeps_quic_socket() -> anyhow::Result<()> {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_address = server_socket.local_addr()?;
    let source_address = "127.0.0.1:20004".parse()?;
    for retry in [false, true] {
      let mut forwarder = UdpForwarder::new();
      let [first, next] = crate::test::quic_initials_with_server_cid(
        source_address,
        server_address,
        "socket.example",
        retry,
      )
      .await?;
      let mut observed_source = None;
      // Include a retransmitted Initial and subsequent short-header traffic.
      for payload in [first.clone(), first, next, vec![0x40; 32]] {
        forwarder
          .send(OutgoingUdpPacket {
            source: create_source(source_address),
            destination: create_destination(server_address),
            response_destination: None,
            payload: payload.clone(),
          })
          .await?;
        let mut buffer = [0; 1500];
        let (length, source) = tokio::time::timeout(
          std::time::Duration::from_secs(2),
          server_socket.recv_from(&mut buffer),
        )
        .await??;
        assert_eq!(&buffer[..length], payload);
        assert_eq!(*observed_source.get_or_insert(source), source);
      }
    }
    Ok(())
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
        routing_domain: None,
        routing_protocol: None,
      },
      response_destination: None,
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
          routing_domain: None,
          routing_protocol: None,
        },
        response_destination: None,
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
