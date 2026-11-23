use std::{
  collections::{HashMap, VecDeque},
  future::Future,
  net::SocketAddr,
  pin::Pin,
  task::{Context, Poll},
  time::{Duration, Instant},
};

use futures::{Sink, Stream};
use tokio::time::{Instant as TokioInstant, Sleep, sleep_until};

use crate::{
  primitives::{BidiStream, SniffedProtocol, SocketDestination, SocketDestinationHost},
  sniff::{QuicSniffer, SniffOutcome, TcpSniffOptions, quic_initial_dcid, sniff_tcp_stream},
  udp_forwarder::{
    InboundUdpPacketStream, IncomingUdpPacket, OutgoingUdpPacket, UdpPacketStreamError,
  },
};

pub async fn sniff_tcp_ingress(
  mut destination: SocketDestination,
  stream: Box<dyn BidiStream>,
) -> std::io::Result<(SocketDestination, Box<dyn BidiStream>)> {
  let sniffed = sniff_tcp_stream(stream, TcpSniffOptions::default()).await?;
  log::debug!(
    "TCP sniff: destination={}, result={:?}, elapsed_ms={}, bytes={}, protocol={}, domain={}",
    destination,
    sniffed.end_reason,
    sniffed.elapsed.as_millis(),
    sniffed.bytes_read,
    sniffed
      .protocol
      .map(|protocol| protocol.to_string())
      .as_deref()
      .unwrap_or("-"),
    sniffed
      .domain
      .as_ref()
      .map(|domain| domain.domain.as_str())
      .unwrap_or("-")
  );

  destination.set_routing_protocol(sniffed.protocol);
  if let Some(sniffed_domain) = sniffed.domain {
    destination.set_routing_domain(Some(sniffed_domain.domain));
  }

  Ok((destination, Box::new(sniffed.stream)))
}

const QUIC_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_QUIC_FLOWS: usize = 1024;
const QUIC_INITIAL_SNIFF_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_BUFFERED_QUIC_INITIAL_PACKETS: usize = 8;
const MAX_BUFFERED_QUIC_INITIAL_BYTES: usize = 16 * 1024;
const MAX_PENDING_QUIC_FLOWS: usize = 256;

type QuicFlowKey = (SocketAddr, SocketAddr);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpSniffStatus {
  Resolved,
  NeedMoreData { flow_key: QuicFlowKey },
}

struct QuicFlowSniffState {
  sniffer: Option<QuicSniffer>,
  initial_dcid: Vec<u8>,
  domain: Option<String>,
  protocol: Option<SniffedProtocol>,
  last_seen: Instant,
}

#[derive(Default)]
pub struct UdpDestinationSniffer {
  flows: HashMap<QuicFlowKey, QuicFlowSniffState>,
  received_packets: u64,
}

impl UdpDestinationSniffer {
  pub fn sniff(&mut self, destination: &mut SocketDestination, payload: &[u8], source: SocketAddr) {
    let _ = self.sniff_status(destination, payload, source);
  }

  fn sniff_status(
    &mut self,
    destination: &mut SocketDestination,
    payload: &[u8],
    source: SocketAddr,
  ) -> UdpSniffStatus {
    self.received_packets = self.received_packets.wrapping_add(1);
    if self.received_packets.is_multiple_of(256) {
      self.expire_flows();
    }

    let SocketDestinationHost::IpAddress(destination_ip) = &destination.host else {
      return UdpSniffStatus::Resolved;
    };
    let destination_address = SocketAddr::new(*destination_ip, destination.port);
    let key = (source, destination_address);
    let initial_dcid = quic_initial_dcid(payload);

    if !self.flows.contains_key(&key) && initial_dcid.is_none() {
      return UdpSniffStatus::Resolved;
    }

    if let Some(dcid) = &initial_dcid
      && let Some(state) = self.flows.get_mut(&key)
      && state.initial_dcid != *dcid
    {
      // A server-selected DCID or Retry also changes this value. Probe for a
      // new ClientHello, but retain the route until its SNI can be decoded.
      // The probe survives across datagrams for fragmented ClientHellos.
      state.initial_dcid = dcid.clone();
      state.sniffer = Some(QuicSniffer::new());
    }

    let initial_dcid = initial_dcid.unwrap_or_else(|| {
      self
        .flows
        .get(&key)
        .expect("non-Initial packet requires an existing QUIC sniff flow")
        .initial_dcid
        .clone()
    });
    let state = self.flows.entry(key).or_insert_with(|| QuicFlowSniffState {
      sniffer: Some(QuicSniffer::new()),
      initial_dcid,
      domain: None,
      protocol: None,
      last_seen: Instant::now(),
    });
    state.last_seen = Instant::now();

    if let Some(sniffer) = &mut state.sniffer {
      match sniffer.sniff_datagram(payload, source, destination_address) {
        SniffOutcome::Domain(sniffed) => {
          log::debug!(
            "sniffed {:?} domain {} while preserving UDP destination {}",
            sniffed.protocol,
            sniffed.domain,
            destination
          );
          state.domain = Some(sniffed.domain);
          state.protocol = Some(sniffed.protocol);
          state.sniffer = None;
        }
        SniffOutcome::Protocol(protocol) => {
          state.protocol = Some(protocol);
          state.sniffer = None;
        }
        SniffOutcome::NoDomain => {
          state.sniffer = None;
        }
        SniffOutcome::NeedMoreData => {}
      }
    }

    destination.set_routing_domain(state.domain.clone());
    destination.set_routing_protocol(state.protocol);

    if state.sniffer.is_some() {
      UdpSniffStatus::NeedMoreData { flow_key: key }
    } else {
      UdpSniffStatus::Resolved
    }
  }

  fn apply_flow_metadata(&self, destination: &mut SocketDestination, flow_key: QuicFlowKey) {
    if let Some(state) = self.flows.get(&flow_key) {
      destination.set_routing_domain(state.domain.clone());
      destination.set_routing_protocol(state.protocol);
    }
  }

  fn abandon_active_sniff(&mut self, flow_key: QuicFlowKey) {
    if let Some(state) = self.flows.get_mut(&flow_key) {
      state.sniffer = None;
    }
  }

  fn active_dcid(&self, flow_key: QuicFlowKey) -> Option<&[u8]> {
    self
      .flows
      .get(&flow_key)
      .map(|state| state.initial_dcid.as_slice())
  }

  fn expire_flows(&mut self) {
    self
      .flows
      .retain(|_, state| state.last_seen.elapsed() < QUIC_FLOW_IDLE_TIMEOUT);

    let excess = self.flows.len().saturating_sub(MAX_QUIC_FLOWS);
    if excess > 0 {
      let mut oldest = self
        .flows
        .iter()
        .map(|(key, state)| (*key, state.last_seen))
        .collect::<Vec<_>>();
      oldest.sort_unstable_by_key(|(_, last_seen)| *last_seen);
      for (key, _) in oldest.into_iter().take(excess) {
        self.flows.remove(&key);
      }
    }
  }
}

struct PendingQuicInitial {
  packets: VecDeque<OutgoingUdpPacket>,
  buffered_bytes: usize,
  deadline: TokioInstant,
}

pub struct SniffingUdpPacketStream {
  inner: Box<dyn InboundUdpPacketStream>,
  destination_sniffer: UdpDestinationSniffer,
  pending_flows: HashMap<QuicFlowKey, PendingQuicInitial>,
  ready: VecDeque<OutgoingUdpPacket>,
  flush_timer: Option<Pin<Box<Sleep>>>,
}

impl SniffingUdpPacketStream {
  pub fn new(inner: Box<dyn InboundUdpPacketStream>) -> Self {
    Self {
      inner,
      destination_sniffer: UdpDestinationSniffer::default(),
      pending_flows: HashMap::new(),
      ready: VecDeque::new(),
      flush_timer: None,
    }
  }

  fn release_flow(&mut self, flow_key: QuicFlowKey, abandon_sniff: bool) {
    if abandon_sniff {
      self.destination_sniffer.abandon_active_sniff(flow_key);
    }

    let Some(pending) = self.pending_flows.remove(&flow_key) else {
      return;
    };

    for mut buffered in pending.packets {
      self
        .destination_sniffer
        .apply_flow_metadata(&mut buffered.destination, flow_key);
      self.ready.push_back(buffered);
    }
  }

  fn flush_expired_flows(&mut self, now: TokioInstant) {
    let mut expired = self
      .pending_flows
      .iter()
      .filter_map(|(&key, pending)| (pending.deadline <= now).then_some((pending.deadline, key)))
      .collect::<Vec<_>>();
    expired.sort_unstable_by_key(|(deadline, _)| *deadline);

    for (_, flow_key) in expired {
      self.release_flow(flow_key, true);
    }
  }

  fn flush_all_flows(&mut self) {
    let mut all = self
      .pending_flows
      .iter()
      .map(|(&key, pending)| (pending.deadline, key))
      .collect::<Vec<_>>();
    all.sort_unstable_by_key(|(deadline, _)| *deadline);

    for (_, flow_key) in all {
      self.release_flow(flow_key, true);
    }
  }

  fn handle_incoming_packet(&mut self, mut packet: OutgoingUdpPacket) {
    if let SocketDestinationHost::IpAddress(destination_ip) = &packet.destination.host {
      let flow_key = (
        packet.source.address,
        SocketAddr::new(*destination_ip, packet.destination.port),
      );
      if self.pending_flows.contains_key(&flow_key)
        && let Some(new_dcid) = quic_initial_dcid(&packet.payload)
        && self.destination_sniffer.active_dcid(flow_key) != Some(new_dcid.as_slice())
      {
        self.release_flow(flow_key, true);
      }
    }

    let status = self.destination_sniffer.sniff_status(
      &mut packet.destination,
      &packet.payload,
      packet.source.address,
    );

    match status {
      UdpSniffStatus::Resolved => {
        if let SocketDestinationHost::IpAddress(destination_ip) = &packet.destination.host {
          let flow_key = (
            packet.source.address,
            SocketAddr::new(*destination_ip, packet.destination.port),
          );
          if self.pending_flows.contains_key(&flow_key) {
            self.release_flow(flow_key, false);
          }
        }
        self.ready.push_back(packet);
      }
      UdpSniffStatus::NeedMoreData { flow_key } => {
        let can_buffer = match self.pending_flows.get(&flow_key) {
          Some(pending) => {
            pending.packets.len() < MAX_BUFFERED_QUIC_INITIAL_PACKETS
              && pending.buffered_bytes.saturating_add(packet.payload.len())
                <= MAX_BUFFERED_QUIC_INITIAL_BYTES
          }
          None => {
            self.pending_flows.len() < MAX_PENDING_QUIC_FLOWS
              && packet.payload.len() <= MAX_BUFFERED_QUIC_INITIAL_BYTES
          }
        };

        if can_buffer {
          let payload_len = packet.payload.len();
          let pending =
            self
              .pending_flows
              .entry(flow_key)
              .or_insert_with(|| PendingQuicInitial {
                packets: VecDeque::new(),
                buffered_bytes: 0,
                deadline: TokioInstant::now() + QUIC_INITIAL_SNIFF_TIMEOUT,
              });
          pending.buffered_bytes += payload_len;
          pending.packets.push_back(packet);
        } else {
          self.release_flow(flow_key, true);
          self
            .destination_sniffer
            .apply_flow_metadata(&mut packet.destination, flow_key);
          self.ready.push_back(packet);
        }
      }
    }
  }
}

impl Sink<IncomingUdpPacket> for SniffingUdpPacketStream {
  type Error = UdpPacketStreamError;

  fn poll_ready(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.inner).poll_ready(context)
  }

  fn start_send(mut self: Pin<&mut Self>, packet: IncomingUdpPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.inner).start_send(packet)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.inner).poll_flush(context)
  }

  fn poll_close(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.inner).poll_close(context)
  }
}

impl Stream for SniffingUdpPacketStream {
  type Item = OutgoingUdpPacket;

  fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    let this = self.as_mut().get_mut();

    loop {
      if let Some(packet) = this.ready.pop_front() {
        return Poll::Ready(Some(packet));
      }

      if !this.pending_flows.is_empty() {
        this.flush_expired_flows(TokioInstant::now());
        if let Some(packet) = this.ready.pop_front() {
          return Poll::Ready(Some(packet));
        }
      }

      match Pin::new(&mut this.inner).poll_next(context) {
        Poll::Ready(Some(packet)) => {
          this.handle_incoming_packet(packet);
        }
        Poll::Ready(None) => {
          this.flush_all_flows();
          this.flush_timer = None;
          return Poll::Ready(this.ready.pop_front());
        }
        Poll::Pending => {
          let Some(earliest_deadline) = this
            .pending_flows
            .values()
            .map(|pending| pending.deadline)
            .min()
          else {
            this.flush_timer = None;
            return Poll::Pending;
          };

          match &mut this.flush_timer {
            Some(timer) => timer.as_mut().reset(earliest_deadline),
            None => this.flush_timer = Some(Box::pin(sleep_until(earliest_deadline))),
          }

          if this
            .flush_timer
            .as_mut()
            .unwrap()
            .as_mut()
            .poll(context)
            .is_ready()
          {
            continue;
          }

          return Poll::Pending;
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt, poll};
  use tokio::{io::duplex, net::UdpSocket};

  use super::*;
  use crate::{
    quic_connection::MAX_DATAGRAM_SIZE,
    sniff::SniffedDomain,
    udp_forwarder::{UdpForwarder, UdpPacketSource, UdpPacketStream},
  };

  fn quic_initial(
    server_name: &str,
    source: SocketAddr,
    destination: SocketAddr,
    connection_id_byte: u8,
  ) -> anyhow::Result<Vec<u8>> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"])?;
    let connection_id_bytes = [connection_id_byte; 16];
    let connection_id = quiche::ConnectionId::from_ref(&connection_id_bytes);
    let mut connection = quiche::connect(
      Some(server_name),
      &connection_id,
      source,
      destination,
      &mut config,
    )?;
    let mut packet = vec![0; 1350];
    let (length, _) = connection.send(&mut packet)?;
    packet.truncate(length);
    Ok(packet)
  }

  fn fragmented_quic_initials(
    server_name: &str,
    source: SocketAddr,
    destination: SocketAddr,
    connection_id_byte: u8,
  ) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1200);
    config.set_application_protos(&[
      b"h3",
      &[b'a'; 240],
      &[b'b'; 240],
      &[b'c'; 240],
      &[b'd'; 240],
      &[b'e'; 240],
    ])?;

    let connection_id_bytes = [connection_id_byte; 16];
    let connection_id = quiche::ConnectionId::from_ref(&connection_id_bytes);
    let mut connection = quiche::connect(
      Some(server_name),
      &connection_id,
      source,
      destination,
      &mut config,
    )?;

    let mut packets = Vec::new();
    loop {
      let mut packet = vec![0; 1200];
      match connection.send(&mut packet) {
        Ok((length, _)) => {
          packet.truncate(length);
          packets.push(packet);
        }
        Err(quiche::Error::Done) => break,
        Err(error) => return Err(error.into()),
      }
    }

    assert!(
      packets.len() >= 2,
      "expected multi-datagram QUIC Initial ClientHello, got {} packet(s)",
      packets.len()
    );
    Ok(packets)
  }

  fn destination(address: SocketAddr) -> SocketDestination {
    SocketDestination {
      host: SocketDestinationHost::IpAddress(address.ip()),
      port: address.port(),
      routing_domain: None,
      routing_protocol: None,
    }
  }

  fn outgoing_packet(source: SocketAddr, target: SocketAddr, payload: Vec<u8>) -> OutgoingUdpPacket {
    OutgoingUdpPacket {
      source: UdpPacketSource {
        via: Vec::new(),
        address: source,
      },
      destination: destination(target),
      response_destination: None,
      payload,
    }
  }

  fn rewrite_sniffed_route(mut packet: OutgoingUdpPacket) -> OutgoingUdpPacket {
    if let (SocketDestinationHost::IpAddress(ip), Some(domain)) = (
      packet.destination.host.clone(),
      packet.destination.routing_domain.clone(),
    ) {
      let original_address = SocketAddr::new(ip, packet.destination.port);
      packet.destination = SocketDestination {
        host: SocketDestinationHost::DomainName(domain),
        port: packet.destination.port,
        routing_domain: Some(original_address.ip().to_string()),
        routing_protocol: packet.destination.routing_protocol,
      };
      packet.response_destination = Some(original_address);
    }

    packet
  }

  #[test]
  fn new_quic_initial_replaces_metadata_for_reused_tuple() -> anyhow::Result<()> {
    let source = "192.0.2.10:54321".parse()?;
    let target = "203.0.113.7:443".parse()?;
    let mut sniffer = UdpDestinationSniffer::default();

    let mut first_destination = destination(target);
    sniffer.sniff(
      &mut first_destination,
      &quic_initial("first.example", source, target, 1)?,
      source,
    );
    assert_eq!(
      first_destination.routing_domain.as_deref(),
      Some("first.example")
    );

    let mut second_destination = destination(target);
    sniffer.sniff(
      &mut second_destination,
      &quic_initial("second.example", source, target, 2)?,
      source,
    );
    assert_eq!(
      second_destination.routing_domain.as_deref(),
      Some("second.example")
    );
    assert_eq!(
      second_destination.routing_protocol,
      Some(SniffedProtocol::Quic)
    );
    Ok(())
  }

  #[test]
  fn retransmitted_initial_keeps_metadata_for_same_dcid() -> anyhow::Result<()> {
    let source = "192.0.2.10:54321".parse()?;
    let target = "203.0.113.7:443".parse()?;
    let initial = quic_initial("stable.example", source, target, 7)?;
    let mut sniffer = UdpDestinationSniffer::default();

    let mut first = destination(target);
    sniffer.sniff(&mut first, &initial, source);
    assert_eq!(first.routing_domain.as_deref(), Some("stable.example"));

    let mut retransmission = destination(target);
    sniffer.sniff(&mut retransmission, &initial, source);
    assert_eq!(
      retransmission.routing_domain.as_deref(),
      Some("stable.example")
    );
    assert_eq!(retransmission.routing_protocol, Some(SniffedProtocol::Quic));
    Ok(())
  }

  #[tokio::test]
  async fn server_cid_change_keeps_quic_routing_metadata() -> anyhow::Result<()> {
    let source = "192.0.2.10:54321".parse()?;
    let target = "203.0.113.7:443".parse()?;
    for retry in [false, true] {
      let (writer, reader) = duplex(MAX_DATAGRAM_SIZE * 4);
      let mut sender =
        UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(writer));
      let inbound = UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(reader));
      let mut stream = SniffingUdpPacketStream::new(Box::new(inbound));

      let packets =
        crate::test::quic_initials_with_server_cid(source, target, "stable.example", retry).await?;
      for packet in packets {
        sender.send(outgoing_packet(source, target, packet)).await?;
        let emitted = tokio::time::timeout(Duration::from_millis(5), stream.next())
          .await?
          .expect("expected immediate packet without buffering stall");
        assert_eq!(
          emitted.destination.routing_domain.as_deref(),
          Some("stable.example")
        );
        assert_eq!(
          emitted.destination.routing_protocol,
          Some(SniffedProtocol::Quic)
        );
      }

      // A genuinely new ClientHello on the same tuple must still refresh SNI,
      // even when both connections have an empty SCID.
      let [new_initial, _] =
        crate::test::quic_initials_with_server_cid(source, target, "new.example", retry).await?;
      sender
        .send(outgoing_packet(source, target, new_initial))
        .await?;
      let refreshed = tokio::time::timeout(Duration::from_millis(5), stream.next())
        .await?
        .expect("expected refreshed initial");
      assert_eq!(
        refreshed.destination.routing_domain.as_deref(),
        Some("new.example")
      );
    }
    Ok(())
  }

  #[tokio::test]
  async fn fragmented_quic_initial_holds_first_datagram_and_keeps_single_udp_socket()
  -> anyhow::Result<()> {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let target = server_socket.local_addr()?;
    let source: SocketAddr = "100.107.52.74:58123".parse()?;

    let fragments = fragmented_quic_initials("localhost", source, target, 0x55)?;
    let mut raw_sniffer = QuicSniffer::new();
    assert_eq!(
      raw_sniffer.sniff_datagram(&fragments[0], source, target),
      SniffOutcome::NeedMoreData
    );
    assert_eq!(
      raw_sniffer.sniff_datagram(&fragments[1], source, target),
      SniffOutcome::Domain(SniffedDomain {
        protocol: SniffedProtocol::Quic,
        domain: "localhost".to_owned(),
      })
    );

    for reverse_order in [false, true] {
      let (writer, reader) = duplex(MAX_DATAGRAM_SIZE * 4);
      let mut sender =
        UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(writer));
      let inbound = UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(reader));
      let mut sniffing_stream = SniffingUdpPacketStream::new(Box::new(inbound));

      let ordered = if reverse_order {
        vec![fragments[1].clone(), fragments[0].clone()]
      } else {
        vec![fragments[0].clone(), vec![0x43, 0x01, 0x02, 0x03], fragments[1].clone()]
      };

      sender
        .send(outgoing_packet(source, target, ordered[0].clone()))
        .await?;
      assert!(poll!(sniffing_stream.next()).is_pending());

      for payload in &ordered[1..] {
        sender
          .send(outgoing_packet(source, target, payload.clone()))
          .await?;
      }

      let mut forwarder = UdpForwarder::new();
      let mut received_from_ports = Vec::new();
      let mut recv_buf = vec![0u8; 2048];

      for expected_payload in &ordered {
        let sniffed = sniffing_stream
          .next()
          .await
          .expect("expected released QUIC packet");
        assert_eq!(&sniffed.payload, expected_payload);
        assert_eq!(
          sniffed.destination.routing_domain.as_deref(),
          Some("localhost")
        );
        assert_eq!(
          sniffed.destination.routing_protocol,
          Some(SniffedProtocol::Quic)
        );

        forwarder.send(rewrite_sniffed_route(sniffed)).await?;
        let (len, from_addr) =
          tokio::time::timeout(Duration::from_secs(2), server_socket.recv_from(&mut recv_buf))
            .await??;
        assert_eq!(&recv_buf[..len], expected_payload.as_slice());
        received_from_ports.push(from_addr);
      }

      assert!(
        received_from_ports.windows(2).all(|pair| pair[0] == pair[1]),
        "all fragmented QUIC Initial packets must share one outbound UDP socket: {received_from_ports:?}",
      );
    }

    Ok(())
  }

  #[tokio::test(start_paused = true)]
  async fn fragmented_quic_initial_timeout_flushes_without_mid_handshake_route_split()
  -> anyhow::Result<()> {
    let source: SocketAddr = "100.107.52.74:58124".parse()?;
    let target: SocketAddr = "203.0.113.7:443".parse()?;
    let fragments = fragmented_quic_initials("s.youtube.com", source, target, 0x77)?;

    let (writer, reader) = duplex(MAX_DATAGRAM_SIZE * 4);
    let mut sender = UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(writer));
    let inbound = UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(reader));
    let mut sniffing_stream = SniffingUdpPacketStream::new(Box::new(inbound));

    sender
      .send(outgoing_packet(source, target, fragments[0].clone()))
      .await?;
    assert!(poll!(sniffing_stream.next()).is_pending());

    tokio::time::advance(QUIC_INITIAL_SNIFF_TIMEOUT + Duration::from_millis(1)).await;
    let first_emitted = sniffing_stream
      .next()
      .await
      .expect("expected timeout-flushed Initial[0]");
    assert_eq!(first_emitted.payload, fragments[0]);
    assert_eq!(first_emitted.destination.routing_domain, None);

    // A late Initial[1] for the same DCID must keep the already-emitted route
    // (`None`) instead of flipping mid-handshake to `DomainName`.
    sender
      .send(outgoing_packet(source, target, fragments[1].clone()))
      .await?;
    let late_second = sniffing_stream
      .next()
      .await
      .expect("expected immediate late Initial[1]");
    assert_eq!(late_second.payload, fragments[1]);
    assert_eq!(late_second.destination.routing_domain, None);

    // A brand-new connection on the same tuple with a new DCID sniffs normally.
    let fresh = fragmented_quic_initials("s.youtube.com", source, target, 0x88)?;
    sender
      .send(outgoing_packet(source, target, fresh[0].clone()))
      .await?;
    sender
      .send(outgoing_packet(source, target, fresh[1].clone()))
      .await?;

    for expected in &fresh[..2] {
      let emitted = sniffing_stream.next().await.expect("expected fresh packet");
      assert_eq!(&emitted.payload, expected);
      assert_eq!(
        emitted.destination.routing_domain.as_deref(),
        Some("s.youtube.com")
      );
    }

    Ok(())
  }
}
