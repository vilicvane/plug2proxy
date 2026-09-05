use std::{
  collections::HashMap,
  net::SocketAddr,
  pin::Pin,
  task::{Context, Poll},
  time::{Duration, Instant},
};

use futures::{Sink, Stream};

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

struct QuicFlowSniffState {
  sniffer: Option<QuicSniffer>,
  initial_dcid: Vec<u8>,
  domain: Option<String>,
  protocol: Option<SniffedProtocol>,
  last_seen: Instant,
}

#[derive(Default)]
pub struct UdpDestinationSniffer {
  flows: HashMap<(SocketAddr, SocketAddr), QuicFlowSniffState>,
  received_packets: u64,
}

impl UdpDestinationSniffer {
  pub fn sniff(&mut self, destination: &mut SocketDestination, payload: &[u8], source: SocketAddr) {
    self.received_packets = self.received_packets.wrapping_add(1);
    if self.received_packets.is_multiple_of(256) {
      self.expire_flows();
    }

    let SocketDestinationHost::IpAddress(destination_ip) = &destination.host else {
      return;
    };
    let destination_address = SocketAddr::new(*destination_ip, destination.port);
    let key = (source, destination_address);
    let initial_dcid = quic_initial_dcid(payload);

    if !self.flows.contains_key(&key) && initial_dcid.is_none() {
      return;
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

pub struct SniffingUdpPacketStream {
  inner: Box<dyn InboundUdpPacketStream>,
  destination_sniffer: UdpDestinationSniffer,
}

impl SniffingUdpPacketStream {
  pub fn new(inner: Box<dyn InboundUdpPacketStream>) -> Self {
    Self {
      inner,
      destination_sniffer: UdpDestinationSniffer::default(),
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
    match Pin::new(&mut self.inner).poll_next(context) {
      Poll::Ready(Some(mut packet)) => {
        self.destination_sniffer.sniff(
          &mut packet.destination,
          &packet.payload,
          packet.source.address,
        );
        Poll::Ready(Some(packet))
      }
      result => result,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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

  fn destination(address: SocketAddr) -> SocketDestination {
    SocketDestination {
      host: SocketDestinationHost::IpAddress(address.ip()),
      port: address.port(),
      routing_domain: None,
      routing_protocol: None,
    }
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
      let mut sniffer = UdpDestinationSniffer::default();
      let packets =
        crate::test::quic_initials_with_server_cid(source, target, "stable.example", retry).await?;
      for packet in packets {
        let mut destination = destination(target);
        sniffer.sniff(&mut destination, &packet, source);
        assert_eq!(
          destination.routing_domain.as_deref(),
          Some("stable.example")
        );
        assert_eq!(destination.routing_protocol, Some(SniffedProtocol::Quic));
      }
      // A genuinely new ClientHello on the same tuple must still refresh SNI,
      // even when both connections have an empty SCID.
      let [new_initial, _] =
        crate::test::quic_initials_with_server_cid(source, target, "new.example", retry).await?;
      let mut new_destination = destination(target);
      sniffer.sniff(&mut new_destination, &new_initial, source);
      assert_eq!(
        new_destination.routing_domain.as_deref(),
        Some("new.example")
      );
    }
    Ok(())
  }
}
