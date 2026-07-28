use std::{
  collections::HashMap,
  net::SocketAddr,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
  time::{Duration, Instant},
};

use async_trait::async_trait;
use colored::Colorize;
use futures::{Sink, Stream};
use lowkit::SelfWrapExt;
use socks5_server::{
  AssociatedUdpSocket, Command, Connect, IncomingConnection, Server,
  auth::NoAuth,
  connection::{connect::state::Ready, state::NeedAuthenticate},
  proto::{Address, Reply, UdpHeader},
};
use tokio::{
  io::{AsyncRead, AsyncWrite, ReadBuf},
  net::{TcpListener, UdpSocket},
  sync::mpsc,
  task::JoinSet,
};

use crate::{
  inbound::{Error, Inbound},
  primitives::{BidiStream, SocketDestination, SocketDestinationHost},
  sniff::{QuicSniffer, TcpSniffOptions, sniff_tcp_stream},
  udp_forwarder::{
    InboundUdpPacketStream, IncomingUdpPacket, OutgoingUdpPacket, UdpPacketSource,
    UdpPacketStreamError,
  },
};

#[derive(Debug)]
pub struct Socks5Inbound {
  listen_address: SocketAddr,
  tcp_connect_receiver:
    tokio::sync::Mutex<mpsc::UnboundedReceiver<(SocketDestination, Box<dyn BidiStream>)>>,
  udp_packet_stream: tokio::sync::Mutex<Option<Socks5UdpPacketStream>>,
  _join_set: JoinSet<()>,
}

pub struct Socks5InboundOptions {
  pub listen: SocketAddr,
  pub sniff: bool,
}

impl Socks5Inbound {
  pub async fn new(options: Socks5InboundOptions) -> Result<Self, Error> {
    let tcp_listener = TcpListener::bind(options.listen).await?;

    let listen_address = tcp_listener.local_addr()?;
    let udp_socket = UdpSocket::bind(listen_address).await?;
    let udp_relay_address = udp_socket.local_addr()?;
    let udp_socket = AssociatedUdpSocket::new(udp_socket, u16::MAX as usize).arc();

    log::info!(
      "{} TCP and UDP are listening on {}...",
      "SOCKS5".red(),
      listen_address.to_string().yellow()
    );

    let server = Server::new(tcp_listener, NoAuth.arc());

    let (tcp_connect_sender, tcp_connect_receiver) = mpsc::unbounded_channel();
    let (incoming_packet_sender, incoming_packet_receiver) = flume::unbounded();
    let (outgoing_packet_sender, outgoing_packet_receiver) = flume::unbounded();
    let udp_packet_stream = Socks5UdpPacketStream {
      packet_sink: incoming_packet_sender.into_sink(),
      packet_stream: outgoing_packet_receiver.into_stream(),
    };
    let mut join_set = JoinSet::new();

    join_set.spawn(async move {
      loop {
        let (connection, peer_address) = server.accept().await.unwrap();

        let tcp_connect_sender = tcp_connect_sender.clone();

        tokio::spawn(async move {
          handle_incoming_connection(
            connection,
            peer_address,
            udp_relay_address,
            tcp_connect_sender,
            options.sniff,
          )
          .await
          .inspect_err(|error| {
            log::error!("error handling incoming connection: {}", error);
          })
          .ok();
        });
      }
    });

    join_set.spawn(run_udp_socket(
      udp_socket,
      outgoing_packet_sender,
      incoming_packet_receiver,
      options.sniff,
    ));

    Self {
      listen_address,
      tcp_connect_receiver: tokio::sync::Mutex::new(tcp_connect_receiver),
      udp_packet_stream: Some(udp_packet_stream).tokio_mutex(),
      _join_set: join_set,
    }
    .wrap_ok()
  }

  pub fn listen_address(&self) -> SocketAddr {
    self.listen_address
  }
}

#[async_trait]
impl Inbound for Socks5Inbound {
  async fn accept_tcp_connect(&self) -> Result<(SocketDestination, Box<dyn BidiStream>), Error> {
    let mut tcp_connect_receiver = self.tcp_connect_receiver.lock().await;

    tcp_connect_receiver.recv().await.ok_or(Error::Closed)
  }

  async fn get_udp_packet_stream(&self) -> Result<Box<dyn InboundUdpPacketStream>, Error> {
    self
      .udp_packet_stream
      .lock()
      .await
      .take()
      .map(|stream| Box::new(stream) as Box<dyn InboundUdpPacketStream>)
      .ok_or(Error::Closed)
  }
}

pub struct Socks5TcpStream {
  stream: Connect<Ready>,
}

impl AsyncRead for Socks5TcpStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    context: &mut Context,
    buffer: &mut ReadBuf,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.stream).poll_read(context, buffer)
  }
}

impl AsyncWrite for Socks5TcpStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    context: &mut Context,
    buffer: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    Pin::new(&mut self.stream).poll_write(context, buffer)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    context: &mut Context,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.stream).poll_flush(context)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    context: &mut Context,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.stream).poll_shutdown(context)
  }
}

#[derive(Debug)]
pub struct Socks5UdpPacketStream {
  packet_sink: flume::r#async::SendSink<'static, IncomingUdpPacket>,
  packet_stream: flume::r#async::RecvStream<'static, OutgoingUdpPacket>,
}

impl Sink<IncomingUdpPacket> for Socks5UdpPacketStream {
  type Error = UdpPacketStreamError;

  fn poll_ready(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.get_mut().packet_sink)
      .poll_ready(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn start_send(self: Pin<&mut Self>, packet: IncomingUdpPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.get_mut().packet_sink)
      .start_send(packet)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_flush(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.get_mut().packet_sink)
      .poll_flush(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_close(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.get_mut().packet_sink)
      .poll_close(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }
}

impl Stream for Socks5UdpPacketStream {
  type Item = OutgoingUdpPacket;

  fn poll_next(self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.get_mut().packet_stream).poll_next(context)
  }
}

async fn run_udp_socket(
  socket: Arc<AssociatedUdpSocket>,
  outgoing_packet_sender: flume::Sender<OutgoingUdpPacket>,
  incoming_packet_receiver: flume::Receiver<IncomingUdpPacket>,
  sniff: bool,
) {
  let mut quic_flows = HashMap::new();
  let mut received_packets = 0_u64;

  loop {
    tokio::select! {
      received = socket.recv_from() => {
        match received {
          Ok((payload, header, source_address)) => {
            if header.frag != 0 {
              log::debug!(
                "ignoring fragmented SOCKS5 UDP packet from {source_address}: FRAG={}",
                header.frag
              );
              continue;
            }

            let mut destination: SocketDestination = header.address.into();
            if sniff {
              sniff_udp_destination(
                &mut destination,
                &payload,
                source_address,
                &mut quic_flows,
              );
              received_packets += 1;
              if received_packets.is_multiple_of(256) {
                expire_quic_flows(&mut quic_flows);
              }
            }

            let packet = OutgoingUdpPacket {
              source: UdpPacketSource {
                via: vec![],
                address: source_address,
              },
              destination,
              payload: payload.to_vec(),
            };

            if outgoing_packet_sender.send_async(packet).await.is_err() {
              break;
            }
          }
          Err((error, _)) => {
            log::warn!("invalid SOCKS5 UDP packet: {error}");
          }
        }
      }
      incoming = incoming_packet_receiver.recv_async() => {
        let Ok(IncomingUdpPacket {
          source,
          destination,
          payload,
        }) = incoming else {
          break;
        };
        let header = UdpHeader::new(0, Address::SocketAddress(destination));

        if let Err(error) = socket.send_to(payload, &header, source.address).await {
          log::warn!("error sending SOCKS5 UDP response to {}: {error}", source.address);
        }
      }
    }
  }
}

async fn handle_incoming_connection(
  connection: IncomingConnection<(), NeedAuthenticate>,
  peer_address: SocketAddr,
  udp_relay_address: SocketAddr,
  tcp_connect_sender: mpsc::UnboundedSender<(SocketDestination, Box<dyn BidiStream>)>,
  sniff: bool,
) -> Result<(), Error> {
  let (connection, _) = connection.authenticate().await?;

  match connection.wait().await? {
    Command::Connect(connect_command, address) => {
      log::debug!("SOCKS5 CONNECT {peer_address} -> {address}");

      let connect = connect_command
        .reply(Reply::Succeeded, Address::unspecified())
        .await?;

      let mut destination: SocketDestination = address.into();
      let stream = Socks5TcpStream { stream: connect };
      let stream: Box<dyn BidiStream> =
        if sniff && matches!(&destination.host, SocketDestinationHost::IpAddress(_)) {
          let sniffed = sniff_tcp_stream(stream, TcpSniffOptions::default()).await?;
          if let Some(sniffed_domain) = sniffed.domain {
            log::debug!(
              "sniffed {:?} domain {} while preserving SOCKS5 destination {}",
              sniffed_domain.protocol,
              sniffed_domain.domain,
              destination
            );
            destination.set_routing_domain(Some(sniffed_domain.domain));
          }
          Box::new(sniffed.stream)
        } else {
          Box::new(stream)
        };

      tcp_connect_sender.send((destination, stream)).unwrap()
    }
    Command::Associate(associate_command, _address) => {
      let udp_relay_address = if udp_relay_address.ip().is_unspecified() {
        SocketAddr::new(
          associate_command.local_addr()?.ip(),
          udp_relay_address.port(),
        )
      } else {
        udp_relay_address
      };

      log::debug!("SOCKS5 UDP ASSOCIATE {peer_address} -> {udp_relay_address}");

      let mut associate = associate_command
        .reply(Reply::Succeeded, Address::SocketAddress(udp_relay_address))
        .await?;
      associate.wait_close().await?;
    }
    Command::Bind(bind_command, _address) => {
      bind_command
        .reply(Reply::CommandNotSupported, Address::unspecified())
        .await?;
    }
  }

  Ok(())
}

const QUIC_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_QUIC_FLOWS: usize = 4096;

struct QuicFlowSniffState {
  sniffer: Option<QuicSniffer>,
  domain: Option<String>,
  last_seen: Instant,
}

fn sniff_udp_destination(
  destination: &mut SocketDestination,
  payload: &[u8],
  source: SocketAddr,
  flows: &mut HashMap<(SocketAddr, SocketDestination), QuicFlowSniffState>,
) {
  let SocketDestinationHost::IpAddress(destination_ip) = &destination.host else {
    return;
  };
  let key = (source, destination.clone());

  if !flows.contains_key(&key) && !QuicSniffer::looks_like_initial(payload) {
    return;
  }

  let state = flows.entry(key).or_insert_with(|| QuicFlowSniffState {
    sniffer: Some(QuicSniffer::new()),
    domain: None,
    last_seen: Instant::now(),
  });
  state.last_seen = Instant::now();

  if state.domain.is_none() {
    let destination_address = SocketAddr::new(*destination_ip, destination.port);
    if let Some(sniffer) = &mut state.sniffer {
      match sniffer.sniff_datagram(payload, source, destination_address) {
        crate::sniff::SniffOutcome::Domain(sniffed) => {
          log::debug!(
            "sniffed {:?} domain {} while preserving SOCKS5 UDP destination {}",
            sniffed.protocol,
            sniffed.domain,
            destination
          );
          state.domain = Some(sniffed.domain);
          state.sniffer = None;
        }
        crate::sniff::SniffOutcome::NoDomain => {
          state.sniffer = None;
        }
        crate::sniff::SniffOutcome::NeedMoreData => {}
      }
    }
  }

  destination.set_routing_domain(state.domain.clone());
}

fn expire_quic_flows(flows: &mut HashMap<(SocketAddr, SocketDestination), QuicFlowSniffState>) {
  flows.retain(|_, state| state.last_seen.elapsed() < QUIC_FLOW_IDLE_TIMEOUT);

  while flows.len() > MAX_QUIC_FLOWS {
    let Some(oldest) = flows
      .iter()
      .min_by_key(|(_, state)| state.last_seen)
      .map(|(key, _)| key.clone())
    else {
      break;
    };
    flows.remove(&oldest);
  }
}

impl From<socks5_server::proto::Address> for SocketDestination {
  fn from(address: socks5_server::proto::Address) -> Self {
    match address {
      socks5_server::proto::Address::DomainAddress(domain, port) => SocketDestination {
        host: SocketDestinationHost::DomainName(String::from_utf8_lossy(&domain).into_owned()),
        port,
        routing_domain: None,
      },
      socks5_server::proto::Address::SocketAddress(socket_address) => SocketDestination {
        host: SocketDestinationHost::IpAddress(socket_address.ip()),
        port: socket_address.port(),
        routing_domain: None,
      },
    }
  }
}

impl<T> From<(std::io::Error, T)> for Error {
  fn from((error, _): (std::io::Error, T)) -> Self {
    Error::Io(error)
  }
}

impl<T> From<(socks5_server::proto::Error, T)> for Error {
  fn from((error, _): (socks5_server::proto::Error, T)) -> Self {
    Error::Io(error.into())
  }
}

#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::oneshot,
    time::{Duration, timeout},
  };

  use crate::{
    inbound::Inbound,
    primitives::{SocketDestination, SocketDestinationHost},
    udp_forwarder::IncomingUdpPacket,
  };

  use super::*;

  #[tokio::test]
  async fn accept_tcp_connect_returns_destination_and_stream() -> anyhow::Result<()> {
    let inbound = Socks5Inbound::new(Socks5InboundOptions {
      listen: "127.0.0.1:0".parse()?,
      sniff: true,
    })
    .await?;
    let listen_address = inbound.listen_address();
    let (accept_result_sender, accept_result_receiver) = oneshot::channel();

    tokio::spawn(async move {
      let accept_result = async {
        let (destination, mut tcp_stream) = inbound
          .accept_tcp_connect()
          .await
          .map_err(std::io::Error::other)?;
        let mut received_payload = [0u8; 4];
        tcp_stream.read_exact(&mut received_payload).await?;
        tcp_stream.write_all(b"pong").await?;
        Ok::<_, std::io::Error>((destination, received_payload))
      }
      .await;

      let _ = accept_result_sender.send(accept_result);
    });

    let mut client_stream = TcpStream::connect(listen_address).await?;

    let handshake_request = socks5_server::proto::handshake::Request::new(vec![
      socks5_server::proto::handshake::Method::NONE,
    ]);
    handshake_request.write_to(&mut client_stream).await?;

    let handshake_response =
      socks5_server::proto::handshake::Response::read_from(&mut client_stream).await?;
    assert!(matches!(
      handshake_response.method,
      socks5_server::proto::handshake::Method::NONE
    ));

    let destination_address =
      socks5_server::proto::Address::DomainAddress(b"example.com".to_vec(), 443);
    let connect_request = socks5_server::proto::Request::new(
      socks5_server::proto::Command::Connect,
      destination_address,
    );
    connect_request.write_to(&mut client_stream).await?;

    let connect_response = socks5_server::proto::Response::read_from(&mut client_stream).await?;
    assert!(matches!(
      connect_response.reply,
      socks5_server::proto::Reply::Succeeded
    ));

    client_stream.write_all(b"ping").await?;
    let mut client_receive_buffer = [0u8; 4];
    client_stream.read_exact(&mut client_receive_buffer).await?;
    assert_eq!(&client_receive_buffer, b"pong");

    let (destination, received_payload) = accept_result_receiver.await??;

    assert_eq!(&received_payload, b"ping");
    assert_destination(destination, "example.com", 443);

    Ok(())
  }

  #[tokio::test]
  async fn tcp_sniff_preserves_ip_and_replays_client_hello() -> anyhow::Result<()> {
    let inbound = Socks5Inbound::new(Socks5InboundOptions {
      listen: "127.0.0.1:0".parse()?,
      sniff: true,
    })
    .await?;
    let listen_address = inbound.listen_address();
    let mut client_stream = TcpStream::connect(listen_address).await?;

    socks5_server::proto::handshake::Request::new(vec![
      socks5_server::proto::handshake::Method::NONE,
    ])
    .write_to(&mut client_stream)
    .await?;
    socks5_server::proto::handshake::Response::read_from(&mut client_stream).await?;

    let original_address: SocketAddr = "182.140.143.139:443".parse()?;
    socks5_server::proto::Request::new(
      socks5_server::proto::Command::Connect,
      Address::SocketAddress(original_address),
    )
    .write_to(&mut client_stream)
    .await?;
    let response = socks5_server::proto::Response::read_from(&mut client_stream).await?;
    assert!(matches!(response.reply, Reply::Succeeded));

    let client_hello = test_tls_client_hello("c2c.cdn.weixin.qq.com");
    for chunk in client_hello.chunks(11) {
      client_stream.write_all(chunk).await?;
    }

    let (destination, mut stream) =
      timeout(Duration::from_secs(3), inbound.accept_tcp_connect()).await??;
    assert_eq!(
      destination.host,
      SocketDestinationHost::IpAddress(original_address.ip())
    );
    assert_eq!(destination.port, original_address.port());
    assert_eq!(
      destination.routing_domain.as_deref(),
      Some("c2c.cdn.weixin.qq.com")
    );

    let mut replayed = vec![0; client_hello.len()];
    stream.read_exact(&mut replayed).await?;
    assert_eq!(replayed, client_hello);
    Ok(())
  }

  #[tokio::test]
  async fn udp_associate_preserves_domain_and_returns_response() -> anyhow::Result<()> {
    let inbound = Socks5Inbound::new(Socks5InboundOptions {
      listen: "127.0.0.1:0".parse()?,
      sniff: true,
    })
    .await?;
    let listen_address = inbound.listen_address();
    let mut packet_stream = inbound.get_udp_packet_stream().await?;
    let mut control_stream = TcpStream::connect(listen_address).await?;

    let handshake_request = socks5_server::proto::handshake::Request::new(vec![
      socks5_server::proto::handshake::Method::NONE,
    ]);
    handshake_request.write_to(&mut control_stream).await?;
    socks5_server::proto::handshake::Response::read_from(&mut control_stream).await?;

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_client_address = udp_socket.local_addr()?;
    let associate_request = socks5_server::proto::Request::new(
      socks5_server::proto::Command::Associate,
      Address::SocketAddress(udp_client_address),
    );
    associate_request.write_to(&mut control_stream).await?;
    let associate_response = socks5_server::proto::Response::read_from(&mut control_stream).await?;
    assert!(matches!(associate_response.reply, Reply::Succeeded));
    let Address::SocketAddress(udp_relay_address) = associate_response.address else {
      panic!("expected a socket address in UDP ASSOCIATE response");
    };
    let udp_socket = AssociatedUdpSocket::new(udp_socket, u16::MAX as usize);
    let destination = Address::DomainAddress(b"example.com".to_vec(), 53);

    udp_socket
      .send_to(
        b"dns query",
        &UdpHeader::new(0, destination.clone()),
        udp_relay_address,
      )
      .await?;

    let outgoing = timeout(Duration::from_secs(3), packet_stream.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("SOCKS5 UDP packet stream closed"))?;
    assert_eq!(outgoing.source.address, udp_client_address);
    assert_eq!(outgoing.destination, destination.into());
    assert_eq!(outgoing.payload, b"dns query");

    let response_source = "203.0.113.7:53".parse()?;
    packet_stream
      .send(IncomingUdpPacket {
        source: outgoing.source,
        destination: response_source,
        payload: b"dns response".to_vec(),
      })
      .await?;

    let (payload, header, relay_source) = timeout(Duration::from_secs(3), udp_socket.recv_from())
      .await?
      .map_err(|(error, _)| std::io::Error::from(error))?;
    assert_eq!(relay_source, udp_relay_address);
    assert_eq!(header.frag, 0);
    assert_eq!(header.address, Address::SocketAddress(response_source));
    assert_eq!(&payload[..], b"dns response");

    Ok(())
  }

  #[tokio::test]
  async fn udp_sniff_preserves_ip_and_extracts_quic_sni() -> anyhow::Result<()> {
    let inbound = Socks5Inbound::new(Socks5InboundOptions {
      listen: "127.0.0.1:0".parse()?,
      sniff: true,
    })
    .await?;
    let listen_address = inbound.listen_address();
    let mut packet_stream = inbound.get_udp_packet_stream().await?;
    let mut control_stream = TcpStream::connect(listen_address).await?;

    socks5_server::proto::handshake::Request::new(vec![
      socks5_server::proto::handshake::Method::NONE,
    ])
    .write_to(&mut control_stream)
    .await?;
    socks5_server::proto::handshake::Response::read_from(&mut control_stream).await?;

    let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_client_address = udp_socket.local_addr()?;
    socks5_server::proto::Request::new(
      socks5_server::proto::Command::Associate,
      Address::SocketAddress(udp_client_address),
    )
    .write_to(&mut control_stream)
    .await?;
    let associate_response = socks5_server::proto::Response::read_from(&mut control_stream).await?;
    let Address::SocketAddress(udp_relay_address) = associate_response.address else {
      panic!("expected a socket address in UDP ASSOCIATE response");
    };
    let udp_socket = AssociatedUdpSocket::new(udp_socket, u16::MAX as usize);

    let original_address: SocketAddr = "203.0.113.7:443".parse()?;
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    quic_config.verify_peer(false);
    quic_config.set_application_protos(&[b"h3"])?;
    let source_connection_id = quiche::ConnectionId::from_ref(&[0x42; 16]);
    let mut quic_client = quiche::connect(
      Some("passkeys.example.com"),
      &source_connection_id,
      udp_client_address,
      original_address,
      &mut quic_config,
    )?;
    let mut initial = vec![0; 1350];
    let (initial_length, _) = quic_client.send(&mut initial)?;

    udp_socket
      .send_to(
        &initial[..initial_length],
        &UdpHeader::new(0, Address::SocketAddress(original_address)),
        udp_relay_address,
      )
      .await?;

    let outgoing = timeout(Duration::from_secs(3), packet_stream.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("SOCKS5 UDP packet stream closed"))?;
    assert_eq!(outgoing.source.address, udp_client_address);
    assert_eq!(
      outgoing.destination.host,
      SocketDestinationHost::IpAddress(original_address.ip())
    );
    assert_eq!(outgoing.destination.port, original_address.port());
    assert_eq!(
      outgoing.destination.routing_domain.as_deref(),
      Some("passkeys.example.com")
    );
    assert_eq!(outgoing.payload, initial[..initial_length]);

    udp_socket
      .send_to(
        b"\x40encrypted-follow-up",
        &UdpHeader::new(0, Address::SocketAddress(original_address)),
        udp_relay_address,
      )
      .await?;
    let follow_up = timeout(Duration::from_secs(3), packet_stream.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("SOCKS5 UDP packet stream closed"))?;
    assert_eq!(
      follow_up.destination.routing_domain.as_deref(),
      Some("passkeys.example.com")
    );
    assert_eq!(follow_up.payload, b"\x40encrypted-follow-up");
    Ok(())
  }

  fn assert_destination(destination: SocketDestination, domain: &str, port: u16) {
    assert_eq!(destination.port, port);
    match destination.host {
      SocketDestinationHost::DomainName(domain_name) => assert_eq!(domain_name, domain),
      SocketDestinationHost::IpAddress(_) => panic!("expected domain destination"),
    }
  }

  fn test_tls_client_hello(domain: &str) -> Vec<u8> {
    let domain = domain.as_bytes();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&((domain.len() + 3) as u16).to_be_bytes());
    server_name.push(0);
    server_name.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    server_name.extend_from_slice(domain);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&server_name);

    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303_u16.to_be_bytes());
    hello.extend_from_slice(&[7; 32]);
    hello.push(0);
    hello.extend_from_slice(&2_u16.to_be_bytes());
    hello.extend_from_slice(&0x1301_u16.to_be_bytes());
    hello.extend_from_slice(&[1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![
      1,
      ((hello.len() >> 16) & 0xff) as u8,
      ((hello.len() >> 8) & 0xff) as u8,
      (hello.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&hello);

    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
  }
}
