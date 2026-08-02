use std::{
  mem,
  net::{Ipv4Addr, Ipv6Addr, SocketAddr},
  os::fd::{AsRawFd, RawFd},
  pin::Pin,
  ptr,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  task::{Context, Poll},
  time::Duration,
};

use async_trait::async_trait;
use futures::{Sink, Stream};
use lowkit::SelfWrapExt;
use moka::sync::Cache;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
  io::copy_bidirectional,
  net::{TcpListener, UdpSocket},
  sync::{Semaphore, mpsc},
  task::JoinSet,
};

use crate::{
  inbound::{Error, Inbound, SniffingUdpPacketStream, sniff_tcp_ingress},
  primitives::{BidiStream, SocketDestination, SocketDestinationHost},
  udp_forwarder::{
    InboundUdpPacketStream, IncomingUdpPacket, OutgoingUdpPacket, UdpPacketSource,
    UdpPacketStreamError,
  },
  utils::task::reap_finished_tasks,
};

const TCP_PENDING_CONNECTIONS: usize = 1024;
const UDP_PACKET_QUEUE_CAPACITY: usize = 4096;
const UDP_RESPONSE_SOCKET_CAPACITY: u64 = 4096;
const UDP_RESPONSE_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const UDP_RECEIVE_BUFFER_SIZE: usize = u16::MAX as usize;
const DNS_PROXY_CONCURRENCY: usize = 1024;
const TCP_DNS_PROXY_CONCURRENCY: usize = 256;
const DNS_PROXY_TIMEOUT: Duration = Duration::from_secs(10);
const CAPABILITY_PROBE_ADDRESS: SocketAddr =
  SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53));
static SO_MARK_WARNING_LOGGED: AtomicBool = AtomicBool::new(false);

pub const TPROXY_MARK_MASK: u32 = 0xff00_0000;
pub const TPROXY_OUTPUT_ROUTE_MARK: u32 = 0x5100_0000;
pub const TPROXY_BYPASS_MARK: u32 = 0x5200_0000;
pub const TPROXY_PREROUTING_ROUTE_MARK: u32 = 0x5300_0000;

#[derive(Debug)]
pub struct TproxyInbound {
  listen_address: SocketAddr,
  tcp_connect_receiver:
    tokio::sync::Mutex<mpsc::Receiver<(SocketDestination, Box<dyn BidiStream>)>>,
  udp_packet_stream: tokio::sync::Mutex<Option<TproxyUdpPacketStream>>,
  sniff: bool,
  _join_set: JoinSet<()>,
}

#[derive(Clone, Copy, Debug)]
pub struct TproxyInboundOptions {
  pub listen: SocketAddr,
  pub sniff: bool,
  pub bypass_mark: u32,
  pub bypass_uid: u32,
  pub dns_hijack: Option<SocketAddr>,
}

impl TproxyInbound {
  pub async fn new(options: TproxyInboundOptions) -> Result<Self, Error> {
    if !options.listen.is_ipv4() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::Unsupported,
          "TPROXY currently supports IPv4 listeners only",
        )
        .into(),
      );
    }
    if !options.listen.ip().is_loopback() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "TPROXY listener must use an IPv4 loopback address",
        )
        .into(),
      );
    }
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != options.bypass_uid {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::PermissionDenied,
          format!(
            "TPROXY bypass user uid {} does not match process effective uid {effective_uid}",
            options.bypass_uid
          ),
        )
        .into(),
      );
    }
    if options
      .dns_hijack
      .is_some_and(|dns_hijack| listeners_overlap(options.listen, dns_hijack))
    {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "TPROXY listener and DNS hijack listener must not overlap",
        )
        .into(),
      );
    }

    probe_response_socket_capabilities(options.bypass_mark).map_err(|error| {
      std::io::Error::new(
        error.kind(),
        format!(
          "TPROXY startup capability probe failed; the process needs CAP_NET_RAW and \
           CAP_NET_BIND_SERVICE: {error}"
        ),
      )
    })?;

    let tcp_listener = create_tcp_listener(options.listen)?;
    let listen_address = tcp_listener.local_addr()?;
    let udp_socket = create_udp_socket(listen_address)?;

    let (tcp_connect_sender, tcp_connect_receiver) = mpsc::channel(TCP_PENDING_CONNECTIONS);
    let (outgoing_packet_sender, outgoing_packet_receiver) =
      flume::bounded(UDP_PACKET_QUEUE_CAPACITY);
    let (incoming_packet_sender, incoming_packet_receiver) =
      flume::bounded(UDP_PACKET_QUEUE_CAPACITY);

    let udp_packet_stream = TproxyUdpPacketStream {
      packet_sink: incoming_packet_sender.into_sink(),
      packet_stream: outgoing_packet_receiver.into_stream(),
    };
    let mut join_set = JoinSet::new();
    join_set.spawn(run_tcp_listener(
      tcp_listener,
      tcp_connect_sender,
      options.sniff,
      options.dns_hijack,
    ));
    join_set.spawn(run_udp_socket(
      udp_socket,
      listen_address,
      outgoing_packet_sender,
      incoming_packet_receiver,
      options.bypass_mark,
      options.dns_hijack,
    ));

    log::info!("TPROXY TCP and UDP are listening on {listen_address}...");

    Self {
      listen_address,
      tcp_connect_receiver: tcp_connect_receiver.tokio_mutex(),
      udp_packet_stream: Some(udp_packet_stream).tokio_mutex(),
      sniff: options.sniff,
      _join_set: join_set,
    }
    .wrap_ok()
  }

  pub fn listen_address(&self) -> SocketAddr {
    self.listen_address
  }
}

#[async_trait]
impl Inbound for TproxyInbound {
  async fn accept_tcp_connect(&self) -> Result<(SocketDestination, Box<dyn BidiStream>), Error> {
    self
      .tcp_connect_receiver
      .lock()
      .await
      .recv()
      .await
      .ok_or(Error::Closed)
  }

  async fn get_udp_packet_stream(&self) -> Result<Box<dyn InboundUdpPacketStream>, Error> {
    let stream = self
      .udp_packet_stream
      .lock()
      .await
      .take()
      .map(|stream| Box::new(stream) as Box<dyn InboundUdpPacketStream>)
      .ok_or(Error::Closed)?;

    if self.sniff {
      Ok(Box::new(SniffingUdpPacketStream::new(stream)))
    } else {
      Ok(stream)
    }
  }
}

async fn run_tcp_listener(
  listener: TcpListener,
  sender: mpsc::Sender<(SocketDestination, Box<dyn BidiStream>)>,
  sniff: bool,
  dns_hijack: Option<SocketAddr>,
) {
  let permits = Arc::new(Semaphore::new(TCP_PENDING_CONNECTIONS));
  let dns_permits = Arc::new(Semaphore::new(TCP_DNS_PROXY_CONCURRENCY));
  let mut connections = JoinSet::new();
  let listen_address = listener.local_addr().ok();

  loop {
    reap_finished_tasks(&mut connections, "TPROXY TCP ingress task");

    let permit = tokio::select! {
      _ = sender.closed() => break,
      permit = permits.clone().acquire_owned() => {
        let Ok(permit) = permit else {
          break;
        };
        permit
      }
    };

    let (stream, source) = match listener.accept().await {
      Ok(accepted) => accepted,
      Err(error) => {
        log::warn!("error accepting TPROXY TCP connection: {error}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        continue;
      }
    };

    let sender = sender.clone();
    let dns_permits = dns_permits.clone();
    connections.spawn(async move {
      let original_destination = match stream.local_addr() {
        Ok(address) => address,
        Err(error) => {
          log::warn!("cannot obtain TPROXY TCP destination for {source}: {error}");
          return;
        }
      };
      if is_direct_listener_destination(original_destination, listen_address) {
        log::warn!(
          "rejecting direct connection to TPROXY listener from {source}; traffic must arrive via TPROXY"
        );
        return;
      }
      if original_destination.port() == 53
        && let Some(dns_hijack) = dns_hijack
      {
        drop(permit);
        let Ok(_dns_permit) = dns_permits.try_acquire_owned() else {
          log::warn!("TPROXY TCP DNS concurrency limit reached; rejecting {source}");
          return;
        };
        let dns_hijack = connectable_local_address(dns_hijack);
        match tokio::net::TcpStream::connect(dns_hijack).await {
          Ok(mut dns_stream) => {
            let mut stream = stream;
            if let Err(error) = copy_bidirectional(&mut stream, &mut dns_stream).await {
              log::debug!(
                "TPROXY TCP DNS relay failed for {source} -> {original_destination}: {error}"
              );
            }
          }
          Err(error) => {
            log::warn!("cannot connect to local DNS listener {dns_hijack}: {error}");
          }
        }
        return;
      }
      let _permit = permit;
      let destination = socket_destination(original_destination);
      let stream: Box<dyn BidiStream> = Box::new(stream);
      let connection = if sniff {
        match sniff_tcp_ingress(destination, stream).await {
          Ok(connection) => connection,
          Err(error) => {
            log::debug!("TPROXY TCP sniff failed for {source} -> {original_destination}: {error}");
            return;
          }
        }
      } else {
        (destination, stream)
      };

      if sender.send(connection).await.is_err() {
        return;
      }

      log::debug!("TPROXY TCP accepted {source} -> {original_destination}");
    });
  }
}

fn create_tcp_listener(listen: SocketAddr) -> std::io::Result<TcpListener> {
  let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_reuse_address(true)?;
  socket.set_ip_transparent_v4(true)?;
  socket.set_nonblocking(true)?;
  socket.bind(&listen.into())?;
  socket.listen(1024)?;
  TcpListener::from_std(socket.into())
}

fn create_udp_socket(listen: SocketAddr) -> std::io::Result<tokio::io::unix::AsyncFd<Socket>> {
  let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_reuse_address(true)?;
  socket.set_ip_transparent_v4(true)?;
  set_socket_option(
    socket.as_raw_fd(),
    libc::IPPROTO_IP,
    libc::IP_RECVORIGDSTADDR,
    1,
  )?;
  socket.set_nonblocking(true)?;
  socket.bind(&listen.into())?;
  tokio::io::unix::AsyncFd::new(socket)
}

async fn run_udp_socket(
  socket: tokio::io::unix::AsyncFd<Socket>,
  listen_address: SocketAddr,
  outgoing_sender: flume::Sender<OutgoingUdpPacket>,
  incoming_receiver: flume::Receiver<IncomingUdpPacket>,
  bypass_mark: u32,
  dns_hijack: Option<SocketAddr>,
) {
  let response_sockets = Cache::builder()
    .max_capacity(UDP_RESPONSE_SOCKET_CAPACITY)
    .time_to_idle(UDP_RESPONSE_SOCKET_IDLE_TIMEOUT)
    .build();
  let mut buffer = vec![0; UDP_RECEIVE_BUFFER_SIZE];
  let mut dropped_packets = 0_u64;
  let dns_permits = Arc::new(Semaphore::new(DNS_PROXY_CONCURRENCY));
  let mut dns_tasks = JoinSet::new();

  loop {
    reap_finished_tasks(&mut dns_tasks, "TPROXY UDP DNS task");
    tokio::select! {
      received = receive_udp_datagram(&socket, &mut buffer) => {
        match received {
          Ok((length, source, destination)) => {
            if is_direct_listener_destination(destination, Some(listen_address)) {
              log::warn!(
                "ignoring direct UDP packet to TPROXY listener from {source}; traffic must arrive via TPROXY"
              );
              continue;
            }
            if destination.port() == 53
              && let Some(dns_hijack) = dns_hijack
            {
              let Ok(permit) = dns_permits.clone().try_acquire_owned() else {
                dropped_packets = dropped_packets.wrapping_add(1);
                if dropped_packets.is_power_of_two() {
                  log::warn!(
                    "TPROXY UDP DNS concurrency limit reached; dropped {dropped_packets} packets"
                  );
                }
                continue;
              };
              let payload = buffer[..length].to_vec();
              let response_sockets = response_sockets.clone();
              dns_tasks.spawn(async move {
                let _permit = permit;
                if let Err(error) = proxy_udp_dns(
                  response_sockets,
                  bypass_mark,
                  connectable_local_address(dns_hijack),
                  source,
                  destination,
                  payload,
                )
                .await
                {
                  log::debug!(
                    "TPROXY UDP DNS relay failed for {source} -> {destination}: {error}"
                  );
                }
              });
              continue;
            }
            let packet = OutgoingUdpPacket {
              source: UdpPacketSource {
                via: vec![],
                address: source,
              },
              destination: socket_destination(destination),
              response_destination: None,
              payload: buffer[..length].to_vec(),
            };

            match outgoing_sender.try_send(packet) {
              Ok(()) => {}
              Err(flume::TrySendError::Full(_)) => {
                dropped_packets = dropped_packets.wrapping_add(1);
                if dropped_packets.is_power_of_two() {
                  log::warn!(
                    "TPROXY UDP ingress queue full; dropped {dropped_packets} packets"
                  );
                }
              }
              Err(flume::TrySendError::Disconnected(_)) => break,
            }
          }
          Err(error) => {
            log::warn!("error receiving TPROXY UDP packet: {error}");
          }
        }
      }
      incoming = incoming_receiver.recv_async() => {
        let Ok(packet) = incoming else {
          break;
        };
        if let Err(error) = send_udp_response(&response_sockets, bypass_mark, packet).await {
          log::warn!("error sending TPROXY UDP response: {error}");
        }
      }
    }
  }
}

async fn proxy_udp_dns(
  response_sockets: Cache<SocketAddr, Arc<UdpSocket>>,
  bypass_mark: u32,
  dns_hijack: SocketAddr,
  source: SocketAddr,
  original_destination: SocketAddr,
  payload: Vec<u8>,
) -> std::io::Result<()> {
  let bind_address = match dns_hijack {
    SocketAddr::V4(_) => "0.0.0.0:0",
    SocketAddr::V6(_) => "[::]:0",
  };
  let socket = UdpSocket::bind(bind_address).await?;
  socket.connect(dns_hijack).await?;
  socket.send(&payload).await?;

  let mut response = vec![0; UDP_RECEIVE_BUFFER_SIZE];
  let length = tokio::time::timeout(DNS_PROXY_TIMEOUT, socket.recv(&mut response))
    .await
    .map_err(|_| {
      std::io::Error::new(std::io::ErrorKind::TimedOut, "local DNS response timed out")
    })??;
  response.truncate(length);
  send_udp_response(
    &response_sockets,
    bypass_mark,
    IncomingUdpPacket {
      source: UdpPacketSource {
        via: vec![],
        address: source,
      },
      destination: original_destination,
      payload: response,
    },
  )
  .await
}

async fn send_udp_response(
  sockets: &Cache<SocketAddr, Arc<UdpSocket>>,
  bypass_mark: u32,
  IncomingUdpPacket {
    source,
    destination,
    payload,
  }: IncomingUdpPacket,
) -> std::io::Result<()> {
  if !destination.is_ipv4() || !source.address.is_ipv4() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "TPROXY currently supports IPv4 UDP packets only",
    ));
  }

  let socket = if let Some(socket) = sockets.get(&destination) {
    socket
  } else {
    let socket = create_response_socket(destination, bypass_mark)?;
    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    sockets.insert(destination, socket.clone());
    socket
  };

  socket.send_to(&payload, source.address).await?;
  Ok(())
}

fn create_response_socket(destination: SocketAddr, bypass_mark: u32) -> std::io::Result<Socket> {
  let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_ip_transparent_v4(true)?;
  socket.set_reuse_address(true)?;
  socket.set_reuse_port(true)?;
  if bypass_mark != 0
    && let Err(error) = socket.set_mark(bypass_mark)
    && !SO_MARK_WARNING_LOGGED.swap(true, Ordering::Relaxed)
  {
    log::warn!(
      "cannot set TPROXY UDP response SO_MARK ({error}); continuing with verified UID bypass"
    );
  }
  socket.set_nonblocking(true)?;
  socket.bind(&destination.into())?;
  Ok(socket)
}

fn probe_response_socket_capabilities(bypass_mark: u32) -> std::io::Result<()> {
  drop(create_response_socket(
    CAPABILITY_PROBE_ADDRESS,
    bypass_mark,
  )?);
  Ok(())
}

fn socket_destination(address: SocketAddr) -> SocketDestination {
  SocketDestination {
    host: SocketDestinationHost::IpAddress(address.ip()),
    port: address.port(),
    routing_domain: None,
    routing_protocol: None,
  }
}

fn connectable_local_address(address: SocketAddr) -> SocketAddr {
  if address.ip().is_unspecified() {
    match address {
      SocketAddr::V4(address) => SocketAddr::from((Ipv4Addr::LOCALHOST, address.port())),
      SocketAddr::V6(address) => SocketAddr::from((Ipv6Addr::LOCALHOST, address.port())),
    }
  } else {
    address
  }
}

fn listeners_overlap(left: SocketAddr, right: SocketAddr) -> bool {
  left.port() == right.port()
    && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn is_direct_listener_destination(
  destination: SocketAddr,
  listen_address: Option<SocketAddr>,
) -> bool {
  let Some(listen_address) = listen_address else {
    return false;
  };
  destination.port() == listen_address.port()
    && (destination == listen_address
      || listen_address.ip().is_unspecified() && destination.ip().is_loopback())
}

#[derive(Debug)]
pub struct TproxyUdpPacketStream {
  packet_sink: flume::r#async::SendSink<'static, IncomingUdpPacket>,
  packet_stream: flume::r#async::RecvStream<'static, OutgoingUdpPacket>,
}

impl Sink<IncomingUdpPacket> for TproxyUdpPacketStream {
  type Error = UdpPacketStreamError;

  fn poll_ready(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_ready(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn start_send(mut self: Pin<&mut Self>, packet: IncomingUdpPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink)
      .start_send(packet)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_flush(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }

  fn poll_close(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink)
      .poll_close(context)
      .map_err(|_| UdpPacketStreamError::Closed)
  }
}

impl Stream for TproxyUdpPacketStream {
  type Item = OutgoingUdpPacket;

  fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(context)
  }
}

async fn receive_udp_datagram(
  socket: &tokio::io::unix::AsyncFd<Socket>,
  buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
  loop {
    let mut guard = socket.readable().await?;
    match receive_udp_datagram_now(socket.get_ref().as_raw_fd(), buffer) {
      Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
        guard.clear_ready();
      }
      result => return result,
    }
  }
}

#[repr(C, align(8))]
struct ControlBuffer([u8; 128]);

fn receive_udp_datagram_now(
  fd: RawFd,
  buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
  unsafe {
    let mut source_storage = mem::zeroed::<libc::sockaddr_storage>();
    let mut iovec = libc::iovec {
      iov_base: buffer.as_mut_ptr().cast(),
      iov_len: buffer.len(),
    };
    let mut control = ControlBuffer([0; 128]);
    let mut message = mem::zeroed::<libc::msghdr>();
    message.msg_name = (&mut source_storage as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();

    let length = libc::recvmsg(fd, &mut message, 0);
    if length < 0 {
      return Err(std::io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_TRUNC != 0 {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "TPROXY UDP datagram was truncated",
      ));
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "TPROXY UDP control message was truncated",
      ));
    }

    let source = copy_socket_address(message.msg_name, message.msg_namelen)?;
    let destination = original_destination(&message)?;
    Ok((length as usize, source, destination))
  }
}

unsafe fn copy_socket_address(
  source: *const libc::c_void,
  length: libc::socklen_t,
) -> std::io::Result<SocketAddr> {
  if source.is_null() || length == 0 || length as usize > mem::size_of::<libc::sockaddr_storage>() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "TPROXY packet contained an invalid socket address length",
    ));
  }
  let (_, address) = unsafe {
    SockAddr::try_init(|storage, storage_length| {
      ptr::copy_nonoverlapping(source.cast::<u8>(), storage.cast::<u8>(), length as usize);
      *storage_length = length;
      Ok(())
    })?
  };
  address.as_socket().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "TPROXY packet contained an invalid socket address",
    )
  })
}

fn original_destination(message: &libc::msghdr) -> std::io::Result<SocketAddr> {
  unsafe {
    let mut header = libc::CMSG_FIRSTHDR(message);
    while !header.is_null() {
      if (*header).cmsg_level == libc::SOL_IP && (*header).cmsg_type == libc::IP_RECVORIGDSTADDR {
        let address_length = mem::size_of::<libc::sockaddr_in>();
        if ((*header).cmsg_len as usize) < libc::CMSG_LEN(address_length as u32) as usize {
          return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TPROXY UDP original destination control message was too short",
          ));
        }
        return copy_socket_address(
          libc::CMSG_DATA(header).cast(),
          address_length as libc::socklen_t,
        );
      }
      header = libc::CMSG_NXTHDR(message, header);
    }
  }

  Err(std::io::Error::new(
    std::io::ErrorKind::InvalidData,
    "TPROXY UDP packet did not include its original destination",
  ))
}

fn set_socket_option(fd: RawFd, level: i32, name: i32, value: i32) -> std::io::Result<()> {
  let result = unsafe {
    libc::setsockopt(
      fd,
      level,
      name,
      (&value as *const i32).cast(),
      mem::size_of_val(&value) as libc::socklen_t,
    )
  };
  if result == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn socket_destination_preserves_ip_and_port() {
    let address: SocketAddr = "203.0.113.7:443".parse().unwrap();
    assert_eq!(
      socket_destination(address),
      SocketDestination {
        host: SocketDestinationHost::IpAddress(address.ip()),
        port: 443,
        routing_domain: None,
        routing_protocol: None,
      }
    );
  }

  #[test]
  fn listener_overlap_includes_unspecified_dns_address() {
    assert!(listeners_overlap(
      "127.0.0.1:12345".parse().unwrap(),
      "0.0.0.0:12345".parse().unwrap(),
    ));
    assert!(listeners_overlap(
      "127.0.0.1:12345".parse().unwrap(),
      "[::]:12345".parse().unwrap(),
    ));
    assert!(!listeners_overlap(
      "127.0.0.1:12345".parse().unwrap(),
      "127.0.0.1:5353".parse().unwrap(),
    ));
    assert!(!listeners_overlap(
      "127.0.0.1:12345".parse().unwrap(),
      "127.0.0.2:12345".parse().unwrap(),
    ));
  }

  #[test]
  fn rejects_overlapping_dns_listener_before_opening_privileged_sockets() {
    let error = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap()
      .block_on(TproxyInbound::new(TproxyInboundOptions {
        listen: "127.0.0.1:12345".parse().unwrap(),
        sniff: true,
        bypass_mark: 1,
        bypass_uid: unsafe { libc::geteuid() },
        dns_hijack: Some("0.0.0.0:12345".parse().unwrap()),
      }))
      .unwrap_err();
    assert!(error.to_string().contains("must not overlap"));
  }

  #[test]
  fn rejects_ipv6_before_opening_privileged_sockets() {
    let error = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap()
      .block_on(TproxyInbound::new(TproxyInboundOptions {
        listen: "[::1]:12345".parse().unwrap(),
        sniff: true,
        bypass_mark: 1,
        bypass_uid: unsafe { libc::geteuid() },
        dns_hijack: None,
      }))
      .unwrap_err();
    assert!(error.to_string().contains("IPv4"));
  }

  #[test]
  fn rejects_non_loopback_listener_before_opening_privileged_sockets() {
    let error = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap()
      .block_on(TproxyInbound::new(TproxyInboundOptions {
        listen: "0.0.0.0:12345".parse().unwrap(),
        sniff: true,
        bypass_mark: 1,
        bypass_uid: unsafe { libc::geteuid() },
        dns_hijack: None,
      }))
      .unwrap_err();
    assert!(error.to_string().contains("loopback"));
  }

  #[test]
  fn rejects_mismatched_bypass_uid_before_opening_privileged_sockets() {
    let effective_uid = unsafe { libc::geteuid() };
    let error = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap()
      .block_on(TproxyInbound::new(TproxyInboundOptions {
        listen: "127.0.0.1:12345".parse().unwrap(),
        sniff: true,
        bypass_mark: 1,
        bypass_uid: effective_uid.wrapping_add(1),
        dns_hijack: None,
      }))
      .unwrap_err();
    assert!(error.to_string().contains("effective uid"));
  }
}
