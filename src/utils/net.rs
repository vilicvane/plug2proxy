use std::{
  borrow::Borrow,
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use async_trait::async_trait;
use lits::bytes;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

const MAX_LINUX_INTERFACE_NAME_LENGTH: usize = 15;
pub const UDP_SOCKET_BUFFER_SIZE: usize = bytes!("4 MiB") as usize;

pub fn configure_udp_socket_buffers<S>(socket: &S)
where
  for<'a> SockRef<'a>: From<&'a S>,
{
  let sock = SockRef::from(socket);
  let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER_SIZE);
  let _ = sock.set_send_buffer_size(UDP_SOCKET_BUFFER_SIZE);
}

pub fn validate_interface_name(interface: &str) -> io::Result<()> {
  if interface.is_empty() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "interface name must not be empty",
    ));
  }

  if interface.as_bytes().contains(&0) {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "interface name must not contain NUL",
    ));
  }

  if interface.len() > MAX_LINUX_INTERFACE_NAME_LENGTH {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("interface name must be at most {MAX_LINUX_INTERFACE_NAME_LENGTH} bytes on Linux"),
    ));
  }

  Ok(())
}

#[cfg(target_os = "linux")]
pub fn bind_socket_to_interface<S>(socket: &S, interface: &str) -> io::Result<()>
where
  for<'a> SockRef<'a>: From<&'a S>,
{
  SockRef::from(socket).bind_device(Some(interface.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
pub fn bind_socket_to_interface<S>(_socket: &S, _interface: &str) -> io::Result<()> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "bind.interface is only supported on Linux",
  ))
}

pub fn bind_tcp_listener(address: SocketAddr, interface: Option<&str>) -> io::Result<TcpListener> {
  let socket = if address.is_ipv4() {
    TcpSocket::new_v4()?
  } else {
    TcpSocket::new_v6()?
  };

  socket.set_reuseaddr(true)?;

  if let Some(interface) = interface {
    bind_socket_to_interface(&socket, interface)?;
  }

  socket.bind(address)?;
  socket.listen(1024)
}

pub fn bind_udp_socket(address: SocketAddr, interface: Option<&str>) -> io::Result<UdpSocket> {
  let socket = Socket::new(
    Domain::for_address(address),
    Type::DGRAM,
    Some(Protocol::UDP),
  )?;
  socket.set_nonblocking(true)?;
  configure_udp_socket_buffers(&socket);

  if let Some(interface) = interface {
    bind_socket_to_interface(&socket, interface)?;
  }

  socket.bind(&address.into())?;
  UdpSocket::from_std(socket.into())
}

pub async fn connect_tcp_bound(
  target: SocketAddr,
  local_ip: Option<IpAddr>,
  interface: Option<&str>,
) -> io::Result<TcpStream> {
  if let Some(local_ip) = local_ip
    && local_ip.is_ipv4() != target.is_ipv4()
  {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("local address {local_ip} is incompatible with target {target}"),
    ));
  }

  let socket = if target.is_ipv4() {
    TcpSocket::new_v4()?
  } else {
    TcpSocket::new_v6()?
  };

  if let Some(interface) = interface {
    bind_socket_to_interface(&socket, interface)?;
  }

  if let Some(local_ip) = local_ip {
    socket.bind(SocketAddr::new(local_ip, 0))?;
  }

  socket.connect(target).await
}

#[async_trait]
pub trait SocketAddressExt: Borrow<SocketAddr> {
  fn unspecified(&self) -> SocketAddr {
    match self.borrow() {
      SocketAddr::V4(_) => SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
      SocketAddr::V6(_) => SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
    }
  }

  fn get_ip_version(&self) -> u8 {
    match self.borrow() {
      SocketAddr::V4(_) => 4,
      SocketAddr::V6(_) => 6,
    }
  }

  async fn test_udp_connect(&self) -> bool {
    let address = self.borrow();

    let Ok(socket) = UdpSocket::bind(address.unspecified()).await else {
      return false;
    };

    socket.connect(address).await.is_ok()
  }
}

impl<T> SocketAddressExt for T where T: Borrow<SocketAddr> {}
