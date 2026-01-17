use std::{
  borrow::Borrow,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::net::UdpSocket;

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
