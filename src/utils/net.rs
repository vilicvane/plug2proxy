use std::{
  borrow::Borrow,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub trait SocketAddressExt {
  fn unspecified(&self) -> SocketAddr;
}

impl<T> SocketAddressExt for T
where
  T: Borrow<SocketAddr>,
{
  fn unspecified(&self) -> SocketAddr {
    match *self.borrow() {
      SocketAddr::V4(_) => SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
      SocketAddr::V6(_) => SocketAddr::from((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
    }
  }
}
