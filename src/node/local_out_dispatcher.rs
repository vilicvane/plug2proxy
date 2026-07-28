use std::io;

use async_trait::async_trait;
use lowkit::SelfWrapExt;
#[cfg(target_os = "linux")]
use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream};

use crate::{
  node::{Error, OutDispatcher},
  primitives::{
    BidiStream, OutExit, OutExitMatch, OutExitTag, OutExits, SocketDestination,
    SocketDestinationHost,
  },
  udp_forwarder::{OutboundUdpPacketStream, UdpForwarder},
};

const MAX_LINUX_INTERFACE_NAME_LENGTH: usize = 15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefaultLocalExit {
  /// Kept local to this node: provides `DIRECT` (and the local branch of
  /// `ANY`) but is not advertised as `PROXY`.
  Private,
  /// Also advertised as a provider. Empty tags still advertise `PROXY`.
  Advertised { tags: Vec<OutExitTag> },
}

pub struct LocalOutDispatcher {
  exits: OutExits,
  interface: Option<String>,
}

impl LocalOutDispatcher {
  pub fn new_default(default_local_exit: DefaultLocalExit) -> Self {
    let exits = match default_local_exit {
      DefaultLocalExit::Private => OutExits::new([OutExit::Direct]),
      DefaultLocalExit::Advertised { tags } => OutExits::new(
        [OutExit::Direct, OutExit::Proxy]
          .into_iter()
          .chain(tags.into_iter().map(OutExit::Tag)),
      ),
    };

    Self {
      exits,
      interface: None,
    }
  }

  pub fn new_bound(tags: Vec<OutExitTag>, interface: String) -> io::Result<Self> {
    validate_interface_name(&interface)?;

    Ok(Self {
      exits: OutExits::new(
        std::iter::once(OutExit::Proxy).chain(tags.into_iter().map(OutExit::Tag)),
      ),
      interface: Some(interface),
    })
  }

  pub fn exits(&self) -> &OutExits {
    &self.exits
  }

  pub fn interface(&self) -> Option<&str> {
    self.interface.as_deref()
  }
}

#[async_trait]
impl OutDispatcher for LocalOutDispatcher {
  fn match_exit(&self, route: &OutExit) -> Option<OutExitMatch> {
    self.exits.match_exit(route)
  }

  async fn connect(
    &self,
    _: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn BidiStream>, Error> {
    let tcp_stream = if let Some(interface) = &self.interface {
      connect_bound(&destination, interface).await?
    } else {
      match destination.host {
        SocketDestinationHost::DomainName(domain) => {
          TcpStream::connect((domain, destination.port)).await?
        }
        SocketDestinationHost::IpAddress(ip_addr) => {
          TcpStream::connect((ip_addr, destination.port)).await?
        }
      }
    };

    Ok(tcp_stream.wrap_box())
  }

  async fn associate(&self, _: OutExit) -> Result<Box<dyn OutboundUdpPacketStream>, Error> {
    Ok(Box::new(UdpForwarder::with_interface(
      self.interface.clone(),
    )))
  }
}

fn validate_interface_name(interface: &str) -> io::Result<()> {
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

async fn connect_bound(destination: &SocketDestination, interface: &str) -> io::Result<TcpStream> {
  let addresses = destination.resolve().await?;
  let mut last_error = None;

  for address in addresses {
    let socket = if address.is_ipv4() {
      TcpSocket::new_v4()?
    } else {
      TcpSocket::new_v6()?
    };

    bind_socket_to_interface(&socket, interface)?;

    match socket.connect(address).await {
      Ok(stream) => return Ok(stream),
      Err(error) => last_error = Some(error),
    }
  }

  Err(last_error.unwrap_or_else(|| {
    io::Error::new(
      io::ErrorKind::AddrNotAvailable,
      format!("destination {destination} resolved to no addresses"),
    )
  }))
}

#[cfg(target_os = "linux")]
fn bind_socket_to_interface(socket: &TcpSocket, interface: &str) -> io::Result<()> {
  SockRef::from(socket).bind_device(Some(interface.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn bind_socket_to_interface(_: &TcpSocket, _: &str) -> io::Result<()> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "bind.interface is only supported on Linux",
  ))
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::net::TcpListener;

  #[test]
  fn default_local_exit_distinguishes_private_and_advertised() {
    let private = LocalOutDispatcher::new_default(DefaultLocalExit::Private);
    let tagless = LocalOutDispatcher::new_default(DefaultLocalExit::Advertised { tags: vec![] });
    let tagged = LocalOutDispatcher::new_default(DefaultLocalExit::Advertised {
      tags: vec![
        OutExitTag::from("cn"),
        OutExitTag::from("youtube"),
        OutExitTag::from("cn"),
      ],
    });

    assert_eq!(private.exits().as_slice(), &[OutExit::Direct]);
    assert_eq!(
      tagless.exits().as_slice(),
      &[OutExit::Direct, OutExit::Proxy]
    );
    assert_eq!(
      tagged.exits().as_slice(),
      &[
        OutExit::Direct,
        OutExit::Proxy,
        OutExit::from("cn"),
        OutExit::from("youtube"),
      ]
    );

    assert_eq!(private.exits().for_advertising().as_slice(), &[]);
    assert_eq!(
      tagless.exits().for_advertising().as_slice(),
      &[OutExit::Proxy]
    );
    assert_eq!(
      tagged.exits().for_advertising().as_slice(),
      &[
        OutExit::Proxy,
        OutExit::from("cn"),
        OutExit::from("youtube"),
      ]
    );
  }

  #[test]
  fn bound_local_exit_is_a_provider_but_not_default_local() {
    let bound = LocalOutDispatcher::new_bound(
      vec![
        OutExitTag::from("us"),
        OutExitTag::from("netflix"),
        OutExitTag::from("us"),
      ],
      "wg0".to_owned(),
    )
    .unwrap();

    assert_eq!(
      bound.exits().as_slice(),
      &[
        OutExit::Proxy,
        OutExit::from("us"),
        OutExit::from("netflix"),
      ]
    );
    assert_eq!(bound.interface(), Some("wg0"));
    assert!(bound.match_exit(&OutExit::Direct).is_none());
  }

  #[test]
  fn invalid_interface_names_are_rejected() {
    for interface in ["", "nul\0suffix", "interface-name-too-long"] {
      assert!(
        LocalOutDispatcher::new_bound(vec![], interface.to_owned()).is_err(),
        "{interface:?}"
      );
    }
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn binds_socket_to_requested_interface() -> io::Result<()> {
    let socket = TcpSocket::new_v4()?;

    bind_socket_to_interface(&socket, "lo")?;

    assert_eq!(
      SockRef::from(&socket).device()?.as_deref(),
      Some(b"lo".as_slice())
    );

    Ok(())
  }

  #[cfg(target_os = "linux")]
  #[tokio::test]
  async fn connects_through_bound_loopback_interface() -> anyhow::Result<()> {
    // WSL mirrored networking routes 127/8 through its synthetic
    // `loopback0`; ordinary Linux uses `lo`.
    let interface = if std::path::Path::new("/sys/class/net/loopback0").exists() {
      "loopback0"
    } else {
      "lo"
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let destination = SocketDestination {
      host: SocketDestinationHost::DomainName("localhost".to_owned()),
      port: listener.local_addr()?.port(),
      routing_domain: None,
    };
    let dispatcher = LocalOutDispatcher::new_bound(vec![], interface.to_owned())?;

    let (connect_result, accept_result) =
      tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(
          dispatcher.connect(OutExit::Proxy, destination),
          listener.accept()
        )
      })
      .await?;

    let _client = connect_result?;
    let (_server, _) = accept_result?;

    Ok(())
  }
}
