use async_trait::async_trait;
use lowkit::SelfWrapExt;
use tokio::net::TcpStream;

use crate::{
  node::{Error, OutDispatcher},
  primitives::{
    BidiStream, OutExit, OutExitMatch, OutExitTag, OutExits, SocketDestination,
    SocketDestinationHost,
  },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefaultLocalExit {
  /// Kept local to this node: provides `DIRECT` (and the local branch of
  /// `ANY`) but is not advertised as `PROXY`.
  Private,
  /// Also advertised as a provider. Empty tags still advertise `PROXY`.
  Advertised { tags: Vec<OutExitTag> },
}

pub struct DirectOutDispatcher {
  exits: OutExits,
}

impl DirectOutDispatcher {
  pub fn new(default_local_exit: DefaultLocalExit) -> Self {
    let exits = match default_local_exit {
      DefaultLocalExit::Private => OutExits::new([OutExit::Direct]),
      DefaultLocalExit::Advertised { tags } => OutExits::new(
        [OutExit::Direct, OutExit::Proxy]
          .into_iter()
          .chain(tags.into_iter().map(OutExit::Tag)),
      ),
    };

    Self { exits }
  }

  pub fn exits(&self) -> &OutExits {
    &self.exits
  }
}

#[async_trait]
impl OutDispatcher for DirectOutDispatcher {
  fn match_exit(&self, route: &OutExit) -> Option<OutExitMatch> {
    self.exits.match_exit(route)
  }

  async fn connect(
    &self,
    _: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn BidiStream>, Error> {
    let tcp_stream = match destination.host {
      SocketDestinationHost::DomainName(domain) => {
        TcpStream::connect((domain, destination.port)).await?
      }
      SocketDestinationHost::IpAddress(ip_addr) => {
        TcpStream::connect((ip_addr, destination.port)).await?
      }
    }
    .wrap_box();

    Ok(tcp_stream)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_local_exit_distinguishes_private_and_advertised() {
    let private = DirectOutDispatcher::new(DefaultLocalExit::Private);
    let tagless = DirectOutDispatcher::new(DefaultLocalExit::Advertised { tags: vec![] });
    let tagged = DirectOutDispatcher::new(DefaultLocalExit::Advertised {
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
}
