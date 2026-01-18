use async_trait::async_trait;
use lowkit::SelfWrapExt;
use tokio::net::TcpStream;

use crate::{
  r#in::out_dispatcher::{self, OutDispatcher, OutTcpStream},
  out::{OutExit, OutExitTag},
  primitives::{SocketDestination, SocketDestinationHost},
};

pub struct DirectOutDispatcher {
  tags: Option<Vec<OutExitTag>>,
}

impl DirectOutDispatcher {
  pub fn new(tags: Option<Vec<OutExitTag>>) -> Self {
    Self { tags }
  }

  pub fn is_proxy(&self) -> bool {
    self.tags.is_some()
  }
}

#[async_trait]
impl OutDispatcher for DirectOutDispatcher {
  fn match_exit(&self, route: &OutExit) -> bool {
    match route {
      OutExit::Direct => true,
      OutExit::Proxy => self.is_proxy(),
      OutExit::Any => true,
      OutExit::Tag(route_tag) => self
        .tags
        .as_ref()
        .is_some_and(|tags| tags.iter().any(|tag| tag == route_tag)),
    }
  }

  async fn connect(
    &self,
    _: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn OutTcpStream>, out_dispatcher::Error> {
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
