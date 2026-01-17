use async_trait::async_trait;
use lowkit::SelfWrapExt;

use crate::{
  r#in::out_dispatcher::{self, OutDispatcher, OutTcpStream},
  out::OutExitTag,
  primitives::{Route, SocketDestination},
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
  fn match_out(&self, route: &Route) -> bool {
    match route {
      Route::Direct => true,
      Route::Proxy => self.is_proxy(),
      Route::Any => true,
      Route::Tag(route_tag) => self
        .tags
        .as_ref()
        .is_some_and(|tags| tags.iter().any(|tag| tag == route_tag)),
    }
  }

  async fn connect(
    &self,
    _: &Route,
    destination: SocketDestination,
  ) -> Result<Box<dyn OutTcpStream>, out_dispatcher::Error> {
    let tcp_stream = match destination.host {
      crate::primitives::SocketDestinationHost::DomainName(domain) => {
        tokio::net::TcpStream::connect((domain, destination.port)).await?
      }
      crate::primitives::SocketDestinationHost::IpAddress(ip_addr) => {
        tokio::net::TcpStream::connect((ip_addr, destination.port)).await?
      }
    }
    .wrap_box();

    Ok(tcp_stream)
  }
}
