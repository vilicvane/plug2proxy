use std::sync::Arc;

use async_trait::async_trait;
use tokio::{sync::Semaphore, task::JoinSet};

use crate::{
  inbound::{AnyInbound, Inbound},
  node::{self, Node},
  primitives::{BidiStream, SocketDestination},
  route::Router,
  udp_forwarder::InboundUdpPacketStream,
  utils::task::reap_finished_tasks,
};

const MAX_INBOUND_TCP_CONNECTIONS: usize = 4096;

#[async_trait]
pub trait InLike: Node + 'static {
  fn router(&self) -> &Router;

  async fn in_tcp_connect(
    &self,
    destination: SocketDestination,
    stream: Box<dyn BidiStream>,
  ) -> Result<(), Error> {
    let routes = self.router().match_routes(&destination).await;

    self.tcp_connect_routes(routes, destination, stream).await?;

    Ok(())
  }

  fn inbounds(&self) -> &[Arc<AnyInbound>];

  async fn run_inbounds(self: Arc<Self>) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    for inbound in self.inbounds().iter() {
      join_set.spawn(self.clone().run_inbound(inbound.clone()));
    }

    let Some(result) = join_set.join_next().await else {
      return Ok(());
    };

    result??;

    unreachable!();
  }

  async fn run_inbound(self: Arc<Self>, inbound: Arc<AnyInbound>) -> anyhow::Result<()> {
    tokio::try_join!(
      self.clone().run_inbound_tcp(inbound.clone()),
      self.run_inbound_udp(inbound),
    )?;

    Ok(())
  }

  async fn run_inbound_tcp(self: Arc<Self>, inbound: Arc<AnyInbound>) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();
    let permits = Arc::new(Semaphore::new(MAX_INBOUND_TCP_CONNECTIONS));

    loop {
      let permit = permits.clone().acquire_owned().await?;
      let (destination, stream) = inbound.accept_tcp_connect().await?;

      let hub = self.clone();

      reap_finished_tasks(&mut join_set, "inbound TCP task");

      join_set.spawn(async move {
        let _permit = permit;
        hub
          .in_tcp_connect(destination, stream)
          .await
          .inspect_err(|error| {
            log::warn!("inbound TCP connection error: {}", error);
          })
          .ok();
      });
    }
  }

  async fn run_inbound_udp(self: Arc<Self>, inbound: Arc<AnyInbound>) -> anyhow::Result<()> {
    let packet_stream: Box<dyn InboundUdpPacketStream> = inbound.get_udp_packet_stream().await?;

    self.route_udp(self.router(), packet_stream).await?;

    Ok(())
  }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("node error: {0}")]
  Node(#[from] node::Error),
}
