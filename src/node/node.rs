use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use colored::Colorize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::io::copy_bidirectional;
use uuid::Uuid;

use crate::{
  node::OutDispatcher,
  out::DirectOut,
  primitives::{BidiStream, OutExit, OutExitTag, SocketDestination},
  route::AnyRule,
};

static NEXT_PROXY_DISPATCHER: AtomicUsize = AtomicUsize::new(0);

#[async_trait]
pub trait Node {
  fn id(&self) -> NodeId;

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>>;

  async fn tcp_connect(
    &self,
    exits: Vec<OutExit>,
    destination: SocketDestination,
    mut stream: Box<dyn BidiStream>,
  ) -> Result<(), Error> {
    if exits.is_empty() {
      log::info!("TCP {destination} no exit matched.");
      return Ok(());
    }

    let out_dispatchers = self.get_out_dispatchers();

    let Some((matched_exit, out_dispatcher)) = exits.iter().find_map(|route| {
      let matching_dispatchers = out_dispatchers
        .iter()
        .filter(|dispatcher| dispatcher.match_exit(route))
        .collect_vec();

      if matching_dispatchers.is_empty() {
        return None;
      }

      // Preserve the established DIRECT-first behavior for ANY. Explicit
      // proxy/tag routes are spread across equivalent OUT connections so each
      // one has an independent QUIC and TCP congestion window.
      let index = if *route == OutExit::Any {
        0
      } else {
        NEXT_PROXY_DISPATCHER.fetch_add(1, Ordering::Relaxed) % matching_dispatchers.len()
      };

      Some((route, matching_dispatchers[index].clone()))
    }) else {
      log::info!("TCP {destination} no out dispatcher matched.");
      return Ok(());
    };

    log::info!(
      "TCP {destination} -> {}",
      exits
        .iter()
        .map(|exit| if exit == matched_exit {
          exit.to_string().cyan().to_string()
        } else {
          exit.to_string()
        })
        .join(",")
    );

    let mut out_stream = out_dispatcher
      .connect(matched_exit.clone(), destination)
      .await?;

    copy_bidirectional(&mut stream, &mut out_stream).await?;

    Ok(())
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, derive_more::Display)]
#[serde(transparent)]
#[display("{}", _0.hyphenated().to_string().split_once("-").unwrap().0)]
pub struct NodeId(#[serde(with = "uuid::serde::compact")] pub Uuid);

impl NodeId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }
}

impl Default for NodeId {
  fn default() -> Self {
    Self::new()
  }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NodeHello {
  In(NodeId),
  Out(NodeHelloOut),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeHelloOut {
  pub id: NodeId,
  pub tags: Vec<OutExitTag>,
  pub direct_out: Option<DirectOut>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeHelloAck(pub NodeId);

#[derive(Serialize, Deserialize)]
pub enum NodeMessageToOut {
  Connect(OutExit, SocketDestination),
  Associate(OutExit, SocketDestination),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NodeMessageToIn {
  Update(NodeMessageToInUpdate),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeMessageToInUpdate {
  pub tags: Vec<OutExitTag>,
  pub direct_outs: Vec<DirectOut>,
  pub route_rules: Vec<AnyRule>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Out dispatcher not matched")]
  OutDispatcherNotMatched,
}
