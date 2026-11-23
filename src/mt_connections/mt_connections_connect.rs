use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use lits::duration;
use tokio::{
  io::AsyncWriteExt,
  net::TcpStream,
  sync::{mpsc, oneshot},
  task::JoinSet,
  time::{Instant, MissedTickBehavior, interval_at, sleep, timeout},
};

const BOOTSTRAP_STAGGER_DELAY: Duration = Duration::from_millis(250);

use crate::{
  mt_connections::{
    BOOTSTRAP_FALLBACK_GROUP_ID, LocalInterface, MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE, MT_CONNECTIONS_ROTATION_INTERVAL, MtConnections,
    MtConnectionsId, MtConnectionsMagic, MtConnectionsPacket, MtConnectionsRequestHead,
    MtConnectionsRequestHeadData, MtConnectionsResponseHead, MtConnectionsResponseHeadData,
    MtConnectionsUnderlayMetrics, configure_mt_tcp_stream,
  },
  primitives::ConnectionSide,
  utils::{
    net::connect_tcp_bound,
    postcard::{PostcardStreamError, postcard_read_stream},
  },
};

#[derive(Clone)]
pub struct MtDialTarget {
  pub local_interface: Arc<LocalInterface>,
  pub remote_address: SocketAddr,
}

#[derive(Clone)]
pub struct MtExtendPairPlan {
  pub pair_id: u16,
  pub local_interface: Arc<LocalInterface>,
  pub remote_address: SocketAddr,
  pub target_connections: usize,
  pub allow_rotation: bool,
}

pub struct MtExtendPlan {
  pub token: [u8; 32],
  pub bootstrap_pair_id: Option<u16>,
  pub pairs: Vec<MtExtendPairPlan>,
}

pub async fn mt_connections_connect<TPacket>(
  address: SocketAddr,
  target_connections: usize,
) -> Result<(MtConnections<TPacket>, oneshot::Sender<()>), MtConnectionsConnectError>
where
  TPacket: MtConnectionsPacket,
{
  let default_interface = LocalInterface::default_implicit();
  let (mut mt_connections, plan_sender, _, _) =
    mt_connections_connect_multi::<TPacket>(vec![MtDialTarget {
      local_interface: default_interface.clone(),
      remote_address: address,
    }])
    .await?;

  let (legacy_sender, legacy_receiver) = oneshot::channel();
  mt_connections.spawn(async move {
    if legacy_receiver.await.is_ok() {
      let _ = plan_sender.send(MtExtendPlan {
        token: [0; 32],
        bootstrap_pair_id: Some(0),
        pairs: vec![MtExtendPairPlan {
          pair_id: 0,
          local_interface: default_interface,
          remote_address: address,
          target_connections: target_connections.max(1),
          allow_rotation: true,
        }],
      });
    }
  });

  Ok((mt_connections, legacy_sender))
}

async fn dial_bootstrap_target(
  target: MtDialTarget,
) -> Result<(TcpStream, MtConnectionsId, u16, SocketAddr), MtConnectionsConnectError> {
  let mut tcp_stream = timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    connect_tcp_bound(
      target.remote_address,
      target.local_interface.address,
      target.local_interface.interface.as_deref(),
    ),
  )
  .await
  .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

  configure_mt_tcp_stream(&tcp_stream)?;

  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    send_request_head(&mut tcp_stream, MtConnectionsRequestHeadData::Create),
  )
  .await
  .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

  let response_head = timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    postcard_read_stream::<MtConnectionsResponseHead>(&mut tcp_stream),
  )
  .await
  .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

  match response_head.data {
    MtConnectionsResponseHeadData::Created(id) => Ok((
      tcp_stream,
      id,
      target.local_interface.id,
      target.remote_address,
    )),
    _ => Err(MtConnectionsConnectError::InvalidResponseHead),
  }
}

pub async fn mt_connections_connect_multi<TPacket>(
  bootstrap_targets: Vec<MtDialTarget>,
) -> Result<
  (
    MtConnections<TPacket>,
    oneshot::Sender<MtExtendPlan>,
    u16,
    SocketAddr,
  ),
  MtConnectionsConnectError,
>
where
  TPacket: MtConnectionsPacket,
{
  if bootstrap_targets.is_empty() {
    return Err(MtConnectionsConnectError::Io(std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "mTCP connect requires at least one bootstrap target",
    )));
  }

  let (tcp_stream, id, bootstrap_client_if_id, bootstrap_remote_address) = if bootstrap_targets
    .len()
    == 1
  {
    let target = bootstrap_targets.into_iter().next().unwrap();
    dial_bootstrap_target(target).await?
  } else {
    let mut remaining = bootstrap_targets.into_iter().peekable();
    let mut pending = JoinSet::new();
    let mut last_error = None;
    let mut established = None;

    if let Some(first_target) = remaining.next() {
      let label = (
        first_target.remote_address,
        first_target.local_interface.interface.clone(),
      );
      pending.spawn(async move { (label, dial_bootstrap_target(first_target).await) });
    }

    let stagger = sleep(BOOTSTRAP_STAGGER_DELAY);
    tokio::pin!(stagger);

    while !pending.is_empty() || remaining.peek().is_some() {
      let has_more = remaining.peek().is_some();

      tokio::select! {
        Some(joined) = pending.join_next(), if !pending.is_empty() => {
          match joined {
            Ok((_, Ok(success))) => {
              established = Some(success);
              break;
            }
            Ok(((remote_address, interface), Err(error))) => {
              log::debug!(
                "bootstrap mTCP connect to {remote_address} (interface={interface:?}) failed: {error}"
              );
              last_error = Some(error);
              if let Some(next_target) = remaining.next() {
                let label = (
                  next_target.remote_address,
                  next_target.local_interface.interface.clone(),
                );
                pending.spawn(async move { (label, dial_bootstrap_target(next_target).await) });
                stagger.as_mut().reset(Instant::now() + BOOTSTRAP_STAGGER_DELAY);
              }
            }
            Err(join_error) => {
              if join_error.is_panic() {
                std::panic::resume_unwind(join_error.into_panic());
              }
            }
          }
        }
        _ = &mut stagger, if has_more => {
          if let Some(next_target) = remaining.next() {
            let label = (
              next_target.remote_address,
              next_target.local_interface.interface.clone(),
            );
            pending.spawn(async move { (label, dial_bootstrap_target(next_target).await) });
            stagger.as_mut().reset(Instant::now() + BOOTSTRAP_STAGGER_DELAY);
          }
        }
      }
    }

    established.ok_or_else(|| last_error.unwrap())?
  };

  let (mut mt_connections, tcp_stream_sender, mut tcp_stream_close_receiver) =
    MtConnections::<TPacket>::new(tcp_stream, ConnectionSide::Client, id);

  let (extend_plan_sender, extend_plan_receiver) = oneshot::channel::<MtExtendPlan>();
  let underlay_metrics = mt_connections.underlay_metrics();

  mt_connections.spawn(async move {
    let Ok(MtExtendPlan {
      token,
      bootstrap_pair_id,
      pairs,
    }) = extend_plan_receiver.await
    else {
      // Sender dropped, no more connections to extend. Also no need to reopen
      // after close, as the MtConnections will be closed if the only
      // tcp_stream is closed.
      return;
    };

    let mut close_senders = HashMap::<u16, mpsc::UnboundedSender<()>>::new();
    let mut pair_tasks = JoinSet::new();

    for pair in pairs {
      let initial_connections = usize::from(bootstrap_pair_id == Some(pair.pair_id));
      let (pair_close_sender, pair_close_receiver) = mpsc::unbounded_channel();
      close_senders.insert(pair.pair_id, pair_close_sender);

      pair_tasks.spawn(run_pair_connections(
        id,
        token,
        pair,
        initial_connections,
        tcp_stream_sender.clone(),
        pair_close_receiver,
        underlay_metrics.clone(),
      ));
    }

    if bootstrap_pair_id.is_none() {
      let retire_metrics = underlay_metrics.clone();
      let closed_observer = tcp_stream_sender.clone();
      pair_tasks.spawn(async move {
        let notify = retire_metrics.non_fallback_path_notify();
        loop {
          let notified = notify.notified();
          tokio::pin!(notified);
          notified.as_mut().enable();

          if retire_metrics.has_non_fallback_path() {
            retire_metrics.retire_path(0);
            break;
          }

          tokio::select! {
            _ = &mut notified => {}
            _ = closed_observer.closed() => break,
          }
        }
      });
    }

    while let Some(closed_group_id) = tcp_stream_close_receiver.recv().await {
      if closed_group_id == BOOTSTRAP_FALLBACK_GROUP_ID {
        continue;
      }

      if let Some(sender) = close_senders.get(&closed_group_id) {
        sender.send(()).ok();
      }
    }

    drop(close_senders);
    while pair_tasks.join_next().await.is_some() {}
  });

  Ok((
    mt_connections,
    extend_plan_sender,
    bootstrap_client_if_id,
    bootstrap_remote_address,
  ))
}

async fn run_pair_connections<TPacket: MtConnectionsPacket>(
  id: MtConnectionsId,
  token: [u8; 32],
  pair: MtExtendPairPlan,
  initial_connections: usize,
  tcp_stream_sender: mpsc::UnboundedSender<(TcpStream, u16)>,
  mut close_receiver: mpsc::UnboundedReceiver<()>,
  underlay_metrics: Arc<MtConnectionsUnderlayMetrics<TPacket>>,
) {
  let target_connections = pair.target_connections.max(1);
  let add_tcp_stream = || async {
    let tcp_stream = loop {
      let connect = async {
        let mut tcp_stream = timeout(
          MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
          connect_tcp_bound(
            pair.remote_address,
            pair.local_interface.address,
            pair.local_interface.interface.as_deref(),
          ),
        )
        .await
        .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

        configure_mt_tcp_stream(&tcp_stream)?;

        timeout(
          MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
          send_request_head(
            &mut tcp_stream,
            MtConnectionsRequestHeadData::Extend {
              id,
              pair_id: pair.pair_id,
              token,
            },
          ),
        )
        .await
        .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

        let response_head = timeout(
          MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
          postcard_read_stream::<MtConnectionsResponseHead>(&mut tcp_stream),
        )
        .await
        .map_err(|_| MtConnectionsConnectError::HandshakeTimeout)??;

        match response_head.data {
          MtConnectionsResponseHeadData::Extended => Ok(tcp_stream),
          _ => Err(MtConnectionsConnectError::InvalidResponseHead),
        }
      };

      let result = tokio::select! {
        _ = tcp_stream_sender.closed() => return false,
        result = connect => result,
      };

      if let Ok(tcp_stream) = result.inspect_err(|error| {
        log::warn!(
          "error connecting to address {} (pair {}): {}",
          pair.remote_address,
          pair.pair_id,
          error
        );
      }) {
        break tcp_stream;
      }

      tokio::select! {
        _ = tcp_stream_sender.closed() => return false,
        _ = sleep(duration!("5s")) => {}
      }
    };

    tcp_stream_sender
      .send((tcp_stream, pair.pair_id))
      .inspect_err(|error| {
        log::warn!("error adding tcp stream to mt connections: {}", error);
      })
      .is_ok()
  };

  let mut managed_connections = initial_connections;
  for _ in initial_connections..target_connections {
    if !add_tcp_stream().await {
      return;
    }
    managed_connections += 1;
  }

  let mut rotation = interval_at(
    Instant::now() + MT_CONNECTIONS_ROTATION_INTERVAL,
    MT_CONNECTIONS_ROTATION_INTERVAL,
  );
  rotation.set_missed_tick_behavior(MissedTickBehavior::Skip);
  let mut desired_connections = managed_connections;

  'outer: loop {
    let closed = tokio::select! {
      biased;
      closed = close_receiver.recv() => closed,
      _ = rotation.tick(), if cfg!(target_os = "linux") && pair.allow_rotation => {
        desired_connections = target_connections + 1;
        if underlay_metrics.available_path_count_in_group(pair.pair_id) <= target_connections {
          if !add_tcp_stream().await {
            break;
          }
          managed_connections += 1;
        } else {
          // The normal close notification starts the replacement only after
          // both halves of the selected TCP connection have drained.
          underlay_metrics.retire_worst_path_in_group(
            pair.pair_id,
            target_connections,
            std::time::Instant::now(),
          );
        }
        continue;
      }
    };

    if closed.is_none() {
      break;
    }

    let mut connections_to_extend = 1_usize;

    loop {
      match timeout(duration!("1s"), close_receiver.recv()).await {
        Ok(Some(())) => connections_to_extend += 1,
        Ok(None) => break 'outer,
        Err(_) => break,
      }
    }

    // Count accepted additions here rather than relying on asynchronous
    // path registration. A cycle may have added a spare while another path
    // was draining, in which case its close must not add a second spare.
    managed_connections = managed_connections.saturating_sub(connections_to_extend);
    while managed_connections < desired_connections {
      if close_receiver.is_closed() || tcp_stream_sender.is_closed() {
        break 'outer;
      }

      if !add_tcp_stream().await {
        break 'outer;
      }
      managed_connections += 1;
    }
  }
}

#[derive(thiserror::Error, Debug)]
pub enum MtConnectionsConnectError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Postcard deserialization error: {0}")]
  PostcardDeserialization(postcard::Error),
  #[error("mTCP handshake timed out")]
  HandshakeTimeout,
  #[error("Invalid response head")]
  InvalidResponseHead,
}

impl From<PostcardStreamError> for MtConnectionsConnectError {
  fn from(error: PostcardStreamError) -> Self {
    match error {
      PostcardStreamError::Io(error) => Self::Io(error),
      PostcardStreamError::Deserialization(error) => Self::PostcardDeserialization(error),
    }
  }
}

async fn send_request_head(
  stream: &mut TcpStream,
  data: MtConnectionsRequestHeadData,
) -> Result<(), MtConnectionsConnectError> {
  let bytes =
    postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
      magic: MtConnectionsMagic,
      data,
    })
    .unwrap();

  stream.write_all(&bytes).await?;

  Ok(())
}
