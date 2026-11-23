use std::{
  collections::HashMap,
  net::IpAddr,
  sync::{Arc, Mutex, Weak},
};

use lowkit::{DropCallback, SelfWrapExt};
use tokio::{
  io::AsyncWriteExt,
  net::{TcpListener, TcpStream, UdpSocket},
  sync::{Semaphore, mpsc},
  task::JoinSet,
  time::{Duration, sleep, timeout},
};

use crate::{
  mt_connections::{
    LocalInterface, MAX_UDP_WIRE_DATAGRAM_SIZE, MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE, MtConnections, MtConnectionsId, MtConnectionsMagic,
    MtConnectionsPacket, MtConnectionsRequestHead, MtConnectionsRequestHeadData,
    MtConnectionsResponseHead, MtConnectionsResponseHeadData, MtConnectionsSideUdpDuplex,
    MtConnectionsUdpPacket, MtConnectionsUnderlayMetrics, UDP_RECV_BUFFER_SIZE,
    UdpBandwidthAccountant, UdpDuplexSlot, configure_mt_tcp_stream, decode_udp_frame,
  },
  primitives::ConnectionSide,
  utils::{
    net::configure_udp_socket_buffers,
    postcard::{PostcardStreamError, postcard_read_stream},
    task::reap_finished_tasks,
  },
};

const MAX_CONCURRENT_MTCP_HANDSHAKES: usize = 128;

pub struct MtListenerBinding {
  pub interface_id: u16,
  pub local_interface: Arc<LocalInterface>,
  pub tcp_listener: TcpListener,
  pub udp_socket: Option<UdpSocket>,
}

fn constant_time_eq(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
  let mut diff = 0_u8;
  for (left, right) in lhs.iter().zip(rhs.iter()) {
    diff |= left ^ right;
  }
  diff == 0
}

type PairPathCounter = Arc<dyn Fn(u16) -> usize + Send + Sync>;

enum ExtendAuth {
  Legacy,
  Plan {
    token: [u8; 32],
    pair_to_server_if: HashMap<u16, u16>,
    pair_max_paths: HashMap<u16, usize>,
    path_counter: PairPathCounter,
  },
}

impl ExtendAuth {
  fn authorizes(
    &self,
    token: &[u8; 32],
    pair_id: u16,
    server_if_id: u16,
    binding_idx: usize,
  ) -> bool {
    match self {
      Self::Legacy => *token == [0; 32] && pair_id == 0 && binding_idx == 0,
      Self::Plan {
        token: expected,
        pair_to_server_if,
        pair_max_paths,
        path_counter,
      } => {
        constant_time_eq(token, expected)
          && pair_to_server_if.get(&pair_id) == Some(&server_if_id)
          && pair_max_paths
            .get(&pair_id)
            .is_some_and(|&max_paths| path_counter(pair_id) < max_paths)
      }
    }
  }
}

struct ListenerSession {
  tcp_stream_sender: mpsc::UnboundedSender<(TcpStream, u16)>,
  extend_auth: ExtendAuth,
}

struct ListenerBindingRuntime<TPacket>
where
  TPacket: 'static,
{
  interface_id: u16,
  udp_socket: Option<Arc<UdpSocket>>,
  udp_dispatch_map: Arc<Mutex<HashMap<MtConnectionsId, UdpDispatchEntry<TPacket>>>>,
}

pub(crate) struct MtListenerSessionHandle<TPacket>
where
  TPacket: 'static,
{
  id: MtConnectionsId,
  bootstrap_server_if_id: u16,
  server_interfaces: Vec<Arc<LocalInterface>>,
  server_udp_enabled: Vec<bool>,
  sessions: Arc<Mutex<HashMap<MtConnectionsId, ListenerSession>>>,
  runtimes: Vec<Arc<ListenerBindingRuntime<TPacket>>>,
  cleanup_channels: Arc<Mutex<Vec<(usize, MtConnectionsId)>>>,
}

impl<TPacket> MtListenerSessionHandle<TPacket>
where
  TPacket: MtConnectionsPacket + MtConnectionsUdpPacket,
{
  pub(crate) fn bootstrap_server_if_id(&self) -> u16 {
    self.bootstrap_server_if_id
  }

  pub(crate) fn server_interfaces(&self) -> &[Arc<LocalInterface>] {
    &self.server_interfaces
  }

  pub(crate) fn server_udp_enabled(&self) -> &[bool] {
    &self.server_udp_enabled
  }

  pub(crate) fn install_extend_plan(
    &self,
    token: [u8; 32],
    pair_to_server_if: HashMap<u16, u16>,
    pair_max_paths: HashMap<u16, usize>,
    underlay_metrics: &Arc<MtConnectionsUnderlayMetrics<TPacket>>,
  ) {
    let weak_metrics = Arc::downgrade(underlay_metrics);
    let path_counter: PairPathCounter = Arc::new(move |pair_id| {
      weak_metrics.upgrade().map_or(usize::MAX, |metrics| {
        metrics.available_path_count_in_group(pair_id)
      })
    });

    let mut sessions = self.sessions.lock().unwrap();
    if let Some(session) = sessions.get_mut(&self.id) {
      session.extend_auth = ExtendAuth::Plan {
        token,
        pair_to_server_if,
        pair_max_paths,
        path_counter,
      };
    }
  }

  pub(crate) fn clear_udp_channels(&self) {
    let old_channels = std::mem::take(&mut *self.cleanup_channels.lock().unwrap());
    for (binding_idx, channel_id) in old_channels {
      if let Some(runtime) = self.runtimes.get(binding_idx) {
        runtime.udp_dispatch_map.lock().unwrap().remove(&channel_id);
      }
    }
  }

  pub(crate) fn replace_udp_channels(
    &self,
    channels: Vec<(u16, MtConnectionsId, Option<UdpBandwidthAccountant>)>,
  ) -> Vec<(MtConnectionsId, Arc<UdpDuplexSlot<TPacket>>)> {
    self.clear_udp_channels();

    let mut slots = Vec::with_capacity(channels.len());
    let mut registered = Vec::with_capacity(channels.len());

    for (server_if_id, channel_id, accountant) in channels {
      let Some((binding_idx, runtime)) =
        self.runtimes.iter().enumerate().find(|(_, runtime)| {
          runtime.interface_id == server_if_id && runtime.udp_socket.is_some()
        })
      else {
        continue;
      };

      let slot = Arc::new(UdpDuplexSlot::new());
      runtime.udp_dispatch_map.lock().unwrap().insert(
        channel_id,
        UdpDispatchEntry {
          sender: None,
          peer_address: None,
          verify_tcp_peer_ip: None,
          accountant,
          slot: Arc::downgrade(&slot),
        },
      );
      registered.push((binding_idx, channel_id));
      slots.push((channel_id, slot));
    }

    *self.cleanup_channels.lock().unwrap() = registered;
    slots
  }
}

/// UDP 分发条目：投递 sender 与 MtConnections 的共享 duplex 槽位。
///
/// sender 与 duplex 解耦：duplex 被上层 take 后，分发循环仍可通过 sender
/// 持续投递到已 take 的 duplex（其内部 channel 接收端跟随 duplex 走）。
struct UdpDispatchEntry<TPacket>
where
  TPacket: 'static,
{
  sender: Option<flume::Sender<TPacket>>,
  peer_address: Option<std::net::SocketAddr>,
  verify_tcp_peer_ip: Option<IpAddr>,
  accountant: Option<UdpBandwidthAccountant>,
  slot: Weak<UdpDuplexSlot<TPacket>>,
}

pub struct MtConnectionsListener<TPacket>
where
  TPacket: MtConnectionsPacket,
{
  created_receiver: mpsc::Receiver<Result<MtConnections<TPacket>, MtConnectionsListenerError>>,
  #[cfg(test)]
  runtimes: Arc<Vec<Arc<ListenerBindingRuntime<TPacket>>>>,
  // JoinSet drop 时自动 abort 全部任务（tokio 内置行为），
  // 分发与 accept 循环随 listener 释放而终止，无需手动管理。
  _join_set: JoinSet<()>,
}

impl<TPacket> MtConnectionsListener<TPacket>
where
  TPacket: MtConnectionsPacket + MtConnectionsUdpPacket,
{
  pub fn new(listener: TcpListener, udp_socket: Option<UdpSocket>) -> Self {
    Self::from_bindings(vec![MtListenerBinding {
      interface_id: 0,
      local_interface: LocalInterface::default_implicit(),
      tcp_listener: listener,
      udp_socket,
    }])
  }

  pub fn from_bindings(bindings: Vec<MtListenerBinding>) -> Self {
    assert!(
      !bindings.is_empty(),
      "listener requires at least one binding"
    );

    let mut runtimes = Vec::with_capacity(bindings.len());
    let mut tcp_listeners = Vec::with_capacity(bindings.len());
    let mut server_interfaces = Vec::with_capacity(bindings.len());
    let mut server_udp_enabled = Vec::with_capacity(bindings.len());
    let mut join_set = JoinSet::new();

    for (index, binding) in bindings.into_iter().enumerate() {
      assert_eq!(
        binding.interface_id as usize, index,
        "listener bindings must be ordered by sequential interface_id"
      );

      let udp_socket = binding.udp_socket.and_then(|socket| {
        match (binding.tcp_listener.local_addr(), socket.local_addr()) {
          (Ok(tcp_address), Ok(udp_address)) if tcp_address.port() == udp_address.port() => {
            configure_udp_socket_buffers(&socket);
            Some(socket.arc())
          }
          (Ok(tcp_address), Ok(udp_address)) => {
            log::warn!(
              "disabling QomT UDP listener: TCP port {} and UDP port {} differ",
              tcp_address.port(),
              udp_address.port(),
            );
            None
          }
          (Err(error), _) => {
            log::warn!("disabling QomT UDP listener: cannot read TCP local address: {error}");
            None
          }
          (_, Err(error)) => {
            log::warn!("disabling QomT UDP listener: cannot read UDP local address: {error}");
            None
          }
        }
      });

      let udp_dispatch_map: Arc<Mutex<HashMap<MtConnectionsId, UdpDispatchEntry<TPacket>>>> =
        Arc::new(Mutex::new(HashMap::new()));

      if let Some(udp_socket) = &udp_socket {
        join_set.spawn(udp_dispatch_loop(
          udp_socket.clone(),
          udp_dispatch_map.clone(),
        ));
      }

      server_udp_enabled.push(udp_socket.is_some());
      server_interfaces.push(binding.local_interface);
      tcp_listeners.push(binding.tcp_listener);
      runtimes.push(Arc::new(ListenerBindingRuntime {
        interface_id: binding.interface_id,
        udp_socket,
        udp_dispatch_map,
      }));
    }

    let sessions: Arc<Mutex<HashMap<MtConnectionsId, ListenerSession>>> =
      Arc::new(Mutex::new(HashMap::new()));
    let (created_sender, created_receiver) = mpsc::channel(64);
    let handshake_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_MTCP_HANDSHAKES));
    let server_interfaces = Arc::new(server_interfaces);
    let server_udp_enabled = Arc::new(server_udp_enabled);
    let runtimes_shared = Arc::new(runtimes);

    for (binding_idx, tcp_listener) in tcp_listeners.into_iter().enumerate() {
      let sessions = sessions.clone();
      let created_sender = created_sender.clone();
      let handshake_semaphore = handshake_semaphore.clone();
      let server_interfaces = server_interfaces.clone();
      let server_udp_enabled = server_udp_enabled.clone();
      let runtimes_shared = runtimes_shared.clone();

      join_set.spawn(async move {
        let mut handshake_tasks = JoinSet::new();
        let runtime = &runtimes_shared[binding_idx];

        loop {
          let stream = match tcp_listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
              let _ = created_sender.send(Err(error.into())).await;
              break;
            }
          };

          let Ok(permit) = handshake_semaphore.clone().try_acquire_owned() else {
            log::warn!("too many pending mTCP handshakes; dropping incoming TCP stream");
            continue;
          };

          reap_finished_tasks(&mut handshake_tasks, "mTCP accept handshake task");

          let sessions = sessions.clone();
          let created_sender = created_sender.clone();
          let server_interfaces = server_interfaces.clone();
          let server_udp_enabled = server_udp_enabled.clone();
          let runtimes_shared = runtimes_shared.clone();
          let runtime = runtime.clone();

          handshake_tasks.spawn(async move {
            let _permit = permit;
            let mut stream = stream;

            if configure_mt_tcp_stream(&stream)
              .inspect_err(|error| {
                log::warn!("error configuring incoming mTCP connection: {error}");
              })
              .is_err()
            {
              return;
            }

            let Ok(request_head_result) = timeout(
              MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
              postcard_read_stream::<MtConnectionsRequestHead>(&mut stream),
            )
            .await
            else {
              log::warn!("timed out reading request head from incoming mTCP connection");
              return;
            };

            let Ok(request_head) = request_head_result.inspect_err(|error| {
              log::warn!("error reading request head from incoming mTCP connections: {error}")
            }) else {
              return;
            };

            match request_head.data {
              MtConnectionsRequestHeadData::Create => {
                let id = MtConnectionsId::new();

                if send_response_head_with_timeout(
                  &mut stream,
                  MtConnectionsResponseHeadData::Created(id),
                )
                .await
                .inspect_err(|error| {
                  log::warn!(
                    "error sending response head (created) to incoming mTCP connections: {error}"
                  )
                })
                .is_err()
                {
                  return;
                }

                let (mut mt_connections, tcp_stream_sender, _) =
                  MtConnections::new(stream, ConnectionSide::Server, id);

                let cleanup_channels = Arc::new(Mutex::new(Vec::new()));

                if runtime.udp_socket.is_some() {
                  let slot = mt_connections.udp_duplex_slot();
                  runtime.udp_dispatch_map.lock().unwrap().insert(
                    id,
                    UdpDispatchEntry {
                      sender: None,
                      peer_address: None,
                      verify_tcp_peer_ip: Some(mt_connections.peer_address().ip().to_canonical()),
                      accountant: None,
                      slot: Arc::downgrade(&slot),
                    },
                  );
                  cleanup_channels.lock().unwrap().push((binding_idx, id));
                }

                {
                  let mut sessions_guard = sessions.lock().unwrap();
                  sessions_guard.retain(|_, session| !session.tcp_stream_sender.is_closed());
                  sessions_guard.insert(
                    id,
                    ListenerSession {
                      tcp_stream_sender,
                      extend_auth: ExtendAuth::Legacy,
                    },
                  );
                }

                let weak_sessions = Arc::downgrade(&sessions);
                let weak_runtimes = Arc::downgrade(&runtimes_shared);
                let cleanup_channels_for_drop = cleanup_channels.clone();
                mt_connections.set_udp_registration(DropCallback::new(Box::new(move || {
                  if let Some(sessions) = weak_sessions.upgrade() {
                    sessions.lock().unwrap().remove(&id);
                  }
                  if let Some(runtimes) = weak_runtimes.upgrade() {
                    for (b_idx, channel_id) in cleanup_channels_for_drop.lock().unwrap().drain(..) {
                      if let Some(runtime) = runtimes.get(b_idx) {
                        runtime.udp_dispatch_map.lock().unwrap().remove(&channel_id);
                      }
                    }
                  }
                })
                  as Box<dyn Fn() + Send>));

                mt_connections.set_listener_handle(MtListenerSessionHandle {
                  id,
                  bootstrap_server_if_id: runtime.interface_id,
                  server_interfaces: (*server_interfaces).clone(),
                  server_udp_enabled: (*server_udp_enabled).clone(),
                  sessions: sessions.clone(),
                  runtimes: (*runtimes_shared).clone(),
                  cleanup_channels,
                });

                let _ = created_sender.send(Ok(mt_connections)).await;
              }
              MtConnectionsRequestHeadData::Extend { id, pair_id, token } => {
                let authorized_sender = {
                  let sessions_guard = sessions.lock().unwrap();
                  sessions_guard.get(&id).and_then(|session| {
                    (!session.tcp_stream_sender.is_closed()
                      && session.extend_auth.authorizes(
                        &token,
                        pair_id,
                        runtime.interface_id,
                        binding_idx,
                      ))
                    .then(|| session.tcp_stream_sender.clone())
                  })
                };

                if let Some(tcp_stream_sender) = authorized_sender {
                  if send_response_head_with_timeout(
                    &mut stream,
                    MtConnectionsResponseHeadData::Extended,
                  )
                  .await
                  .inspect_err(|error| {
                    log::warn!(
                      "error sending response head (extended) to incoming mTCP connections: {error}"
                    )
                  })
                  .is_err()
                  {
                    return;
                  }

                  tcp_stream_sender.send((stream, pair_id)).ok();
                } else {
                  let _ = send_response_head_with_timeout(
                    &mut stream,
                    MtConnectionsResponseHeadData::AlreadyClosed,
                  )
                  .await
                  .inspect_err(|error| {
                    log::warn!(
                      "error sending response head (already closed) to incoming mTCP connections: \
                       {error}"
                    )
                  });
                }
              }
            }
          });
        }
      });
    }

    Self {
      created_receiver,
      #[cfg(test)]
      runtimes: runtimes_shared,
      _join_set: join_set,
    }
  }

  pub async fn accept(&mut self) -> Result<MtConnections<TPacket>, MtConnectionsListenerError> {
    self.created_receiver.recv().await.unwrap_or_else(|| {
      Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "mTCP listener closed").into())
    })
  }

  #[cfg(test)]
  pub(crate) fn udp_dispatch_count(&self) -> usize {
    self
      .runtimes
      .iter()
      .map(|runtime| runtime.udp_dispatch_map.lock().unwrap().len())
      .sum()
  }
}

/// 全局 UDP 分发循环：按帧头 MtConnectionsId 投递到对应 MtConnections 的
/// UDP duplex。未知 id（如 TCP Create 尚未完成）静默丢弃；每个 route 有
/// 小型有界队列，队列满时丢包并由 QUIC 的丢包恢复处理。
async fn udp_dispatch_loop<TPacket>(
  udp_socket: Arc<UdpSocket>,
  udp_dispatch_map: Arc<Mutex<HashMap<MtConnectionsId, UdpDispatchEntry<TPacket>>>>,
) where
  TPacket: MtConnectionsUdpPacket,
{
  let mut buffer = vec![0; UDP_RECV_BUFFER_SIZE];
  let mut receive_error_streak = 0u32;

  loop {
    let (length, from) = match udp_socket.recv_from(&mut buffer).await {
      Ok(received) => {
        if receive_error_streak > 0 {
          log::info!(
            "QomT UDP dispatch loop recovered after {receive_error_streak} receive errors"
          );
          receive_error_streak = 0;
        }

        received
      }
      Err(error) => {
        receive_error_streak = receive_error_streak.saturating_add(1);
        let backoff_exponent = receive_error_streak.saturating_sub(1).min(6);
        let retry_delay = Duration::from_millis(10 * (1u64 << backoff_exponent));

        if receive_error_streak == 1 || receive_error_streak.is_power_of_two() {
          log::warn!(
            "QomT UDP receive failed {receive_error_streak} consecutive times; \
             retrying in {retry_delay:?}: {error}"
          );
        }

        sleep(retry_delay).await;
        continue;
      }
    };

    if length > MAX_UDP_WIRE_DATAGRAM_SIZE {
      log::trace!("dropping oversized QomT UDP frame from {from}");
      continue;
    }

    let Some((id, payload)) = decode_udp_frame(&buffer[..length]) else {
      continue;
    };

    if payload.is_empty() {
      continue;
    }

    log::trace!("UDP dispatch: received frame for {id:?} from {from}");

    // A sender can disconnect between lookup and delivery. Retry the same
    // packet once so the first packet of a new UDP generation is not lost to
    // that race.
    for delivery_attempt in 0..2 {
      let sender = {
        let mut dispatch_map = udp_dispatch_map.lock().unwrap();

        let Some(entry) = dispatch_map.get_mut(&id) else {
          log::trace!("UDP dispatch: unknown id {id:?}, dropping");
          break;
        };

        if let Some(expected_ip) = entry.verify_tcp_peer_ip
          && from.ip().to_canonical() != expected_ip
        {
          log::trace!("UDP dispatch: source IP mismatch for {id:?}, dropping");
          break;
        }

        // A UDP QUIC generation ending must not remove the stable
        // MtConnectionsId route. Clear only its source-address pin and sender;
        // the next generation can then bind a fresh client UDP port.
        if entry
          .sender
          .as_ref()
          .is_some_and(|sender| sender.is_disconnected())
        {
          entry.sender = None;
          entry.peer_address = None;
        }

        if entry
          .peer_address
          .is_some_and(|peer_address| peer_address != from)
        {
          log::trace!("UDP dispatch: source address changed for {id:?}, dropping");
          break;
        }

        if entry.sender.is_none() {
          let Some(slot) = entry.slot.upgrade() else {
            dispatch_map.remove(&id);
            break;
          };

          let (duplex, sender) = MtConnectionsSideUdpDuplex::listener_side(
            udp_socket.clone(),
            from,
            id,
            entry.accountant.clone(),
          );

          slot.set(duplex);
          entry.peer_address = Some(from);
          entry.sender = Some(sender);

          log::debug!("UDP dispatch: created duplex for {id:?}");
        }

        entry.sender.as_ref().unwrap().clone()
      };

      // dispatcher 是这个 sender 的唯一生产者，先查 full 可避免在丢包路径
      // 上复制 payload；try_send 仍处理接收方并发关闭的竞态。
      if sender.is_full() {
        log::trace!("UDP frame delivery queue full for {id:?}");
        break;
      }

      match sender.try_send(TPacket::from_bytes(payload.to_vec())) {
        Ok(()) => break,
        Err(flume::TrySendError::Full(_)) => {
          log::trace!("UDP frame delivery queue full for {id:?}");
          break;
        }
        Err(flume::TrySendError::Disconnected(_)) if delivery_attempt == 0 => continue,
        Err(flume::TrySendError::Disconnected(_)) => break,
      }
    }
  }
}

#[derive(thiserror::Error, Debug)]
pub enum MtConnectionsListenerError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Postcard deserialization error: {0}")]
  PostcardDeserialization(postcard::Error),
  #[error("mTCP handshake timed out")]
  HandshakeTimeout,
}

impl From<PostcardStreamError> for MtConnectionsListenerError {
  fn from(error: PostcardStreamError) -> Self {
    match error {
      PostcardStreamError::Io(error) => Self::Io(error),
      PostcardStreamError::Deserialization(error) => Self::PostcardDeserialization(error),
    }
  }
}

async fn send_response_head(
  stream: &mut TcpStream,
  data: MtConnectionsResponseHeadData,
) -> Result<(), MtConnectionsListenerError> {
  let bytes =
    postcard::to_vec::<_, MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE>(&MtConnectionsResponseHead {
      magic: MtConnectionsMagic,
      data,
    })
    .unwrap();

  stream.write_all(&bytes).await?;

  Ok(())
}

async fn send_response_head_with_timeout(
  stream: &mut TcpStream,
  data: MtConnectionsResponseHeadData,
) -> Result<(), MtConnectionsListenerError> {
  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    send_response_head(stream, data),
  )
  .await
  .map_err(|_| MtConnectionsListenerError::HandshakeTimeout)?
}
