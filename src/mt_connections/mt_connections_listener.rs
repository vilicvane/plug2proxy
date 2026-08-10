use std::{
  collections::HashMap,
  marker::PhantomData,
  net::IpAddr,
  sync::{Arc, Mutex, Weak},
};

use lowkit::{DropCallback, SelfWrapExt};
use tokio::{
  io::AsyncWriteExt,
  net::{TcpStream, UdpSocket},
  sync::mpsc,
  task::JoinSet,
  time::{Duration, sleep, timeout},
};

use crate::{
  mt_connections::{
    MAX_UDP_WIRE_DATAGRAM_SIZE, MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    MT_CONNECTIONS_RESPONSE_HEAD_BUFFER_SIZE, MtConnections, MtConnectionsId, MtConnectionsMagic,
    MtConnectionsPacket, MtConnectionsPacketMode, MtConnectionsRequestHead,
    MtConnectionsRequestHeadData, MtConnectionsResponseHead, MtConnectionsResponseHeadData,
    MtConnectionsSideUdpDuplex, MtConnectionsUdpPacket, UDP_RECV_BUFFER_SIZE, UdpDuplexSlot,
    configure_mt_tcp_stream, decode_udp_frame,
  },
  primitives::ConnectionSide,
  utils::postcard::{PostcardStreamError, postcard_read_stream},
};

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
  tcp_peer_ip: IpAddr,
  slot: Weak<UdpDuplexSlot<TPacket>>,
}

pub struct MtConnectionsListener<TPacket>
where
  TPacket: MtConnectionsPacket,
{
  listener: Arc<tokio::net::TcpListener>,
  tcp_stream_sender_map: HashMap<MtConnectionsId, mpsc::UnboundedSender<TcpStream>>,
  udp_dispatch_map: Arc<Mutex<HashMap<MtConnectionsId, UdpDispatchEntry<TPacket>>>>,
  udp_socket: Option<Arc<UdpSocket>>,
  // JoinSet drop 时自动 abort 全部任务（tokio 内置行为），
  // 分发循环随 listener 释放而终止，无需手动管理。
  _join_set: JoinSet<()>,
  _type_hint: PhantomData<TPacket>,
}

impl<TPacket> MtConnectionsListener<TPacket>
where
  TPacket: MtConnectionsPacket + MtConnectionsUdpPacket,
{
  pub fn new(listener: tokio::net::TcpListener, udp_socket: Option<UdpSocket>) -> Self {
    let udp_socket =
      udp_socket.and_then(
        |socket| match (listener.local_addr(), socket.local_addr()) {
          (Ok(tcp_address), Ok(udp_address)) if tcp_address.port() == udp_address.port() => {
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
        },
      );

    let udp_dispatch_map: Arc<Mutex<HashMap<MtConnectionsId, UdpDispatchEntry<TPacket>>>> =
      Arc::new(Mutex::new(HashMap::new()));

    let mut join_set = JoinSet::new();

    if let Some(udp_socket) = &udp_socket {
      join_set.spawn(udp_dispatch_loop(
        udp_socket.clone(),
        udp_dispatch_map.clone(),
      ));
    }

    Self {
      listener: listener.arc(),
      tcp_stream_sender_map: HashMap::new(),
      udp_dispatch_map,
      udp_socket,
      _join_set: join_set,
      _type_hint: PhantomData,
    }
  }

  pub async fn accept(&mut self) -> Result<MtConnections<TPacket>, MtConnectionsListenerError> {
    loop {
      let (mut stream, _) = self.listener.accept().await?;

      if configure_mt_tcp_stream(&stream)
        .inspect_err(|error| {
          log::warn!("error configuring incoming mTCP connection: {error}");
        })
        .is_err()
      {
        continue;
      }

      let Ok(request_head_result) = timeout(
        MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
        postcard_read_stream::<MtConnectionsRequestHead>(&mut stream),
      )
      .await
      else {
        log::warn!("timed out reading request head from incoming mTCP connection");
        continue;
      };

      let Ok(request_head) = request_head_result.inspect_err(|error| {
        log::warn!("error reading request head from incoming mTCP connections: {error}")
      }) else {
        continue;
      };

      match request_head.data {
        create @ (MtConnectionsRequestHeadData::Create
        | MtConnectionsRequestHeadData::CreateSequenced) => {
          let id = MtConnectionsId::new();
          let packet_mode = if create == MtConnectionsRequestHeadData::CreateSequenced {
            MtConnectionsPacketMode::Sequenced
          } else {
            MtConnectionsPacketMode::Legacy
          };
          let response = if packet_mode == MtConnectionsPacketMode::Sequenced {
            MtConnectionsResponseHeadData::CreatedSequenced(id)
          } else {
            MtConnectionsResponseHeadData::Created(id)
          };

          if send_response_head_with_timeout(&mut stream, response)
            .await
            .inspect_err(|error| {
              log::warn!(
                "error sending response head (created) to incoming mTCP connections: {error}"
              )
            })
            .is_err()
          {
            continue;
          }

          let (mut mt_connections, tcp_stream_sender, _) =
            MtConnections::new(stream, ConnectionSide::Server, id, packet_mode);

          self
            .tcp_stream_sender_map
            .retain(|_, tcp_stream_sender| !tcp_stream_sender.is_closed());

          self.tcp_stream_sender_map.insert(id, tcp_stream_sender);

          if self.udp_socket.is_some() {
            // 登记 UDP 分发槽位：UDP 首包在 accept 返回后的任意时刻到达，
            // 分发循环通过共享槽位把 duplex 写入 MtConnections。
            let slot = mt_connections.udp_duplex_slot();
            self.udp_dispatch_map.lock().unwrap().insert(
              id,
              UdpDispatchEntry {
                sender: None,
                peer_address: None,
                tcp_peer_ip: mt_connections.peer_address().ip().to_canonical(),
                slot: Arc::downgrade(&slot),
              },
            );

            // registration 跟随 MtConnections（包括 split 后的底层对象）存活，
            // 连接释放时立即注销，避免 listener map 持续增长。
            let udp_dispatch_map = Arc::downgrade(&self.udp_dispatch_map);
            mt_connections.set_udp_registration(DropCallback::new(Box::new(move || {
              if let Some(udp_dispatch_map) = udp_dispatch_map.upgrade() {
                udp_dispatch_map.lock().unwrap().remove(&id);
              }
            })
              as Box<dyn Fn() + Send>));
          }

          return Ok(mt_connections);
        }
        MtConnectionsRequestHeadData::Extend(id) => {
          if let Some(tcp_stream_sender) = self.tcp_stream_sender_map.get(&id) {
            if send_response_head_with_timeout(&mut stream, MtConnectionsResponseHeadData::Extended)
              .await
              .inspect_err(|error| {
                log::warn!(
                  "error sending response head (extended) to incoming mTCP connections: {error}"
                )
              })
              .is_err()
            {
              continue;
            }

            tcp_stream_sender.send(stream).ok();
          } else {
            if send_response_head_with_timeout(
              &mut stream,
              MtConnectionsResponseHeadData::AlreadyClosed,
            )
            .await
            .inspect_err(|error| {
              log::warn!(
                "error sending response head (already closed) to incoming mTCP connections: {error}"
              )
            })
            .is_err()
            {
              continue;
            }
          }
        }
      }
    }
  }

  #[cfg(test)]
  pub(crate) fn udp_dispatch_count(&self) -> usize {
    self.udp_dispatch_map.lock().unwrap().len()
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

        if from.ip().to_canonical() != entry.tcp_peer_ip {
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

          let (duplex, sender) =
            MtConnectionsSideUdpDuplex::listener_side(udp_socket.clone(), from, id);

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
