use std::{
  net::SocketAddr,
  pin::Pin,
  sync::{Arc, Weak},
  task::{Context, Poll},
  time::Duration,
};

use futures::{Sink, Stream};
use lowkit::{SelfWrapExt, tokio_join_set};
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};

use crate::{mt_connections::MtConnectionsId, utils::net::SocketAddressExt};

/// UDP 帧头长度：MtConnectionsId 的 16 字节原始字节（compact UUID）。
pub const MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE: usize = 16;

/// 1500-byte IPv6 路径上的 UDP payload 预算（1500 - IPv6 40B - UDP 8B）。
pub const MAX_UDP_WIRE_DATAGRAM_SIZE: usize = 1452;

/// 路由头之后可承载的最大包体。这个值才是上层 quiche 的 UDP payload 上限。
pub const MAX_UDP_PACKET_FRAME_SIZE: usize =
  MAX_UDP_WIRE_DATAGRAM_SIZE - MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE;

/// 多留一个字节以检测并丢弃被截断的超长数据报。
pub(crate) const UDP_RECV_BUFFER_SIZE: usize = MAX_UDP_WIRE_DATAGRAM_SIZE + 1;

/// 吸收驱动任务切换间隙与小突发，同时保持明确的每连接内存上限。
const UDP_INCOMING_PACKET_QUEUE_CAPACITY: usize = 64;

/// 接收端未就绪时投递的等待上限：超时丢包回到 recv_from，保证对端错误
/// （ICMP port unreachable 等）能被检测并驱动通道关闭。
pub(crate) const MT_CONNECTIONS_UDP_DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);

pub trait MtConnectionsUdpPacket: Sized + Send + 'static {
  fn as_bytes(&self) -> &[u8];

  fn from_bytes(bytes: Vec<u8>) -> Self;
}

impl MtConnectionsUdpPacket for Vec<u8> {
  fn as_bytes(&self) -> &[u8] {
    self
  }

  fn from_bytes(bytes: Vec<u8>) -> Self {
    bytes
  }
}

/// 编码 UDP 帧：`MtConnectionsId(16B) + 包体`。
///
/// listener 侧按帧头的 MtConnectionsId 无状态分发；connect 侧按帧头校验。
pub fn encode_udp_frame(
  id: &MtConnectionsId,
  packet: &impl MtConnectionsUdpPacket,
) -> Option<Vec<u8>> {
  if packet.as_bytes().len() > MAX_UDP_PACKET_FRAME_SIZE {
    return None;
  }

  let mut frame = Vec::with_capacity(MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE + packet.as_bytes().len());

  frame.extend_from_slice(id.as_bytes());
  frame.extend_from_slice(packet.as_bytes());

  Some(frame)
}

/// 解码 UDP 帧，返回（帧头 id，包体）。
pub fn decode_udp_frame(frame: &[u8]) -> Option<(MtConnectionsId, &[u8])> {
  if frame.len() < MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE {
    return None;
  }

  let id = MtConnectionsId::from_bytes(
    frame[..MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE]
      .try_into()
      .ok()?,
  );

  Some((id, &frame[MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE..]))
}

/// 一条 MtConnections 的 UDP 侧双工通道，帧格式为 `MtConnectionsId + 包体`。
///
/// 每个实例固定一个对端；上层 QUIC 连接释放时实例及其后台任务一同释放。
pub struct MtConnectionsSideUdpDuplex<TPacket>
where
  TPacket: 'static,
{
  id: MtConnectionsId,
  peer_address: SocketAddr,
  local_address: SocketAddr,
  packet_sink: Pin<Box<dyn Sink<TPacket, Error = std::io::Error> + Send>>,
  packet_stream: flume::r#async::RecvStream<'static, TPacket>,
  _join_set: JoinSet<()>,
}

impl<TPacket> MtConnectionsSideUdpDuplex<TPacket>
where
  TPacket: MtConnectionsUdpPacket,
{
  /// connect 侧构造：绑定本地 UDP socket（随机端口），向 `peer_address` 收发帧。
  ///
  /// 收到帧头 id 与自身 id 不符的包（杂包/注入）时静默丢弃；
  /// UDP 数据报天然带消息边界，一个数据报即一个包体，无需长度前缀。
  pub async fn connect_side(
    peer_address: SocketAddr,
    id: MtConnectionsId,
  ) -> std::io::Result<Self> {
    let socket = UdpSocket::bind(peer_address.unspecified()).await?;

    // UDP connect：限定单一对端并让 ICMP 错误（如对端无监听）通过
    // recv_from 快速返回，驱动 duplex 关闭而非挂起等超时。
    socket.connect(peer_address).await?;

    Ok(Self::from_socket_inner(socket, peer_address, id, true))
  }

  /// 基于已绑定的 UDP socket 构造（测试等场景可直接指定本地地址）。
  #[cfg(test)]
  fn from_socket(socket: UdpSocket, peer_address: SocketAddr, id: MtConnectionsId) -> Self {
    Self::from_socket_inner(socket, peer_address, id, false)
  }

  fn from_socket_inner(
    socket: UdpSocket,
    peer_address: SocketAddr,
    id: MtConnectionsId,
    connected: bool,
  ) -> Self {
    let local_address = socket
      .local_addr()
      .expect("a bound UDP socket must have a local address");
    let socket = socket.arc();

    let (packet_sender, external_packet_receiver) =
      flume::bounded::<TPacket>(UDP_INCOMING_PACKET_QUEUE_CAPACITY);

    let send_peer_address = peer_address;
    let packet_sink =
      futures::sink::unfold(socket.clone(), move |socket, packet: TPacket| async move {
        let frame = encode_udp_frame(&id, &packet).ok_or_else(|| {
          std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
              "UDP packet exceeds frame limit: {} > {}",
              packet.as_bytes().len(),
              MAX_UDP_PACKET_FRAME_SIZE,
            ),
          )
        })?;

        let length = if connected {
          socket.send(&frame).await?
        } else {
          socket.send_to(&frame, send_peer_address).await?
        };

        log::trace!("sent {length}-byte UDP frame to {send_peer_address}");

        Ok(socket)
      });

    let recv_socket = socket.clone();
    let recv_packet_sender = packet_sender.clone();
    let recv_loop = async move {
      let mut buffer = vec![0; UDP_RECV_BUFFER_SIZE];

      loop {
        let recv_result = if connected {
          recv_socket
            .recv(&mut buffer)
            .await
            .map(|length| (length, peer_address))
        } else {
          recv_socket.recv_from(&mut buffer).await
        };

        let Ok((length, from)) = recv_result else {
          break;
        };

        if length > MAX_UDP_WIRE_DATAGRAM_SIZE {
          continue;
        }

        if !connected && from != peer_address {
          continue;
        }

        log::trace!("received {length}-byte UDP frame from {from}");

        let Some((packet_id, payload)) = decode_udp_frame(&buffer[..length]) else {
          continue;
        };

        if packet_id != id {
          continue;
        }

        // 投递等待有上限：接收端（quiche）处理间隙短暂等待后仍未就绪
        // 则丢包回到 recv_from，保证对端错误（如 ICMP port unreachable）
        // 能被检测到并驱动通道关闭；UDP 语义允许丢包，QUIC 重传兜底。
        match timeout(
          MT_CONNECTIONS_UDP_DELIVERY_TIMEOUT,
          recv_packet_sender.send_async(TPacket::from_bytes(payload.to_vec())),
        )
        .await
        {
          Ok(Ok(())) => {}
          Ok(Err(_)) => break,
          Err(_) => continue,
        }
      }
    };

    Self {
      id,
      peer_address,
      local_address,
      packet_sink: Box::pin(packet_sink),
      packet_stream: external_packet_receiver.into_stream(),
      _join_set: tokio_join_set!(recv_loop),
    }
  }

  /// listener 侧构造：共享全局 UDP socket，包由外部分发循环投递。
  ///
  /// sink 直接向 `peer_address` 发送并传播 socket 错误；收包由分发循环
  /// 通过返回的 sender 投递。sender 与 duplex 解耦：duplex 被 take 后
  /// 分发仍可继续。
  pub(crate) fn listener_side(
    socket: Arc<UdpSocket>,
    peer_address: SocketAddr,
    id: MtConnectionsId,
  ) -> (Self, flume::Sender<TPacket>) {
    let local_address = socket
      .local_addr()
      .expect("a bound UDP socket must have a local address");
    let (packet_sender, external_packet_receiver) =
      flume::bounded::<TPacket>(UDP_INCOMING_PACKET_QUEUE_CAPACITY);

    // Endpoint 不应延长 listener 全局 socket 的生命周期；listener drop 后
    // upgrade 失败会作为底层 transport error 传播给 quiche。
    let send_socket: Weak<UdpSocket> = Arc::downgrade(&socket);
    let send_peer_address = peer_address;
    let packet_sink = futures::sink::unfold(
      send_socket,
      move |send_socket, packet: TPacket| async move {
        let socket = send_socket.upgrade().ok_or_else(|| {
          std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "QomT UDP listener is closed",
          )
        })?;
        let frame = encode_udp_frame(&id, &packet).ok_or_else(|| {
          std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
              "UDP packet exceeds frame limit: {} > {}",
              packet.as_bytes().len(),
              MAX_UDP_PACKET_FRAME_SIZE,
            ),
          )
        })?;

        let length = socket.send_to(&frame, send_peer_address).await?;
        log::trace!("sent {length}-byte UDP frame to {send_peer_address}");

        Ok(send_socket)
      },
    );

    (
      Self {
        id,
        peer_address,
        local_address,
        packet_sink: Box::pin(packet_sink),
        packet_stream: external_packet_receiver.into_stream(),
        _join_set: JoinSet::new(),
      },
      packet_sender,
    )
  }

  pub fn id(&self) -> MtConnectionsId {
    self.id
  }

  pub fn peer_address(&self) -> SocketAddr {
    self.peer_address
  }

  pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
    Ok(self.local_address)
  }
}

impl<TPacket> Stream for MtConnectionsSideUdpDuplex<TPacket>
where
  TPacket: MtConnectionsUdpPacket,
{
  type Item = TPacket;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
    Pin::new(&mut self.packet_stream).poll_next(cx)
  }
}

impl<TPacket> Sink<TPacket> for MtConnectionsSideUdpDuplex<TPacket>
where
  TPacket: MtConnectionsUdpPacket,
{
  type Error = std::io::Error;

  fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_ready(cx)
  }

  fn start_send(mut self: Pin<&mut Self>, item: TPacket) -> Result<(), Self::Error> {
    Pin::new(&mut self.packet_sink).start_send(item)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_flush(cx)
  }

  fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
    Pin::new(&mut self.packet_sink).poll_close(cx)
  }
}

#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use tokio::time::{Duration, timeout};

  use super::*;

  #[test]
  fn test_frame_roundtrip() {
    let id = MtConnectionsId::new();
    let payload = vec![0xde, 0xad, 0xbe, 0xef];

    let frame = encode_udp_frame(&id, &payload).unwrap();

    assert_eq!(
      frame.len(),
      MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE + payload.len()
    );

    let (decoded_id, decoded_payload) = decode_udp_frame(&frame).unwrap();

    assert_eq!(decoded_id, id);
    assert_eq!(decoded_payload, payload.as_slice());
  }

  #[test]
  fn test_frame_too_short() {
    assert!(decode_udp_frame(&[0; MT_CONNECTIONS_UDP_FRAME_HEAD_SIZE - 1]).is_none());
    assert!(decode_udp_frame(&[]).is_none());
  }

  #[test]
  fn test_frame_keeps_packet_id() {
    let id_a = MtConnectionsId::new();
    let id_b = MtConnectionsId::new();
    let payload = vec![0x42; 64];

    let frame = encode_udp_frame(&id_a, &payload).unwrap();
    let (decoded_id, _) = decode_udp_frame(&frame).unwrap();

    assert_eq!(decoded_id, id_a);
    assert_ne!(decoded_id, id_b);
  }

  #[tokio::test]
  async fn test_duplex_sends_and_receives_between_sides() {
    let id = MtConnectionsId::new();

    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address_a = socket_a.local_addr().unwrap();

    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address_b = socket_b.local_addr().unwrap();

    let mut duplex_a = MtConnectionsSideUdpDuplex::<Vec<u8>>::from_socket(socket_a, address_b, id);
    let mut duplex_b = MtConnectionsSideUdpDuplex::<Vec<u8>>::from_socket(socket_b, address_a, id);

    let packet_a = vec![0x01, 0x02, 0x03];
    let packet_b = vec![0x04, 0x05];

    let received_by_b = {
      let receive = duplex_b.next();
      tokio::pin!(receive);

      duplex_a.send(packet_a.clone()).await.unwrap();

      timeout(Duration::from_secs(5), &mut receive)
        .await
        .unwrap()
        .unwrap()
    };

    let received_by_a = {
      let receive = duplex_a.next();
      tokio::pin!(receive);

      duplex_b.send(packet_b.clone()).await.unwrap();

      timeout(Duration::from_secs(5), &mut receive)
        .await
        .unwrap()
        .unwrap()
    };

    assert_eq!(received_by_b, packet_a);
    assert_eq!(received_by_a, packet_b);
  }

  #[tokio::test]
  async fn listener_socket_close_is_reported_by_the_sink() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut duplex, _sender) = MtConnectionsSideUdpDuplex::<Vec<u8>>::listener_side(
      socket.clone(),
      peer.local_addr().unwrap(),
      MtConnectionsId::new(),
    );

    drop(socket);

    let error = duplex.send(vec![0x01]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
  }

  #[test]
  fn test_frame_respects_ipv6_mtu_budget() {
    let id = MtConnectionsId::new();
    let maximum_packet = vec![0; MAX_UDP_PACKET_FRAME_SIZE];

    let frame = encode_udp_frame(&id, &maximum_packet).unwrap();

    assert_eq!(frame.len(), MAX_UDP_WIRE_DATAGRAM_SIZE);
    assert!(encode_udp_frame(&id, &vec![0; MAX_UDP_PACKET_FRAME_SIZE + 1]).is_none());
  }

  #[tokio::test]
  async fn test_duplex_drops_packets_with_wrong_id() {
    let id_a = MtConnectionsId::new();
    let id_b = MtConnectionsId::new();

    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address_a = socket_a.local_addr().unwrap();

    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address_b = socket_b.local_addr().unwrap();

    // A 用 id_a 发，B 用 id_b 收：帧头 id 不匹配，B 应丢弃。
    let mut duplex_a =
      MtConnectionsSideUdpDuplex::<Vec<u8>>::from_socket(socket_a, address_b, id_a);
    let mut duplex_b =
      MtConnectionsSideUdpDuplex::<Vec<u8>>::from_socket(socket_b, address_a, id_b);

    duplex_a.send(vec![0x7f]).await.unwrap();

    assert!(
      timeout(Duration::from_millis(200), duplex_b.next())
        .await
        .is_err(),
      "wrong-id packet should be dropped"
    );
  }
}
