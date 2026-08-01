use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  path::Path,
  sync::LazyLock,
};

use lits::{bytes, duration};

use crate::mt_connections::MAX_UDP_PACKET_FRAME_SIZE;

// quiche 把 DATAGRAM 帧长度固定编码为 2 字节 varint，单帧上限 16383；
// 超过即 BufferTooShort，且 quiche 不做自动分片。
// 该值同时作为 mTCP 帧（QUIC 包）长度上限，需与 quiche 配置一致。
pub const MAX_DATAGRAM_SIZE: usize = bytes!("16 KiB") as usize - 1;

// UDP 旁路路径的 QUIC 包上限。外层 UDP payload 的 1452-byte IPv6 MTU
// 预算还要扣掉 MtConnectionsId 路由头；真正传给 quiche 的是 1436。
pub const MAX_UDP_DATAGRAM_SIZE: usize = MAX_UDP_PACKET_FRAME_SIZE;

/// quiche's DATAGRAM queues and the wrapper receive queue use the same
/// bounded capacity. DATAGRAM delivery is intentionally lossy: once either
/// queue is full, new application datagrams are rejected or dropped instead
/// of applying stream-style backpressure to the QUIC driver.
pub const QUIC_DATAGRAM_QUEUE_CAPACITY: usize = 64;

/// The UDP bypass is actively kept alive by QUIC PING frames. If no packet is
/// received for this long, quiche closes the path and the QomT supervisor can
/// establish a new UDP QUIC connection. quiche may raise the effective value
/// to at least three PTOs on unusually high-latency paths.
pub const QOMT_UDP_IDLE_TIMEOUT: std::time::Duration = duration!("15s");

pub const MAX_DATA_BUFFER_SIZE_PER_STREAM: u64 = bytes!("64 MiB");
pub const MAX_DATA_BUFFER_SIZE: u64 = MAX_DATA_BUFFER_SIZE_PER_STREAM * 8;

pub static UNSPECIFIED_SOCKET_ADDRESS: LazyLock<SocketAddr> =
  LazyLock::new(|| SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)));

fn create_common_quiche_config(pem_path: impl AsRef<Path>) -> quiche::Result<quiche::Config> {
  let pem_path = pem_path.as_ref().to_str().unwrap();

  let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

  config.set_application_protos(&[b"p2p"])?;
  // The main QUIC-over-mTCP connection is long-lived. The UDP-specific
  // builder below overrides this with a short, actively kept-alive timeout so
  // quiche can classify a blackholed branch and trigger its supervisor.
  config.set_max_idle_timeout(duration!("1h").as_millis() as u64);
  config.set_initial_max_data(MAX_DATA_BUFFER_SIZE);
  config.set_initial_max_stream_data_bidi_local(MAX_DATA_BUFFER_SIZE_PER_STREAM);
  config.set_initial_max_stream_data_bidi_remote(MAX_DATA_BUFFER_SIZE_PER_STREAM);
  config.set_initial_max_stream_data_uni(MAX_DATA_BUFFER_SIZE_PER_STREAM);
  // 流上限取足够大的有限值：1024 曾在 DNS 故障的重试风暴中被打满（StreamLimit），
  // 而 u64::MAX 会让握手以 InvalidTransportParam 失败。
  config.set_initial_max_streams_bidi(65536);
  config.set_initial_max_streams_uni(65536);
  config.set_disable_active_migration(true);

  config.load_cert_chain_from_pem_file(pem_path)?;
  config.load_priv_key_from_pem_file(pem_path)?;
  config.load_verify_locations_from_file(pem_path)?;
  config.verify_peer(true);

  Ok(config)
}

pub fn create_quiche_config(pem_path: impl AsRef<Path>) -> quiche::Result<quiche::Config> {
  let mut config = create_common_quiche_config(pem_path)?;

  config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
  config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
  // QomT is carried by TCP, whose kernel congestion control already paces
  // writes. QUIC pacing here would throttle the same bytes a second time and
  // prevent the main QomT connection from filling its parallel mTCP paths.
  config.enable_pacing(false);

  Ok(config)
}

/// UDP 旁路路径的 quiche 配置：共享证书、ALPN 与流控参数，但保留真实
/// UDP 所需的 QUIC pacing，并把包大小限制到外层帧的 MTU 预算内。
pub fn create_udp_quiche_config(pem_path: impl AsRef<Path>) -> quiche::Result<quiche::Config> {
  let mut config = create_common_quiche_config(pem_path)?;

  config.set_max_idle_timeout(QOMT_UDP_IDLE_TIMEOUT.as_millis() as u64);
  config.set_max_recv_udp_payload_size(MAX_UDP_DATAGRAM_SIZE);
  config.set_max_send_udp_payload_size(MAX_UDP_DATAGRAM_SIZE);
  config.enable_dgram(
    true,
    QUIC_DATAGRAM_QUEUE_CAPACITY,
    QUIC_DATAGRAM_QUEUE_CAPACITY,
  );
  config.enable_pacing(true);

  Ok(config)
}
