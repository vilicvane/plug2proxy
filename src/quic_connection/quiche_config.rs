use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  path::Path,
  sync::LazyLock,
};

use lits::{bytes, duration};

// quiche 把 DATAGRAM 帧长度固定编码为 2 字节 varint，单帧上限 16383；
// 超过即 BufferTooShort，且 quiche 不做自动分片。
// 该值同时作为 mTCP 帧（QUIC 包）长度上限，需与 quiche 配置一致。
pub const MAX_DATAGRAM_SIZE: usize = bytes!("16 KiB") as usize - 1;

pub const MAX_DATA_BUFFER_SIZE_PER_STREAM: u64 = bytes!("64 MiB");
pub const MAX_DATA_BUFFER_SIZE: u64 = MAX_DATA_BUFFER_SIZE_PER_STREAM * 8;

pub static UNSPECIFIED_SOCKET_ADDRESS: LazyLock<SocketAddr> =
  LazyLock::new(|| SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)));

pub fn create_quiche_config(pem_path: impl AsRef<Path>) -> quiche::Result<quiche::Config> {
  let pem_path = pem_path.as_ref().to_str().unwrap();

  let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

  config.set_application_protos(&[b"p2p"])?;
  config.set_max_idle_timeout(duration!("1h").as_millis() as u64); // 1 hour - TCP transport handles connection liveness
  config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
  config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
  config.set_initial_max_data(MAX_DATA_BUFFER_SIZE);
  config.set_initial_max_stream_data_bidi_local(MAX_DATA_BUFFER_SIZE_PER_STREAM);
  config.set_initial_max_stream_data_bidi_remote(MAX_DATA_BUFFER_SIZE_PER_STREAM);
  config.set_initial_max_stream_data_uni(MAX_DATA_BUFFER_SIZE_PER_STREAM);
  // 流上限取足够大的有限值：1024 曾在 DNS 故障的重试风暴中被打满（StreamLimit），
  // 而 u64::MAX 会让握手以 InvalidTransportParam 失败。
  config.set_initial_max_streams_bidi(65536);
  config.set_initial_max_streams_uni(65536);
  config.set_disable_active_migration(true);
  // QomT is carried by TCP, whose kernel congestion control already paces
  // writes. QUIC pacing here would throttle the same bytes a second time and
  // prevent independent TCP-backed QUIC connections from filling their paths.
  config.enable_pacing(false);

  config.load_cert_chain_from_pem_file(pem_path)?;
  config.load_priv_key_from_pem_file(pem_path)?;
  config.load_verify_locations_from_file(pem_path)?;
  config.verify_peer(true);

  Ok(config)
}
