use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  path::Path,
  sync::LazyLock,
};

use lits::{bytes, duration};

pub const MAX_DATAGRAM_SIZE: usize = bytes!("64 KiB") as usize;

pub const MAX_DATA_BUFFER_SIZE: u64 = bytes!("32 MiB");

pub static UNSPECIFIED_SOCKET_ADDRESS: LazyLock<SocketAddr> =
  LazyLock::new(|| SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)));

pub static HUB_QUICHE_CONFIG: LazyLock<quiche::Config> = LazyLock::new(|| {
  create_quiche_config("hub.pem", "ca.pem")
    .unwrap_or_else(|error| panic!("failed to create hub quiche config: {}", error))
});

pub static NODE_QUICHE_CONFIG: LazyLock<quiche::Config> = LazyLock::new(|| {
  create_quiche_config("node.pem", "ca.pem")
    .unwrap_or_else(|error| panic!("failed to create node quiche config: {}", error))
});

pub fn create_quiche_config(
  pem_path: impl AsRef<Path>,
  ca_pem_path: impl AsRef<Path>,
) -> quiche::Result<quiche::Config> {
  let pem_path = pem_path.as_ref().to_str().unwrap();
  let ca_pem_path = ca_pem_path.as_ref().to_str().unwrap();

  let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

  config.set_application_protos(&[b"p2p"])?;
  config.set_max_idle_timeout(duration!("1h").as_millis() as u64); // 1 hour - TCP transport handles connection liveness
  config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
  config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
  config.set_initial_max_data(MAX_DATA_BUFFER_SIZE);
  config.set_initial_max_stream_data_bidi_local(MAX_DATA_BUFFER_SIZE);
  config.set_initial_max_stream_data_bidi_remote(MAX_DATA_BUFFER_SIZE);
  config.set_initial_max_stream_data_uni(MAX_DATA_BUFFER_SIZE);
  config.set_initial_max_streams_bidi(1024);
  config.set_initial_max_streams_uni(1024);
  config.set_disable_active_migration(true);

  // Use BBR congestion control since we're running over TCP
  config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);

  config.load_cert_chain_from_pem_file(pem_path)?;
  config.load_priv_key_from_pem_file(pem_path)?;
  config.load_verify_locations_from_file(ca_pem_path)?;
  config.verify_peer(true);

  Ok(config)
}
