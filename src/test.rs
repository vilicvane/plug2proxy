use std::{
  fs::create_dir_all,
  net::{SocketAddr, TcpListener},
  path::PathBuf,
};

pub fn test_dir() -> PathBuf {
  let test_dir = PathBuf::from(".test");

  create_dir_all(&test_dir).unwrap();

  test_dir
}

pub fn get_free_local_tcp_address() -> SocketAddr {
  TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
}

/// Initials before and after the server selects its connection ID. Keep the
/// client SCID empty, as Chrome does for connections without migration support.
pub async fn quic_initials_with_server_cid(
  source: SocketAddr,
  destination: SocketAddr,
  server_name: &str,
  retry: bool,
) -> anyhow::Result<[Vec<u8>; 2]> {
  let [mut server_config, mut client_config] =
    crate::quic_connection::tests::get_udp_quiche_configs().await?;
  for config in [&mut server_config, &mut client_config] {
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"])?;
  }
  let mut client = quiche::connect(
    Some(server_name),
    &quiche::ConnectionId::from_ref(&[]),
    source,
    destination,
    &mut client_config,
  )?;
  let mut first = vec![0; 1350];
  let (length, _) = client.send(&mut first)?;
  first.truncate(length);
  let header = quiche::Header::from_slice(&mut first, quiche::MAX_CONN_ID_LEN)?;
  let server_cid = quiche::ConnectionId::from_ref(&[0x93; 16]);
  let mut reply = vec![0; 1200];
  let length = if retry {
    quiche::retry(
      &header.scid,
      &header.dcid,
      &server_cid,
      b"test-token",
      header.version,
      &mut reply,
    )?
  } else {
    let mut server = quiche::accept(&server_cid, None, destination, source, &mut server_config)?;
    server.recv(
      &mut first.clone(),
      quiche::RecvInfo {
        from: source,
        to: destination,
      },
    )?;
    server.send(&mut reply)?.0
  };
  client.recv(
    &mut reply[..length],
    quiche::RecvInfo {
      from: destination,
      to: source,
    },
  )?;
  let mut next = vec![0; 1350];
  let (length, _) = client.send(&mut next)?;
  next.truncate(length);
  let next_header = quiche::Header::from_slice(&mut next, quiche::MAX_CONN_ID_LEN)?;
  assert_eq!(next_header.ty, quiche::Type::Initial);
  assert!(header.scid.is_empty());
  assert!(next_header.scid.is_empty());
  assert_ne!(header.dcid, next_header.dcid);
  assert_eq!(next_header.dcid, server_cid);
  Ok([first, next])
}
