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
