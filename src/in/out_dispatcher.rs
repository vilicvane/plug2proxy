use async_trait::async_trait;
use tokio::{
  io::{AsyncRead, AsyncWrite},
  net::TcpStream,
};

use crate::{out::OutExit, primitives::SocketDestination};

#[async_trait]
pub trait OutDispatcher: Send + Sync {
  fn match_exit(&self, exit: &OutExit) -> bool;

  async fn connect(
    &self,
    exit: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn OutTcpStream>, Error>;
}

pub trait OutTcpStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> OutTcpStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}
