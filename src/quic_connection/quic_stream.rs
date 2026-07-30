use std::{
  pin::Pin,
  task::{Context, Poll},
};

use lowkit::DropCallback;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::primitives::ConnectionSide;

type QuicStreamDropCallback = DropCallback<Box<dyn Fn() + Send>>;

#[derive(derive_more::Debug, derive_more::Display)]
#[display("QuicStream {side} {id}")]
pub struct QuicStream {
  #[debug("{}", side)]
  side: ConnectionSide,
  id: u64,
  read: DuplexStream,
  write: DuplexStream,
  #[debug(ignore)]
  _drop_callback: QuicStreamDropCallback,
}

impl QuicStream {
  pub fn new(
    side: ConnectionSide,
    id: u64,
    read: DuplexStream,
    write: DuplexStream,
    drop_callback: QuicStreamDropCallback,
  ) -> Self {
    Self {
      side,
      id,
      read,
      write,
      _drop_callback: drop_callback,
    }
  }

  pub fn id(&self) -> u64 {
    self.id
  }
}

impl AsyncRead for QuicStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context,
    buf: &mut ReadBuf,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.read).poll_read(cx, buf)
  }
}

impl AsyncWrite for QuicStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    Pin::new(&mut self.write).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.write).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.write).poll_shutdown(cx)
  }
}
