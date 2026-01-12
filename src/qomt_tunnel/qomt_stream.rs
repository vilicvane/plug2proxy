use std::{
  pin::Pin,
  task::{Context, Poll},
};

use lowkit::DropCallback;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, SimplexStream, WriteHalf};

type QomtStreamDropCallback = DropCallback<Box<dyn Fn() + Send>>;

pub struct QomtStream {
  read: ReadHalf<SimplexStream>,
  write: WriteHalf<SimplexStream>,
  _drop_callback: QomtStreamDropCallback,
}

impl QomtStream {
  pub fn new(
    read: ReadHalf<SimplexStream>,
    write: WriteHalf<SimplexStream>,
    drop_callback: QomtStreamDropCallback,
  ) -> Self {
    Self {
      read,
      write,
      _drop_callback: drop_callback,
    }
  }
}

impl AsyncRead for QomtStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context,
    buf: &mut ReadBuf,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.read).poll_read(cx, buf)
  }
}

impl AsyncWrite for QomtStream {
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
