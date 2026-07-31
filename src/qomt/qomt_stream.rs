use std::{
  pin::Pin,
  task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::quic_connection::QuicStream;

/// QomT 层的流，包装底层 QUIC 流。
///
/// 现阶段仅透传读写；后续将在此基础上为发送端增加
/// reliable / unreliable 语义（reliable 始终走 QUIC stream over mTCP，
/// unreliable 在 RTT 恶化时改走 UDP QUIC datagram 旁路）。
pub struct QomtStream {
  inner: QuicStream,
}

impl QomtStream {
  pub fn new(inner: QuicStream) -> Self {
    Self { inner }
  }

  pub fn id(&self) -> u64 {
    self.inner.id()
  }
}

impl AsyncRead for QomtStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context,
    buf: &mut ReadBuf,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl AsyncWrite for QomtStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}
