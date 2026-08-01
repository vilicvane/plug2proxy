use std::{
  pin::Pin,
  task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::quic_connection::QuicStream;

/// QomT 层的流，包装底层 QUIC 流。
///
/// 该类型始终表示 reliable byte stream，并固定走 QUIC stream over mTCP。
/// unreliable 由平级的 `QomtPacketStream` packet API 承载：
/// `AsyncWrite` 允许 partial write 且不保留包边界，不能安全表达丢包语义。
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
