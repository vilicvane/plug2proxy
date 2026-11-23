use std::{
  pin::Pin,
  task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::quic_connection::QuicStream;

/// QomT 层的可靠字节流，包装底层 QUIC 流。
///
/// 常规流走主连接（QUIC over mTCP）；短控制 RPC（如 `RESOLVE`）在双方协商
/// `p2p-s` 后可直接走 `QomT UDP` 的 QUIC 连接以消除 TCP 队头阻塞。
pub struct QomtStream {
  inner: QuicStream,
  udp_bypass: bool,
}

impl QomtStream {
  pub fn new(inner: QuicStream) -> Self {
    Self {
      inner,
      udp_bypass: false,
    }
  }

  pub(crate) fn new_udp_bypass(inner: QuicStream) -> Self {
    Self {
      inner,
      udp_bypass: true,
    }
  }

  pub fn id(&self) -> u64 {
    self.inner.id()
  }

  pub fn is_udp_bypass(&self) -> bool {
    self.udp_bypass
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
