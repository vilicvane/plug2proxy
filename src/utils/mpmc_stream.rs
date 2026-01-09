use std::{
  collections::VecDeque,
  io,
  pin::Pin,
  sync::Arc,
  task::{Context, Poll, Waker},
};

use tokio::{
  io::{AsyncRead, AsyncWrite, ReadBuf},
  sync::Mutex,
};

struct MpmcStreamInner {
  buffer: VecDeque<u8>,
  closed: bool,
  read_wakers: Vec<Waker>,
  write_wakers: Vec<Waker>,
  /// Maximum buffer size before writers start blocking
  max_buffer_size: usize,
}

impl MpmcStreamInner {
  fn new(max_buffer_size: usize) -> Self {
    Self {
      buffer: VecDeque::new(),
      closed: false,
      read_wakers: Vec::new(),
      write_wakers: Vec::new(),
      max_buffer_size,
    }
  }

  fn wake_readers(&mut self) {
    for waker in self.read_wakers.drain(..) {
      waker.wake();
    }
  }

  fn wake_writers(&mut self) {
    for waker in self.write_wakers.drain(..) {
      waker.wake();
    }
  }

  fn register_read_waker(&mut self, waker: &Waker) {
    if !self.read_wakers.iter().any(|w| w.will_wake(waker)) {
      self.read_wakers.push(waker.clone());
    }
  }

  fn register_write_waker(&mut self, waker: &Waker) {
    if !self.write_wakers.iter().any(|w| w.will_wake(waker)) {
      self.write_wakers.push(waker.clone());
    }
  }
}

/// A cloneable stream that implements `AsyncRead + AsyncWrite`.
///
/// Multiple readers and writers can share this stream:
/// - Writers append data to a shared buffer
/// - Readers consume data from the buffer (each byte is read only once)
/// - When the buffer is full, writers will block until readers consume data
#[derive(Clone)]
pub struct MpmcStream {
  inner: Arc<Mutex<MpmcStreamInner>>,
}

impl MpmcStream {
  /// Creates a new MPMC stream with the specified maximum buffer size.
  ///
  /// When the buffer reaches this size, writers will block until readers
  /// consume some data.
  pub fn new(max_buffer_size: usize) -> Self {
    Self {
      inner: Arc::new(Mutex::new(MpmcStreamInner::new(max_buffer_size))),
    }
  }

  /// Closes the stream, signaling EOF to all readers.
  ///
  /// Writers will receive an error after close.
  pub async fn close(&self) {
    let mut inner = self.inner.lock().await;
    inner.closed = true;
    inner.wake_readers();
    inner.wake_writers();
  }

  /// Returns the current number of bytes in the buffer.
  pub async fn buffer_len(&self) -> usize {
    self.inner.lock().await.buffer.len()
  }

  /// Returns true if the stream has been closed.
  pub async fn is_closed(&self) -> bool {
    self.inner.lock().await.closed
  }
}

impl Default for MpmcStream {
  /// Creates a new MPMC stream with a default buffer size of 64KB.
  fn default() -> Self {
    Self::new(64 * 1024)
  }
}

impl AsyncRead for MpmcStream {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let mut inner = match self.inner.try_lock() {
      Ok(guard) => guard,
      Err(_) => {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
    };

    if inner.buffer.is_empty() {
      if inner.closed {
        return Poll::Ready(Ok(()));
      }

      inner.register_read_waker(cx.waker());
      return Poll::Pending;
    }

    let to_read = buf.remaining().min(inner.buffer.len());
    let (first, second) = inner.buffer.as_slices();

    if to_read <= first.len() {
      buf.put_slice(&first[..to_read]);
    } else {
      buf.put_slice(first);
      buf.put_slice(&second[..to_read - first.len()]);
    }

    inner.buffer.drain(..to_read);

    // Wake writers if buffer was full
    if inner.buffer.len() + to_read >= inner.max_buffer_size {
      inner.wake_writers();
    }

    Poll::Ready(Ok(()))
  }
}

impl AsyncWrite for MpmcStream {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    let mut inner = match self.inner.try_lock() {
      Ok(guard) => guard,
      Err(_) => {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
    };

    if inner.closed {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "stream closed",
      )));
    }

    if inner.buffer.len() >= inner.max_buffer_size {
      inner.register_write_waker(cx.waker());
      return Poll::Pending;
    }

    let available = inner.max_buffer_size - inner.buffer.len();
    let to_write = buf.len().min(available);

    inner.buffer.extend(&buf[..to_write]);
    inner.wake_readers();

    Poll::Ready(Ok(to_write))
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let inner = match self.inner.try_lock() {
      Ok(guard) => guard,
      Err(_) => {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
    };

    if inner.closed {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "stream closed",
      )));
    }

    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut inner = match self.inner.try_lock() {
      Ok(guard) => guard,
      Err(_) => {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
    };

    inner.closed = true;
    inner.wake_readers();
    inner.wake_writers();

    Poll::Ready(Ok(()))
  }
}

#[cfg(test)]
mod tests {
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  use super::*;

  #[tokio::test]
  async fn test_basic_read_write() {
    let stream = MpmcStream::default();
    let mut writer = stream.clone();
    let mut reader = stream;

    writer.write_all(b"hello world").await.unwrap();

    let mut buf = [0u8; 11];
    reader.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf, b"hello world");
  }

  #[tokio::test]
  async fn test_multiple_readers() {
    let stream = MpmcStream::default();
    let mut writer = stream.clone();
    let mut reader1 = stream.clone();
    let mut reader2 = stream;

    writer.write_all(b"abcdef").await.unwrap();

    let mut buf1 = [0u8; 3];
    let mut buf2 = [0u8; 3];

    reader1.read_exact(&mut buf1).await.unwrap();
    reader2.read_exact(&mut buf2).await.unwrap();

    // Data should be consumed, not duplicated
    assert_eq!(&buf1, b"abc");
    assert_eq!(&buf2, b"def");
  }

  #[tokio::test]
  async fn test_multiple_writers() {
    let stream = MpmcStream::default();
    let mut writer1 = stream.clone();
    let mut writer2 = stream.clone();
    let mut reader = stream;

    writer1.write_all(b"hello").await.unwrap();
    writer2.write_all(b"world").await.unwrap();

    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf).await.unwrap();

    assert_eq!(&buf, b"helloworld");
  }

  #[tokio::test]
  async fn test_eof_on_close() {
    let stream = MpmcStream::default();
    let mut reader = stream.clone();

    stream.close().await;

    let mut buf = [0u8; 10];
    let n = reader.read(&mut buf).await.unwrap();

    assert_eq!(n, 0);
  }

  #[tokio::test]
  async fn test_write_after_close_fails() {
    let stream = MpmcStream::default();
    let mut writer = stream.clone();

    stream.close().await;

    let result = writer.write(b"test").await;
    assert!(result.is_err());
  }
}
