use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::TunnelError;
use super::tunnel::Stream as QuicStream;
use crate::util::copy_bidirectional;

/// A unified stream type that can be either a QUIC stream (through tunnel)
/// or a direct TCP stream (for DIRECT routing).
pub enum ProxyStream {
    /// QUIC stream through tunnel (HUB or direct OUT).
    Quic(QuicStream),
    /// Direct TCP connection (DIRECT routing).
    Tcp(TcpStream),
}

impl ProxyStream {
    /// Create from a QUIC stream.
    pub fn from_quic(stream: QuicStream) -> Self {
        ProxyStream::Quic(stream)
    }

    /// Create from a TCP stream.
    pub fn from_tcp(stream: TcpStream) -> Self {
        ProxyStream::Tcp(stream)
    }

    /// Relay data bidirectionally between this stream and a client.
    /// Consumes self since the stream is split for the relay.
    pub async fn relay_bidirectional<C>(self, client: C) -> Result<(), TunnelError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            ProxyStream::Quic(stream) => {
                let (stream_read, stream_write) = stream.into_split();
                let (client_read, client_write) = tokio::io::split(client);
                copy_bidirectional(stream_read, stream_write, client_read, client_write).await?;
            }
            ProxyStream::Tcp(tcp) => {
                let (tcp_read, tcp_write) = tcp.into_split();
                let (client_read, client_write) = tokio::io::split(client);
                copy_bidirectional(tcp_read, tcp_write, client_read, client_write).await?;
            }
        };

        Ok(())
    }

    /// Get the stream ID (only meaningful for QUIC streams).
    pub fn id(&self) -> u64 {
        match self {
            ProxyStream::Quic(stream) => stream.id(),
            ProxyStream::Tcp(_) => 0,
        }
    }

    /// Send data on this stream.
    pub async fn send(&mut self, data: &[u8]) -> Result<usize, TunnelError> {
        match self {
            ProxyStream::Quic(stream) => stream.send(data).await,
            ProxyStream::Tcp(tcp) => {
                tcp.write_all(data).await.map_err(TunnelError::Io)?;
                Ok(data.len())
            }
        }
    }

    /// Receive data from this stream (non-blocking for QUIC, blocking for TCP).
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, bool), TunnelError> {
        match self {
            ProxyStream::Quic(stream) => stream.recv(buf).await,
            ProxyStream::Tcp(tcp) => {
                let n = tcp.read(buf).await.map_err(TunnelError::Io)?;
                Ok((n, n == 0))
            }
        }
    }

    /// Wait for data to be available, then receive.
    pub async fn recv_wait(&mut self, buf: &mut [u8]) -> Result<(usize, bool), TunnelError> {
        match self {
            ProxyStream::Quic(stream) => stream.recv_wait(buf).await,
            ProxyStream::Tcp(tcp) => {
                let n = tcp.read(buf).await.map_err(TunnelError::Io)?;
                Ok((n, n == 0))
            }
        }
    }

    /// Close the stream.
    pub async fn close(&self) -> Result<(), TunnelError> {
        match self {
            ProxyStream::Quic(stream) => stream.close().await,
            ProxyStream::Tcp(_) => {
                // TCP stream will be closed when dropped
                Ok(())
            }
        }
    }

    /// Convert to TCP stream (only works for TCP variant).
    /// Useful for wrapping with TLS.
    pub fn into_tcp_stream(self) -> Result<TcpStream, TunnelError> {
        match self {
            ProxyStream::Tcp(tcp) => Ok(tcp),
            ProxyStream::Quic(_) => Err(TunnelError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot convert QUIC stream to TCP stream",
            ))),
        }
    }

    /// Check if this is a TCP stream (can be wrapped in TLS).
    pub fn is_tcp(&self) -> bool {
        matches!(self, ProxyStream::Tcp(_))
    }

    /// Check if this is a QUIC stream.
    pub fn is_quic(&self) -> bool {
        matches!(self, ProxyStream::Quic(_))
    }
}

impl std::fmt::Debug for ProxyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyStream::Quic(s) => write!(f, "ProxyStream::Quic(id={})", s.id()),
            ProxyStream::Tcp(_) => write!(f, "ProxyStream::Tcp"),
        }
    }
}
