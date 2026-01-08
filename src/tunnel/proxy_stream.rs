use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::TunnelError;
use super::tunnel::Stream as QuicStream;

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
    pub async fn relay_bidirectional<C>(&mut self, client: &mut C) -> Result<(), TunnelError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            ProxyStream::Quic(stream) => relay_quic_client(stream, client).await,
            ProxyStream::Tcp(tcp) => relay_tcp_client(tcp, client).await,
        }
    }

    /// Get the stream ID (only meaningful for QUIC streams).
    pub fn id(&self) -> u64 {
        match self {
            ProxyStream::Quic(stream) => stream.id(),
            ProxyStream::Tcp(_) => 0,
        }
    }
}

/// Relay between QUIC stream and client.
async fn relay_quic_client<C>(stream: &QuicStream, client: &mut C) -> Result<(), TunnelError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf = vec![0u8; 16384];
    let mut stream_buf = vec![0u8; 16384];

    let mut client_closed = false;
    let mut stream_closed = false;

    loop {
        tokio::select! {
            // Client -> Stream
            result = client.read(&mut client_buf), if !client_closed => {
                match result {
                    Ok(0) => {
                        client_closed = true;
                        let _ = stream.send_fin(&[]).await;
                    }
                    Ok(n) => {
                        stream.send(&client_buf[..n]).await?;
                    }
                    Err(e) => {
                        tracing::debug!("client read error: {}", e);
                        break;
                    }
                }
            }

            // Stream -> Client
            result = stream.recv_wait(&mut stream_buf), if !stream_closed => {
                match result {
                    Ok((0, true)) => {
                        stream_closed = true;
                        let _ = client.shutdown().await;
                    }
                    Ok((0, false)) => {
                        // No data yet, continue
                    }
                    Ok((n, fin)) => {
                        if client.write_all(&stream_buf[..n]).await.is_err() {
                            break;
                        }
                        if fin {
                            stream_closed = true;
                            let _ = client.shutdown().await;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("stream recv error: {}", e);
                        break;
                    }
                }
            }

            else => {
                // Both sides closed
                break;
            }
        }
    }

    Ok(())
}

/// Relay between TCP stream and client.
async fn relay_tcp_client<C>(tcp: &mut TcpStream, client: &mut C) -> Result<(), TunnelError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(client, tcp).await {
        Ok((client_to_server, server_to_client)) => {
            tracing::debug!(
                "DIRECT relay completed: client→server {} bytes, server→client {} bytes",
                client_to_server,
                server_to_client
            );
            Ok(())
        }
        Err(e) => {
            tracing::debug!("DIRECT relay error: {}", e);
            // Connection closed is normal
            Ok(())
        }
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
