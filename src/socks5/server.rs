use std::net::SocketAddr;
use std::sync::Arc;

use fast_socks5::Socks5Command;
use fast_socks5::server::{Config, Socks5Socket};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::node::InNode;

/// SOCKS5 server that accepts connections and proxies through InNode.
pub struct Socks5Server {
    in_node: Arc<InNode>,
    bind_addr: SocketAddr,
}

impl Socks5Server {
    pub fn new(in_node: Arc<InNode>, bind_addr: SocketAddr) -> Self {
        Self { in_node, bind_addr }
    }

    /// Run the SOCKS5 server.
    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        tracing::info!("SOCKS5 server listening on {}", self.bind_addr);

        // Create fast-socks5 config (no authentication)
        let config = Arc::new(Config::default());

        loop {
            let (stream, peer) = listener.accept().await?;
            tracing::debug!("accepted SOCKS5 connection from {}", peer);

            let in_node = Arc::clone(&self.in_node);
            let config = Arc::clone(&config);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, in_node, config).await {
                    tracing::error!("SOCKS5 client {} error: {}", peer, e);
                }
            });
        }
    }

    /// Handle a single SOCKS5 client connection.
    async fn handle_client(
        stream: tokio::net::TcpStream,
        in_node: Arc<InNode>,
        config: Arc<Config>,
    ) -> Result<(), Socks5Error> {
        // Create Socks5Socket wrapper
        let mut socket = Socks5Socket::new(stream, config);

        // Perform SOCKS5 handshake and get the request
        socket = socket.upgrade_to_socks5().await?;

        // Get the target address
        let target_addr = socket.target_addr().ok_or_else(|| Socks5Error::NoTarget)?;

        let target = format!("{}", target_addr);
        tracing::info!("SOCKS5 request: {:?} to {}", socket.cmd(), target);

        // Only handle CONNECT command
        match socket.cmd() {
            Some(Socks5Command::TCPConnect) => {
                Self::handle_connect(socket, in_node, target).await?;
            }
            Some(cmd) => {
                tracing::warn!("unsupported SOCKS5 command: {:?}", cmd);
                return Err(Socks5Error::UnsupportedCommand);
            }
            None => {
                return Err(Socks5Error::NoCommand);
            }
        }

        Ok(())
    }

    /// Handle CONNECT command.
    async fn handle_connect<T: AsyncRead + AsyncWrite + Unpin>(
        socket: Socks5Socket<T, impl fast_socks5::server::Authentication>,
        in_node: Arc<InNode>,
        target: String,
    ) -> Result<(), Socks5Error> {
        // Connect through InNode
        let tunnel_stream = match in_node.connect(&target).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::error!("failed to connect to {}: {}", target, e);
                // Note: fast-socks5 doesn't provide a way to send error replies after upgrade
                // The library expects us to handle the connection or drop it
                return Err(Socks5Error::ConnectFailed(e.into()));
            }
        };

        tracing::info!("connected to {} via stream {}", target, tunnel_stream.id());

        // Get the underlying TCP stream from Socks5Socket
        let client_stream = socket.into_inner();

        // Relay bidirectionally
        relay_bidirectional(client_stream, tunnel_stream).await?;

        Ok(())
    }
}

/// Relay data bidirectionally between client and tunnel stream.
async fn relay_bidirectional<C>(
    mut client: C,
    stream: crate::tunnel::Stream,
) -> Result<(), Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = stream.id();
    tracing::debug!("starting relay for stream {}", stream_id);

    let mut client_buf = vec![0u8; 16384];
    let mut stream_buf = vec![0u8; 16384];

    let mut client_closed = false;
    let mut stream_closed = false;

    loop {
        tokio::select! {
            // Read from client, send to stream
            result = client.read(&mut client_buf), if !client_closed => {
                match result {
                    Ok(0) => {
                        tracing::debug!("client closed connection (stream {})", stream_id);
                        if let Err(e) = stream.close().await {
                            tracing::warn!("failed to close stream {}: {}", stream_id, e);
                        }
                        client_closed = true;
                    }
                    Ok(n) => {
                        tracing::trace!("client -> stream {}: {} bytes", stream_id, n);
                        if let Err(e) = stream.send(&client_buf[..n]).await {
                            tracing::error!("failed to send to stream {}: {}", stream_id, e);
                            return Err(Socks5Error::RelayError(e.into()));
                        }
                    }
                    Err(e) => {
                        tracing::error!("client read error (stream {}): {}", stream_id, e);
                        return Err(Socks5Error::IoError(e));
                    }
                }
            }

            // Read from stream, send to client
            result = stream.recv(&mut stream_buf), if !stream_closed => {
                match result {
                    Ok((0, false)) => {
                        // No data available yet
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                    Ok((0, true)) => {
                        tracing::debug!("stream {} closed by remote", stream_id);
                        if let Err(e) = client.shutdown().await {
                            tracing::warn!("failed to shutdown client: {}", e);
                        }
                        stream_closed = true;
                    }
                    Ok((n, fin)) => {
                        tracing::trace!("stream {} -> client: {} bytes (fin={})", stream_id, n, fin);
                        if let Err(e) = client.write_all(&stream_buf[..n]).await {
                            tracing::error!("client write error (stream {}): {}", stream_id, e);
                            return Err(Socks5Error::IoError(e));
                        }
                        if let Err(e) = client.flush().await {
                            tracing::error!("client flush error (stream {}): {}", stream_id, e);
                            return Err(Socks5Error::IoError(e));
                        }
                        if fin {
                            tracing::debug!("stream {} received FIN", stream_id);
                            if let Err(e) = client.shutdown().await {
                                tracing::warn!("failed to shutdown client: {}", e);
                            }
                            stream_closed = true;
                        }
                    }
                    Err(e) => {
                        tracing::error!("stream {} recv error: {}", stream_id, e);
                        return Err(Socks5Error::RelayError(e.into()));
                    }
                }
            }
        }

        // Both sides closed
        if client_closed && stream_closed {
            tracing::debug!("relay completed for stream {}", stream_id);
            break;
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("SOCKS5 error: {0}")]
    Socks5Error(#[from] fast_socks5::SocksError),
    #[error("no target address in request")]
    NoTarget,
    #[error("no command in request")]
    NoCommand,
    #[error("unsupported SOCKS5 command")]
    UnsupportedCommand,
    #[error("connection failed: {0}")]
    ConnectFailed(Box<dyn std::error::Error + Send + Sync>),
    #[error("relay error: {0}")]
    RelayError(Box<dyn std::error::Error + Send + Sync>),
}
