use std::{fmt, net::SocketAddr};

use tokio::io::AsyncWriteExt;

use crate::utils::net::socket::set_keepalive_options;

use super::InTunnelLike;

pub struct DirectInTunnel {
    traffic_mark: u32,
}

impl DirectInTunnel {
    pub fn new(traffic_mark: u32) -> Self {
        Self { traffic_mark }
    }
}

#[async_trait::async_trait]
impl InTunnelLike for DirectInTunnel {
    async fn connect(
        &self,
        destination_address: SocketAddr,
        _destination_name: Option<String>,
        _tag: Option<String>,
        sniff_buffer: Option<Vec<u8>>,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        let socket = match destination_address {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }?;

        socket.set_nodelay(true)?;
        socket.set_keepalive(true)?;

        set_keepalive_options(&socket, 60, 10, 5)?;

        nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &self.traffic_mark)?;

        let mut stream = socket.connect(destination_address).await?;

        if let Some(sniff_buffer) = sniff_buffer {
            stream.write_all(&sniff_buffer).await?;
        }

        let (read_stream, write_stream) = stream.into_split();

        let (stream_closed_sender, _) = tokio::sync::oneshot::channel();

        Ok((
            Box::new(read_stream),
            Box::new(write_stream),
            stream_closed_sender,
        ))
    }
}

impl fmt::Display for DirectInTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DIRECT")
    }
}
