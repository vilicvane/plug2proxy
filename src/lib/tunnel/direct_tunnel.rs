use std::{fmt, net::SocketAddr};

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
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let socket = match destination_address {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }?;

        socket.set_nodelay(true)?;

        nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &self.traffic_mark)?;

        let stream = socket.connect(destination_address).await?;

        let (read_stream, write_stream) = stream.into_split();

        Ok((Box::new(read_stream), Box::new(write_stream)))
    }
}

impl fmt::Display for DirectInTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DIRECT")
    }
}
