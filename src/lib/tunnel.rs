use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait::async_trait]
pub trait ServerTunnel {
    async fn accept(
        &self,
    ) -> anyhow::Result<(
        TransportType,
        SocketAddr,
        (Box<dyn AsyncWrite + Unpin>, Box<dyn AsyncRead + Unpin>),
    )>;
}

#[async_trait::async_trait]
pub trait ClientTunnel {
    async fn connect(
        &self,
        typ: TransportType,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<(Box<dyn AsyncWrite + Unpin>, Box<dyn AsyncRead + Unpin>)>;
}

#[derive(Debug)]
pub enum TransportType {
    Udp,
    Tcp,
}
