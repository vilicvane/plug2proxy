use std::net::SocketAddr;

use super::{direct_output::DirectOutput, socks5_output::Socks5Output};

#[async_trait::async_trait]
pub trait Output {
    async fn connect(
        &self,
        address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )>;
}

#[derive(derive_more::From)]
pub enum AnyOutput {
    Direct(DirectOutput),
    Socks5(Socks5Output),
}

#[async_trait::async_trait]
impl Output for AnyOutput {
    async fn connect(
        &self,
        address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        match self {
            AnyOutput::Direct(output) => output.connect(address).await,
            AnyOutput::Socks5(output) => output.connect(address).await,
        }
    }
}
