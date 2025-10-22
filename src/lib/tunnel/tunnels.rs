use std::{fmt, net::SocketAddr, sync::Arc};

use super::{InTunnel, InTunnelLike};

#[derive(derive_more::From)]
pub enum AnyInTunnelLikeArc {
    InTunnel(Arc<Box<dyn InTunnel>>),
    InTunnelLike(Arc<Box<dyn InTunnelLike>>),
}

impl fmt::Display for AnyInTunnelLikeArc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnyInTunnelLikeArc::InTunnel(tunnel) => tunnel.fmt(formatter),
            AnyInTunnelLikeArc::InTunnelLike(tunnel) => tunnel.fmt(formatter),
        }
    }
}

#[async_trait::async_trait]
impl InTunnelLike for AnyInTunnelLikeArc {
    async fn connect(
        &self,
        destination_address: SocketAddr,
        destination_name: Option<String>,
        tag: Option<String>,
        sniff_buffer: Option<Vec<u8>>,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        match self {
            AnyInTunnelLikeArc::InTunnel(tunnel) => {
                tunnel
                    .connect(destination_address, destination_name, tag, sniff_buffer)
                    .await
            }
            AnyInTunnelLikeArc::InTunnelLike(tunnel) => {
                tunnel
                    .connect(destination_address, destination_name, tag, sniff_buffer)
                    .await
            }
        }
    }
}
