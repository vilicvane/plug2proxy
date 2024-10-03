use std::net::SocketAddr;

use crate::tunnel::{InTunnel, TransportType, TunnelId};

pub struct DirectInTunnel {}

impl DirectInTunnel {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl InTunnel for DirectInTunnel {
    fn id(&self) -> TunnelId {
        unimplemented!()
    }

    fn labels(&self) -> &[String] {
        unimplemented!()
    }

    fn priority(&self) -> i64 {
        unimplemented!()
    }

    async fn connect(
        &self,
        r#type: TransportType,
        remote_address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        match r#type {
            TransportType::Udp => {
                unimplemented!()
            }
            TransportType::Tcp => {
                let stream = tokio::net::TcpStream::connect(remote_address).await?;

                let (read, write) = stream.into_split();

                Ok((Box::new(read), Box::new(write)))
            }
        }
    }

    async fn closed(&self) {
        unimplemented!()
    }

    fn is_closed(&self) -> bool {
        unimplemented!()
    }
}
