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

    fn get_remote(&self, address: SocketAddr, _name: Option<String>) -> (String, u16) {
        (address.ip().to_string(), address.port())
    }

    async fn connect(
        &self,
        r#type: TransportType,
        remote_hostname: String,
        remote_port: u16,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        match r#type {
            TransportType::Udp => {
                unimplemented!()
            }
            TransportType::Tcp => {
                let stream =
                    tokio::net::TcpStream::connect(format!("{remote_hostname}:{remote_port}"))
                        .await?;

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
