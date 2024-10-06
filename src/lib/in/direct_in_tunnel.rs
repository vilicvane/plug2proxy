use std::net::SocketAddr;

use crate::tunnel::{InTunnel, TransportType, TunnelId};

pub struct DirectInTunnel {
    traffic_mark: u32,
}

impl DirectInTunnel {
    pub fn new(traffic_mark: u32) -> Self {
        Self { traffic_mark }
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
        _destination_hostname: String,
        destination_address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        match r#type {
            TransportType::Udp => {
                unimplemented!()
            }
            TransportType::Tcp => {
                let stream = match destination_address {
                    SocketAddr::V4(_) => {
                        let socket = tokio::net::TcpSocket::new_v4()?;

                        nix::sys::socket::setsockopt(
                            &socket,
                            nix::sys::socket::sockopt::Mark,
                            &self.traffic_mark,
                        )?;

                        socket.connect(destination_address).await?
                    }
                    SocketAddr::V6(_) => {
                        let socket = tokio::net::TcpSocket::new_v6()?;

                        nix::sys::socket::setsockopt(
                            &socket,
                            nix::sys::socket::sockopt::Mark,
                            &self.traffic_mark,
                        )?;

                        socket.connect(destination_address).await?
                    }
                };

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
