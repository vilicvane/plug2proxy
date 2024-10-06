use std::{fmt, net::SocketAddr};

use crate::tunnel::{InTunnel, TunnelId};

pub struct DirectInTunnel {
    traffic_mark: u32,
}

impl DirectInTunnel {
    pub fn new(traffic_mark: u32) -> Self {
        Self { traffic_mark }
    }
}

impl fmt::Display for DirectInTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DIRECT")
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
        destination_address: SocketAddr,
        _destination_name: Option<String>,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
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

    async fn closed(&self) {
        unimplemented!()
    }

    fn is_closed(&self) -> bool {
        unimplemented!()
    }
}
