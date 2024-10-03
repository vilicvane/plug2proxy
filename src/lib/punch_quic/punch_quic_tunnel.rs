use std::{net::SocketAddr, sync::Arc};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use crate::tunnel::{InTunnel, OutTunnel, TransportType, TunnelId};

pub struct PunchQuicInTunnel {
    id: TunnelId,
    labels: Vec<String>,
    conn: quinn::Connection,
}

impl PunchQuicInTunnel {
    pub fn new(id: TunnelId, labels: Vec<String>, conn: quinn::Connection) -> Self {
        PunchQuicInTunnel { id, labels, conn }
    }
}

#[async_trait::async_trait]
impl InTunnel for PunchQuicInTunnel {
    fn get_id(&self) -> TunnelId {
        self.id
    }

    async fn connect(
        &self,
        typ: TransportType,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        let (mut send_stream, recv_stream) = self.conn.open_bi().await?;

        let head_buf = {
            let mut buf = Vec::new();

            let type_bit = match typ {
                TransportType::Udp => 0b0000_0000,
                TransportType::Tcp => 0b0000_0001,
            };

            match remote_addr {
                SocketAddr::V4(addr) => {
                    #[allow(clippy::identity_op)]
                    buf.push(type_bit | 0b0000_0000);
                    buf.extend_from_slice(&addr.ip().octets());
                    buf.extend_from_slice(&addr.port().to_be_bytes());
                }
                SocketAddr::V6(addr) => {
                    buf.push(type_bit | 0b0000_0010);
                    buf.extend_from_slice(&addr.ip().octets());
                    buf.extend_from_slice(&addr.port().to_be_bytes());
                }
            };

            buf
        };

        send_stream.write_all(&head_buf).await?;

        Ok((Box::new(recv_stream), Box::new(send_stream)))
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }
}

pub struct PunchQuicOutTunnel {
    id: TunnelId,
    conn: Arc<quinn::Connection>,
}

impl PunchQuicOutTunnel {
    pub fn new(id: TunnelId, conn: Arc<quinn::Connection>) -> Self {
        PunchQuicOutTunnel { id, conn }
    }
}

#[async_trait::async_trait]
impl OutTunnel for PunchQuicOutTunnel {
    fn get_id(&self) -> TunnelId {
        self.id
    }

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        TransportType,
        SocketAddr,
        (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ),
    )> {
        let (send_stream, mut recv_stream) = {
            loop {
                match self.conn.accept_bi().await {
                    Ok(tuple) => break tuple,
                    Err(error) => match error {
                        quinn::ConnectionError::TimedOut => {
                            if self.is_closed() {
                                return Err(anyhow::anyhow!("connection closed."));
                            }

                            continue;
                        }
                        _ => return Err(error.into()),
                    },
                }
            }
        };

        let (typ, remote_addr) = {
            let head_byte = recv_stream.read_u8().await?;

            (
                match head_byte & 0b0000_0001 {
                    0 => TransportType::Udp,
                    _ => TransportType::Tcp,
                },
                match head_byte & 0b0000_0010 {
                    0 => {
                        let ip = std::net::Ipv4Addr::from(recv_stream.read_u32().await?);
                        let port = recv_stream.read_u16().await?;

                        SocketAddr::new(ip.into(), port)
                    }
                    _ => {
                        let ip = std::net::Ipv6Addr::from(recv_stream.read_u128().await?);
                        let port = recv_stream.read_u16().await?;

                        SocketAddr::new(ip.into(), port)
                    }
                },
            )
        };

        Ok((
            typ,
            remote_addr,
            (Box::new(recv_stream), Box::new(send_stream)),
        ))
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }
}
