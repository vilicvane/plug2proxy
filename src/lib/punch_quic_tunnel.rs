use std::net::SocketAddr;

use crate::tunnel::{ClientTunnel, ServerTunnel, Stream, TransportType};

pub struct PunchQuicServerTunnel {
    conn: quinn::Connection,
}

impl PunchQuicServerTunnel {
    pub fn new(conn: quinn::Connection) -> Self {
        PunchQuicServerTunnel { conn }
    }
}

#[async_trait::async_trait]
impl ServerTunnel for PunchQuicServerTunnel {
    async fn accept(&self) -> anyhow::Result<(TransportType, SocketAddr, Box<dyn Stream>)> {
        let (send_stream, mut recv_stream) = self.conn.accept_bi().await?;

        let (typ, remote_addr) = {
            let head_buf = &mut [0u8; 1];

            recv_stream.read_exact(head_buf).await?;

            (
                match head_buf[0] & 0b0000_0001 {
                    0 => TransportType::Udp,
                    _ => TransportType::Tcp,
                },
                match head_buf[0] & 0b0000_0010 {
                    0 => {
                        let mut ip_buf = [0u8; 4];
                        let mut port_buf = [0u8; 2];

                        recv_stream.read_exact(&mut ip_buf).await?;
                        recv_stream.read_exact(&mut port_buf).await?;

                        let ip = std::net::Ipv4Addr::from(ip_buf);
                        let port = u16::from_be_bytes(port_buf);

                        SocketAddr::new(ip.into(), port)
                    }
                    _ => {
                        let mut ip_buf = [0u8; 16];
                        let mut port_buf = [0u8; 2];

                        recv_stream.read_exact(&mut ip_buf).await?;
                        recv_stream.read_exact(&mut port_buf).await?;

                        let ip = std::net::Ipv6Addr::from(ip_buf);
                        let port = u16::from_be_bytes(port_buf);

                        SocketAddr::new(ip.into(), port)
                    }
                },
            )
        };

        Ok((
            typ,
            remote_addr,
            Box::new(QuinnStream {
                send_stream,
                recv_stream,
            }),
        ))
    }
}

pub struct PunchQuicClientTunnel {
    conn: quinn::Connection,
}

impl PunchQuicClientTunnel {
    pub fn new(conn: quinn::Connection) -> Self {
        PunchQuicClientTunnel { conn }
    }
}

#[async_trait::async_trait]
impl ClientTunnel for PunchQuicClientTunnel {
    async fn connect(
        &self,
        typ: TransportType,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<Box<dyn Stream>> {
        let (mut send_stream, recv_stream) = self.conn.open_bi().await?;

        let head_buf = {
            let mut buf = Vec::new();

            let type_bit = match typ {
                TransportType::Udp => 0b0000_0000,
                TransportType::Tcp => 0b0000_0001,
            };

            match remote_addr {
                SocketAddr::V4(addr) => {
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

        Ok(Box::new(QuinnStream {
            send_stream,
            recv_stream,
        }))
    }
}

struct QuinnStream {
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
}

#[async_trait::async_trait]
impl Stream for QuinnStream {
    async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<Option<usize>> {
        Ok(self.recv_stream.read(buf).await?)
    }

    async fn write_all(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        Ok(self.send_stream.write_all(buf).await?)
    }
}
