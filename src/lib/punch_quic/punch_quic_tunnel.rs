use std::{net::SocketAddr, sync::Arc};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use crate::tunnel::{InTunnel, OutTunnel, TransportType, TunnelId};

pub struct PunchQuicInTunnel {
    id: TunnelId,
    labels: Vec<String>,
    priority: i64,
    conn: quinn::Connection,
}

impl PunchQuicInTunnel {
    pub fn new(
        id: TunnelId,
        mut labels: Vec<String>,
        priority: i64,
        conn: quinn::Connection,
    ) -> Self {
        labels.push(id.to_string());

        PunchQuicInTunnel {
            id,
            labels,
            priority,
            conn,
        }
    }
}

#[async_trait::async_trait]
impl InTunnel for PunchQuicInTunnel {
    fn id(&self) -> TunnelId {
        self.id
    }

    fn labels(&self) -> &[String] {
        &self.labels
    }

    fn priority(&self) -> i64 {
        self.priority
    }

    fn get_remote(&self, address: SocketAddr, name: Option<String>) -> (String, u16) {
        (
            name.unwrap_or_else(|| address.ip().to_string()),
            address.port(),
        )
    }

    async fn connect(
        &self,
        r#type: TransportType,
        remote_hostname: String,
        remote_port: u16,
    ) -> anyhow::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        let (mut send_stream, recv_stream) = self.conn.open_bi().await?;

        let head_buf = {
            let mut buf = Vec::new();

            buf.push(match r#type {
                TransportType::Udp => 0b0000_0000,
                TransportType::Tcp => 0b0000_0001,
            });

            let remote_hostname = remote_hostname.as_bytes();

            let remote_hostname_length = remote_hostname.len();

            assert!(remote_hostname_length <= u8::MAX as usize);

            buf.push(remote_hostname_length as u8);
            buf.extend_from_slice(remote_hostname);
            buf.extend_from_slice(&remote_port.to_be_bytes());

            buf
        };

        send_stream.write_all(&head_buf).await?;

        Ok((Box::new(recv_stream), Box::new(send_stream)))
    }

    async fn closed(&self) {
        self.conn.closed().await;
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
    fn id(&self) -> TunnelId {
        self.id
    }

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        TransportType,
        (String, u16),
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

        let (r#type, remote_hostname, remote_port) = {
            let type_byte = recv_stream.read_u8().await?;

            let remote_hostname_length = recv_stream.read_u8().await? as usize;
            let remote_hostname = {
                let mut buf = vec![0; remote_hostname_length];

                recv_stream.read_exact(&mut buf).await?;

                String::from_utf8(buf)?
            };
            let remote_port = recv_stream.read_u16().await?;

            (
                match type_byte & 0b0000_0001 {
                    0 => TransportType::Udp,
                    _ => TransportType::Tcp,
                },
                remote_hostname,
                remote_port,
            )
        };

        Ok((
            r#type,
            (remote_hostname, remote_port),
            (Box::new(recv_stream), Box::new(send_stream)),
        ))
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }
}
