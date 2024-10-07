use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use crate::tunnel::{InTunnel, OutTunnel, TunnelId};

pub struct PunchQuicInTunnel {
    id: TunnelId,
    labels: Vec<String>,
    priority: i64,
    connection: quinn::Connection,
}

impl PunchQuicInTunnel {
    pub fn new(
        id: TunnelId,
        labels: Vec<String>,
        priority: i64,
        connection: quinn::Connection,
    ) -> Self {
        PunchQuicInTunnel {
            id,
            labels,
            priority,
            connection,
        }
    }
}

impl fmt::Display for PunchQuicInTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.id.to_string();
        let id_short = id.split('-').next().unwrap();

        if self.labels.is_empty() {
            write!(formatter, "{id_short}",)
        } else {
            write!(formatter, "{id_short} ({})", self.labels.join(","))
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

    async fn connect(
        &self,
        destination_address: SocketAddr,
        destination_name: Option<String>,
    ) -> anyhow::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        let (mut send_stream, recv_stream) = self.connection.open_bi().await?;

        let head = {
            let mut head = Vec::<u8>::new();

            match destination_address {
                SocketAddr::V4(address) => {
                    head.push(0b_0000_0000);
                    head.extend_from_slice(&address.ip().octets());
                }
                SocketAddr::V6(address) => {
                    head.push(0b_1000_0000);
                    head.extend_from_slice(&address.ip().octets());
                }
            }

            head.extend_from_slice(&destination_address.port().to_be_bytes());

            let destination_name = destination_name.unwrap_or_else(|| "".to_owned());

            let destination_name_length: u8 = destination_name.len().try_into()?;

            head.push(destination_name_length);
            head.extend_from_slice(destination_name.as_bytes());

            head
        };

        send_stream.write_all(&head).await?;

        Ok((Box::new(recv_stream), Box::new(send_stream)))
    }

    async fn closed(&self) {
        self.connection.closed().await;
    }

    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
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
        (SocketAddr, Option<String>),
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
                                return Err(anyhow::anyhow!("quic connection closed."));
                            }

                            continue;
                        }
                        _ => return Err(error.into()),
                    },
                }
            }
        };

        let destination_tuple = {
            let option_byte = recv_stream.read_u8().await?;

            let destination_address = match option_byte & 0b_1000_0000 {
                0 => SocketAddr::V4(SocketAddrV4::new(
                    recv_stream.read_u32().await?.into(),
                    recv_stream.read_u16().await?,
                )),
                _ => SocketAddr::V6(SocketAddrV6::new(
                    recv_stream.read_u128().await?.into(),
                    recv_stream.read_u16().await?,
                    0,
                    0,
                )),
            };

            let destination_name_length = recv_stream.read_u8().await? as usize;
            let destination_name = if destination_name_length == 0 {
                None
            } else {
                let mut buffer = vec![0; destination_name_length];

                recv_stream.read_exact(&mut buffer).await?;

                Some(String::from_utf8(buffer)?)
            };

            (destination_address, destination_name)
        };

        Ok((
            destination_tuple,
            (Box::new(recv_stream), Box::new(send_stream)),
        ))
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }
}
