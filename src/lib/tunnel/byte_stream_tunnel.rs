use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::match_server::MatchOutId;

use super::{InTunnel, InTunnelLike, OutTunnel, TunnelId};

#[async_trait::async_trait]
pub trait ByteStreamInTunnelConnection: Send + Sync {
    async fn open(
        &self,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )>;

    async fn closed(&self);

    fn is_closed(&self) -> bool;

    fn handle_permit(&self, permit: tokio::sync::OwnedSemaphorePermit);
}

pub struct ByteStreamInTunnel<TConnection> {
    id: TunnelId,
    out_id: MatchOutId,
    labels: Vec<String>,
    priority: i64,
    connection: TConnection,
}

impl<TConnection> ByteStreamInTunnel<TConnection>
where
    TConnection: ByteStreamInTunnelConnection,
{
    pub fn new(
        id: TunnelId,
        out_id: MatchOutId,
        labels: Vec<String>,
        priority: i64,
        connection: TConnection,
    ) -> Self {
        ByteStreamInTunnel {
            id,
            out_id,
            labels,
            priority,
            connection,
        }
    }
}

impl<TConnection> fmt::Display for ByteStreamInTunnel<TConnection> {
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
impl<TConnection> InTunnelLike for ByteStreamInTunnel<TConnection>
where
    TConnection: ByteStreamInTunnelConnection,
{
    async fn connect(
        &self,
        destination_address: SocketAddr,
        destination_name: Option<String>,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let (read_stream, mut write_stream) = self.connection.open().await?;

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

        write_stream.write_all(&head).await?;

        Ok((read_stream, write_stream))
    }
}

#[async_trait::async_trait]
impl<TConnection> InTunnel for ByteStreamInTunnel<TConnection>
where
    TConnection: ByteStreamInTunnelConnection,
{
    fn id(&self) -> TunnelId {
        self.id
    }

    fn out_id(&self) -> MatchOutId {
        self.out_id
    }

    fn labels(&self) -> &[String] {
        &self.labels
    }

    fn priority(&self) -> i64 {
        self.priority
    }

    async fn closed(&self) {
        self.connection.closed().await;
    }

    fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    fn handle_permit(&self, permit: tokio::sync::OwnedSemaphorePermit) {
        self.connection.handle_permit(permit);
    }
}

#[async_trait::async_trait]
pub trait ByteStreamOutTunnelConnection: Send + Sync {
    async fn accept(
        &self,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )>;

    fn is_closed(&self) -> bool;
}

pub struct ByteStreamOutTunnel<TConnection> {
    id: TunnelId,
    connection: TConnection,
}

impl<TConnection> ByteStreamOutTunnel<TConnection> {
    pub fn new(id: TunnelId, connection: TConnection) -> Self {
        ByteStreamOutTunnel { id, connection }
    }
}

#[async_trait::async_trait]
impl<TConnection> OutTunnel for ByteStreamOutTunnel<TConnection>
where
    TConnection: ByteStreamOutTunnelConnection,
{
    fn id(&self) -> TunnelId {
        self.id
    }

    async fn accept(
        &self,
    ) -> anyhow::Result<(
        (SocketAddr, Option<String>),
        (
            Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        ),
    )> {
        let (mut read_stream, write_stream) = self.connection.accept().await?;

        let destination_tuple = {
            let option_byte = read_stream.read_u8().await?;

            let destination_address = match option_byte & 0b_1000_0000 {
                0 => SocketAddr::V4(SocketAddrV4::new(
                    read_stream.read_u32().await?.into(),
                    read_stream.read_u16().await?,
                )),
                _ => SocketAddr::V6(SocketAddrV6::new(
                    read_stream.read_u128().await?.into(),
                    read_stream.read_u16().await?,
                    0,
                    0,
                )),
            };

            let destination_name_length = read_stream.read_u8().await? as usize;
            let destination_name = if destination_name_length == 0 {
                None
            } else {
                let mut buffer = vec![0; destination_name_length];

                read_stream.read_exact(&mut buffer).await?;

                Some(String::from_utf8(buffer)?)
            };

            (destination_address, destination_name)
        };

        Ok((destination_tuple, (read_stream, write_stream)))
    }

    fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }
}
