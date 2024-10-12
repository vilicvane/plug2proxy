use tokio::io::{AsyncRead, AsyncWrite};

use crate::tunnel::byte_stream_tunnel::{
    ByteStreamInTunnelConnection, ByteStreamOutTunnelConnection,
};

pub struct PunchQuicInTunnelConnection {
    connection: quinn::Connection,
}

impl PunchQuicInTunnelConnection {
    pub fn new(connection: quinn::Connection) -> Self {
        PunchQuicInTunnelConnection { connection }
    }
}

#[async_trait::async_trait]
impl ByteStreamInTunnelConnection for PunchQuicInTunnelConnection {
    async fn open(
        &self,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let (send_stream, recv_stream) = self.connection.open_bi().await?;

        Ok((Box::new(recv_stream), Box::new(send_stream)))
    }

    async fn closed(&self) {
        self.connection.closed().await;
    }

    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}

pub struct PunchQuicOutTunnelConnection {
    connection: quinn::Connection,
}

impl PunchQuicOutTunnelConnection {
    pub fn new(connection: quinn::Connection) -> Self {
        PunchQuicOutTunnelConnection { connection }
    }
}

#[async_trait::async_trait]
impl ByteStreamOutTunnelConnection for PunchQuicOutTunnelConnection {
    async fn accept(
        &self,
    ) -> anyhow::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )> {
        let (write_stream, read_stream) = {
            loop {
                match self.connection.accept_bi().await {
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

        Ok((Box::new(read_stream), Box::new(write_stream)))
    }

    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
}
