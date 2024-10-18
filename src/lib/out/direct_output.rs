use std::net::SocketAddr;

use super::output::Output;

pub struct DirectOutput {}

impl DirectOutput {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DirectOutput {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Output for DirectOutput {
    async fn connect(
        &self,
        address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let stream = tokio::net::TcpStream::connect(address).await?;

        stream.set_nodelay(true)?;

        let (read_stream, write_stream) = stream.into_split();

        Ok((Box::new(read_stream), Box::new(write_stream)))
    }
}
