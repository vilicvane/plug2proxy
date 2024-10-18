use std::net::SocketAddr;

use super::output::Output;

pub struct Socks5Output {
    proxy_address: SocketAddr,
}

impl Socks5Output {
    pub fn new(proxy_address: SocketAddr) -> Self {
        Self { proxy_address }
    }
}

#[async_trait::async_trait]
impl Output for Socks5Output {
    async fn connect(
        &self,
        address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let stream = tokio_socks::tcp::Socks5Stream::connect(self.proxy_address, address).await?;

        stream.set_nodelay(true)?;

        let (read_stream, write_stream) = tokio::io::split(stream);

        Ok((Box::new(read_stream), Box::new(write_stream)))
    }
}
