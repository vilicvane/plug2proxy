use std::net::SocketAddr;

#[async_trait::async_trait]
pub trait ServerTunnel {
    async fn accept(&self) -> anyhow::Result<(TransportType, SocketAddr, Box<dyn Stream>)>;
}

#[async_trait::async_trait]
pub trait ClientTunnel {
    async fn connect(
        &self,
        typ: TransportType,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<Box<dyn Stream>>;
}

#[async_trait::async_trait]
pub trait Stream {
    async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<Option<usize>>;

    async fn write_all(&mut self, buf: &[u8]) -> anyhow::Result<()>;
}

pub enum TransportType {
    Udp,
    Tcp,
}
