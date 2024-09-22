use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use webrtc::util::{Conn, Result};

pub struct PeerSocket {
    socket: tokio::net::UdpSocket,
    remote_addr: Mutex<Option<SocketAddr>>,
}

impl PeerSocket {
    pub fn new(socket: tokio::net::UdpSocket) -> Self {
        Self {
            socket,
            remote_addr: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl Conn for PeerSocket {
    async fn connect(&self, addr: SocketAddr) -> Result<()> {
        self.remote_addr.lock().unwrap().replace(addr);

        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.socket.recv(buf).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        let remote_addr = self
            .remote_addr
            .lock()
            .unwrap()
            .expect("connect to an address before send.")
            .clone();

        Ok(self.socket.send_to(buf, remote_addr).await?)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr.lock().unwrap().clone()
    }

    async fn close(&self) -> Result<()> {
        Ok(self.socket.close().await?)
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
