mod fake_authority;
mod notes;
mod peer_socket;
mod tproxy_socket;

use std::{
    cell::RefCell,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use fake_authority::FakeAuthority;
use peer_socket::PeerSocket;
use stun::message::Getter as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use webrtc::util::Conn;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let (peer_1, peer_1_address) = create_peer_socket().await?;
    let (peer_2, peer_2_address) = create_peer_socket().await?;

    peer_1.send_to(&[], peer_1_address).await?;
    peer_1.send_to(&[], peer_2_address).await?;
    peer_2.send_to(&[], peer_2_address).await?;
    peer_2.send_to(&[], peer_1_address).await?;

    tokio::spawn({
        let peer_1 = peer_1.clone();

        async move {
            let mut buffer = [0u8; 1024];

            loop {
                println!("receiving...");

                let (length, address) = peer_1.recv_from(&mut buffer).await?;

                println!(
                    "received {} bytes from {}: {:?}",
                    length,
                    address,
                    &buffer[..length]
                );
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    });

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        println!("sending messages...");

        peer_1.send("world 1".as_bytes()).await?;

        peer_2
            .send_to(
                "world local 2".as_bytes(),
                format!("127.0.0.1:{}", peer_1_address.port()).parse()?,
            )
            .await?;
        peer_2.send("world 2".as_bytes()).await?;
    }

    // stun_client.close().await?;

    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn create_peer_socket() -> anyhow::Result<(Arc<PeerSocket>, SocketAddr)> {
    let stun_server_address = "74.125.250.129:19302";
    // let stun_server_address = "stun.l.google.com:19302";

    let socket = Arc::new(PeerSocket::new(tokio::net::UdpSocket::bind("0:0").await?));

    println!("peer local address: {:?}", socket.local_addr()?);

    socket.connect(stun_server_address.parse()?).await?;

    // let local_address = socket.local_addr()?;

    // Ok((socket, address))

    let mut stun_client = stun::client::ClientBuilder::new()
        .with_conn(socket.clone())
        .build()?;

    let mut message = stun::message::Message::new();

    message.build(&[
        Box::new(stun::agent::TransactionId::new()),
        Box::new(stun::message::BINDING_REQUEST),
    ])?;

    let (response_sender, mut response_receiver) = tokio::sync::mpsc::unbounded_channel();

    stun_client
        .send(&message, Some(Arc::new(response_sender)))
        .await?;

    let address = {
        let body = response_receiver.recv().await.unwrap().event_body?;

        let mut xor_addr = stun::xoraddr::XorMappedAddress::default();

        xor_addr.get_from(&body)?;

        SocketAddr::new(xor_addr.ip, xor_addr.port)
    };

    println!("peer address: {:?}", address);

    stun_client.close().await?;

    Ok((socket, address))
}

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
