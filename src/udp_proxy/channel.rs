use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;

/// A datagram with source and destination addressing information.
///
/// This is the unit of data that flows through the proxy, carrying enough
/// information to properly route responses back to the original sender.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// The original source address (client for requests, server for responses).
    pub source: SocketAddr,
    /// The destination address (server for requests, client for responses).
    pub dest: SocketAddr,
    /// The datagram payload.
    pub data: Bytes,
}

impl Datagram {
    pub fn new(source: SocketAddr, dest: SocketAddr, data: impl Into<Bytes>) -> Self {
        Self {
            source,
            dest,
            data: data.into(),
        }
    }

    /// Serialize datagram for transport over a tunnel.
    /// Format: TYPE(1) SOURCE_ADDR(var) TYPE(1) DEST_ADDR(var) LEN(4) DATA(var)
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Serialize source address
        match self.source {
            SocketAddr::V4(addr) => {
                buf.put_u8(4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
        }

        // Serialize dest address
        match self.dest {
            SocketAddr::V4(addr) => {
                buf.put_u8(4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                buf.put_u8(6);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
        }

        // Serialize payload length and data
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);

        buf.freeze()
    }

    /// Deserialize datagram from bytes received from tunnel.
    pub fn deserialize(mut data: Bytes) -> Result<Self, DatagramError> {
        if data.remaining() < 8 {
            // Minimum: 1 + 4 + 2 + 1 + 4 + 2 + 4 = 18, but check progressive
            return Err(DatagramError::TooShort);
        }

        // Deserialize source address
        let source = if data.get_u8() == 4 {
            if data.remaining() < 6 {
                // 4 bytes IP + 2 bytes port
                return Err(DatagramError::TooShort);
            }
            let mut octets = [0u8; 4];
            data.copy_to_slice(&mut octets);
            let port = data.get_u16();
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
        } else {
            if data.remaining() < 18 {
                // 16 bytes IP + 2 bytes port
                return Err(DatagramError::TooShort);
            }
            let mut octets = [0u8; 16];
            data.copy_to_slice(&mut octets);
            let port = data.get_u16();
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        };

        // Deserialize dest address
        let dest = if data.get_u8() == 4 {
            if data.remaining() < 6 {
                return Err(DatagramError::TooShort);
            }
            let mut octets = [0u8; 4];
            data.copy_to_slice(&mut octets);
            let port = data.get_u16();
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
        } else {
            if data.remaining() < 18 {
                return Err(DatagramError::TooShort);
            }
            let mut octets = [0u8; 16];
            data.copy_to_slice(&mut octets);
            let port = data.get_u16();
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        };

        // Deserialize payload
        if data.remaining() < 4 {
            return Err(DatagramError::TooShort);
        }
        let len = data.get_u32() as usize;
        if data.remaining() < len {
            return Err(DatagramError::TooShort);
        }
        let payload = data.split_to(len);

        Ok(Datagram::new(source, dest, payload))
    }
}

/// The sending half of a datagram channel.
///
/// Used by the inbound side to send datagrams toward the outbound side.
#[derive(Clone)]
pub struct ChannelSender {
    tx: mpsc::Sender<Datagram>,
}

impl ChannelSender {
    /// Send a datagram through the channel.
    pub async fn send(&self, datagram: Datagram) -> Result<(), ChannelError> {
        self.tx
            .send(datagram)
            .await
            .map_err(|_| ChannelError::Closed)
    }

    /// Try to send a datagram without waiting.
    pub fn try_send(&self, datagram: Datagram) -> Result<(), ChannelError> {
        self.tx.try_send(datagram).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => ChannelError::Full,
            mpsc::error::TrySendError::Closed(_) => ChannelError::Closed,
        })
    }
}

/// The receiving half of a datagram channel.
///
/// Used by the outbound side to receive datagrams from the inbound side.
pub struct ChannelReceiver {
    rx: mpsc::Receiver<Datagram>,
}

impl ChannelReceiver {
    /// Receive the next datagram from the channel.
    ///
    /// Returns `None` if all senders have been dropped.
    pub async fn recv(&mut self) -> Option<Datagram> {
        self.rx.recv().await
    }
}

/// Create a new datagram channel with the specified capacity.
///
/// Returns a sender and receiver pair for unidirectional communication.
pub fn channel(capacity: usize) -> (ChannelSender, ChannelReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    (ChannelSender { tx }, ChannelReceiver { rx })
}

/// Create a bidirectional channel pair for linking inbound and outbound sides.
///
/// Returns:
/// - `(inbound_tx, inbound_rx)`: For the inbound side to send requests and receive responses.
/// - `(outbound_tx, outbound_rx)`: For the outbound side to receive requests and send responses.
pub fn channel_pair(capacity: usize) -> (ChannelPair, ChannelPair) {
    let (request_tx, request_rx) = channel(capacity);
    let (response_tx, response_rx) = channel(capacity);

    let inbound_pair = ChannelPair {
        tx: request_tx,
        rx: response_rx,
    };

    let outbound_pair = ChannelPair {
        tx: response_tx,
        rx: request_rx,
    };

    (inbound_pair, outbound_pair)
}

/// A bidirectional channel pair (one sender, one receiver).
///
/// Used to connect inbound and outbound components.
pub struct ChannelPair {
    pub tx: ChannelSender,
    pub rx: ChannelReceiver,
}

impl ChannelPair {
    /// Split into separate sender and receiver.
    pub fn split(self) -> (ChannelSender, ChannelReceiver) {
        (self.tx, self.rx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel closed")]
    Closed,
    #[error("channel full")]
    Full,
}

#[derive(Debug, thiserror::Error)]
pub enum DatagramError {
    #[error("datagram data too short")]
    TooShort,
}
