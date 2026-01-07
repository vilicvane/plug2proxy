use std::net::SocketAddr;

use bytes::Bytes;
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
