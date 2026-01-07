use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::{ConnectionError, ConnectionReceiver, ConnectionSender, FramedConnection};

/// A transport that multiplexes datagrams over multiple TCP connections.
///
/// This provides QUIC-like parallelism by distributing datagrams across
/// multiple TCP connections, avoiding head-of-line blocking.
pub struct Transport {
    /// Channel for sending datagrams
    send_tx: mpsc::Sender<Bytes>,
    /// Channel for receiving datagrams
    recv_rx: mpsc::Receiver<Bytes>,
    /// Handle to the transport task
    _handle: Arc<TransportHandle>,
}

struct TransportHandle {
    /// Shutdown signal
    shutdown_tx: mpsc::Sender<()>,
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        // Signal shutdown when the handle is dropped
        let _ = self.shutdown_tx.try_send(());
    }
}

impl Transport {
    /// Create a new transport from multiple TCP connections.
    ///
    /// The connections will be used in parallel to send and receive datagrams.
    /// Datagrams are distributed across connections using round-robin.
    pub fn new(connections: Vec<TcpStream>) -> Self {
        Self::with_buffer_size(connections, 256)
    }

    /// Create a new transport with a custom buffer size.
    pub fn with_buffer_size(connections: Vec<TcpStream>, buffer_size: usize) -> Self {
        let (send_tx, send_rx) = mpsc::channel(buffer_size);
        let (recv_tx, recv_rx) = mpsc::channel(buffer_size);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let handle = Arc::new(TransportHandle { shutdown_tx });

        // Split connections into senders and receivers
        let mut senders = Vec::with_capacity(connections.len());
        let mut receivers = Vec::with_capacity(connections.len());

        for stream in connections {
            let conn = FramedConnection::new(stream);
            let (sender, receiver) = conn.split();
            senders.push(sender);
            receivers.push(receiver);
        }

        // Spawn the send task
        tokio::spawn(send_task(senders, send_rx, shutdown_rx));

        // Spawn receive tasks for each connection
        for receiver in receivers {
            let recv_tx = recv_tx.clone();
            tokio::spawn(recv_task(receiver, recv_tx));
        }

        Self {
            send_tx,
            recv_rx,
            _handle: handle,
        }
    }

    /// Send a datagram through the transport.
    pub async fn send(&self, data: Bytes) -> Result<(), TransportError> {
        self.send_tx
            .send(data)
            .await
            .map_err(|_| TransportError::Closed)?;
        Ok(())
    }

    /// Receive the next datagram from the transport.
    /// Returns `None` if all connections are closed.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.recv_rx.recv().await
    }
}

/// Task that distributes outgoing datagrams across multiple connections.
async fn send_task(
    mut senders: Vec<ConnectionSender>,
    mut recv: mpsc::Receiver<Bytes>,
    mut shutdown: mpsc::Receiver<()>,
) {
    let mut index = 0;
    let count = senders.len();

    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                tracing::debug!("transport send task shutting down");
                break;
            }

            data = recv.recv() => {
                let Some(data) = data else {
                    break;
                };

                // Round-robin distribution across connections
                let sender = &mut senders[index];
                index = (index + 1) % count;

                if let Err(e) = sender.send(data).await {
                    tracing::warn!("failed to send datagram: {}", e);
                    // Continue with other connections even if one fails
                }
            }
        }
    }
}

/// Task that receives datagrams from a single connection.
async fn recv_task(mut receiver: ConnectionReceiver, send: mpsc::Sender<Bytes>) {
    loop {
        match receiver.recv().await {
            Ok(Some(data)) => {
                if send.send(data).await.is_err() {
                    // Receiver dropped, stop
                    break;
                }
            }
            Ok(None) => {
                // Connection closed
                tracing::debug!("connection closed");
                break;
            }
            Err(e) => {
                tracing::warn!("failed to receive datagram: {}", e);
                break;
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    #[error("transport closed")]
    Closed,
}
