use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use super::{FramedConnection, QuicConfig, QuicConnection, QuicError};

/// Handle for adding new TCP connections to an existing tunnel.
#[derive(Clone)]
pub struct TcpConnectionHandle {
    add_connection_tx: mpsc::Sender<TcpStream>,
}

impl TcpConnectionHandle {
    /// Add a new TCP connection to the tunnel.
    pub async fn add_connection(&self, stream: TcpStream) -> Result<(), TunnelError> {
        self.add_connection_tx
            .send(stream)
            .await
            .map_err(|_| TunnelError::ConnectionFailed)?;
        Ok(())
    }
}

/// A QUIC tunnel over multiple TCP connections.
///
/// This provides QUIC protocol features (encryption, streams, reliability)
/// over a TCP transport layer (multiple parallel connections).
pub struct Tunnel {
    quic: QuicConnection,
    /// Handle to the driver task
    driver_handle: tokio::task::JoinHandle<Result<(), QuicError>>,
    /// Handle for adding new TCP connections
    tcp_handle: TcpConnectionHandle,
}

impl Tunnel {
    /// Create a client tunnel connecting to a server.
    pub async fn connect(
        addr: SocketAddr,
        server_name: Option<&str>,
        connection_count: usize,
    ) -> Result<Self, TunnelError> {
        let config = QuicConfig::new_client()?;
        Self::connect_with_config(addr, server_name, connection_count, config.into_inner()).await
    }

    /// Create a client tunnel with custom QUIC config.
    ///
    /// Establishes a single TCP connection first, waits for QUIC handshake to succeed,
    /// then adds additional TCP connections in the background if `connection_count > 1`.
    pub async fn connect_with_config(
        addr: SocketAddr,
        server_name: Option<&str>,
        connection_count: usize,
        mut config: quiche::Config,
    ) -> Result<Self, TunnelError> {
        // Establish the first TCP connection
        let first_stream = TcpStream::connect(addr).await?;
        first_stream.set_nodelay(true)?;

        tracing::info!("established initial TCP connection to {}", addr);

        // Create tunnel with single connection first
        let tunnel =
            Self::from_tcp_streams_client(vec![first_stream], server_name, &mut config).await?;

        // If more connections are requested, add them in the background after handshake succeeds
        if connection_count > 1 {
            let tcp_handle = tunnel.tcp_handle.clone();
            let additional_count = connection_count - 1;

            tokio::spawn(async move {
                for i in 0..additional_count {
                    match TcpStream::connect(addr).await {
                        Ok(stream) => {
                            if let Err(e) = stream.set_nodelay(true) {
                                tracing::warn!(
                                    "failed to set nodelay on connection {}: {}",
                                    i + 2,
                                    e
                                );
                                continue;
                            }
                            if tcp_handle.add_connection(stream).await.is_err() {
                                tracing::warn!(
                                    "failed to add connection {}: channel closed",
                                    i + 2
                                );
                                break;
                            }
                            tracing::debug!("added TCP connection {} to tunnel", i + 2);
                        }
                        Err(e) => {
                            tracing::warn!("failed to establish TCP connection {}: {}", i + 2, e);
                        }
                    }
                }
                tracing::info!(
                    "finished extending tunnel with {} additional TCP connections",
                    additional_count
                );
            });
        }

        Ok(tunnel)
    }

    /// Create a client tunnel from existing TCP streams.
    pub async fn from_tcp_streams_client(
        tcp_streams: Vec<TcpStream>,
        server_name: Option<&str>,
        config: &mut quiche::Config,
    ) -> Result<Self, TunnelError> {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let (incoming_tx, incoming_rx) = mpsc::channel(256);

        // Split TCP streams and spawn IO tasks
        let tcp_handle = spawn_tcp_io_tasks(tcp_streams, outgoing_rx, incoming_tx);

        // Create QUIC connection
        let quic = QuicConnection::connect(server_name, config, outgoing_tx.clone(), incoming_rx)?;

        // Spawn driver task
        let quic_clone = quic.inner();
        let outgoing_tx_clone = outgoing_tx;
        let incoming_rx_clone = Arc::clone(&quic.incoming_rx);
        let next_stream_id_clone = Arc::clone(&quic.next_stream_id);
        let send_notify_clone = quic.send_notify();
        let recv_notify_clone = quic.recv_notify();
        let driver_handle = tokio::spawn(async move {
            let quic_ref = QuicConnection {
                inner: quic_clone,
                outgoing_tx: outgoing_tx_clone,
                incoming_rx: incoming_rx_clone,
                next_stream_id: next_stream_id_clone,
                send_notify: send_notify_clone,
                recv_notify: recv_notify_clone,
            };
            quic_ref.drive().await
        });

        // Wait for connection to be established
        let mut attempts = 0;
        while !quic.is_established().await {
            if quic.is_closed().await {
                return Err(TunnelError::ConnectionFailed);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            attempts += 1;
            if attempts > 500 {
                return Err(TunnelError::ConnectionTimeout);
            }
        }

        tracing::info!("QUIC connection established");

        Ok(Self {
            quic,
            driver_handle,
            tcp_handle,
        })
    }

    /// Create a server tunnel from existing TCP streams.
    pub async fn from_tcp_streams_server(
        tcp_streams: Vec<TcpStream>,
        config: &mut quiche::Config,
    ) -> Result<Self, TunnelError> {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let (incoming_tx, incoming_rx) = mpsc::channel(256);

        // Split TCP streams and spawn IO tasks
        let tcp_handle = spawn_tcp_io_tasks(tcp_streams, outgoing_rx, incoming_tx);

        // Wait for the first packet to get the client's connection ID
        let mut rx = incoming_rx;
        let first_packet = rx.recv().await.ok_or(TunnelError::ConnectionFailed)?;

        // Parse the header to get connection IDs
        let mut first_packet_buf = first_packet.to_vec();
        let hdr = quiche::Header::from_slice(&mut first_packet_buf, quiche::MAX_CONN_ID_LEN)?;
        let scid = hdr.dcid.clone();

        // Recreate the channel with the first packet
        let (new_incoming_tx, new_incoming_rx) = mpsc::channel(256);
        new_incoming_tx
            .send(Bytes::from(first_packet_buf))
            .await
            .map_err(|_| TunnelError::ConnectionFailed)?;

        // Forward remaining packets
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if new_incoming_tx.send(data).await.is_err() {
                    break;
                }
            }
        });

        // Accept QUIC connection
        let quic =
            QuicConnection::accept(&scid, None, config, outgoing_tx.clone(), new_incoming_rx)?;

        // Spawn driver task
        let quic_clone = quic.inner();
        let outgoing_tx_clone = outgoing_tx;
        let incoming_rx_clone = Arc::clone(&quic.incoming_rx);
        let next_stream_id_clone = Arc::clone(&quic.next_stream_id);
        let send_notify_clone = quic.send_notify();
        let recv_notify_clone = quic.recv_notify();
        let driver_handle = tokio::spawn(async move {
            let quic_ref = QuicConnection {
                inner: quic_clone,
                outgoing_tx: outgoing_tx_clone,
                incoming_rx: incoming_rx_clone,
                next_stream_id: next_stream_id_clone,
                send_notify: send_notify_clone,
                recv_notify: recv_notify_clone,
            };
            quic_ref.drive().await
        });

        // Wait for connection to be established
        let mut attempts = 0;
        while !quic.is_established().await {
            if quic.is_closed().await {
                return Err(TunnelError::ConnectionFailed);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            attempts += 1;
            if attempts > 500 {
                return Err(TunnelError::ConnectionTimeout);
            }
        }

        tracing::info!("QUIC server connection established");

        Ok(Self {
            quic,
            driver_handle,
            tcp_handle,
        })
    }

    /// Open a new bidirectional stream.
    pub async fn open_bi_stream(&self) -> Result<Stream, TunnelError> {
        let stream_id = self.quic.open_stream().await?;
        Ok(Stream {
            id: stream_id,
            quic: self.quic.inner(),
            send_notify: self.quic.send_notify(),
            recv_notify: self.quic.recv_notify(),
        })
    }

    /// Accept an incoming stream.
    pub async fn accept_bi_stream(&self) -> Result<Option<Stream>, TunnelError> {
        let streams = self.quic.readable_streams().await;
        if let Some(&stream_id) = streams.first() {
            Ok(Some(Stream {
                id: stream_id,
                quic: self.quic.inner(),
                send_notify: self.quic.send_notify(),
                recv_notify: self.quic.recv_notify(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Wait for and accept the next incoming bidirectional stream.
    /// This properly waits instead of busy-polling.
    pub async fn accept_bi_stream_wait(&self) -> Result<Stream, TunnelError> {
        self.accept_bi_stream_wait_excluding(&std::collections::HashSet::new())
            .await
    }

    /// Wait for and accept the next incoming bidirectional stream, excluding specified stream IDs.
    /// This properly waits instead of busy-polling.
    pub async fn accept_bi_stream_wait_excluding(
        &self,
        exclude: &std::collections::HashSet<u64>,
    ) -> Result<Stream, TunnelError> {
        let recv_notify = self.quic.recv_notify();
        loop {
            // Register for notification BEFORE checking for streams
            let notified = recv_notify.notified();

            // Check for readable streams, excluding already-handled ones
            let streams = self.quic.readable_streams().await;
            for &stream_id in &streams {
                if !exclude.contains(&stream_id) {
                    return Ok(Stream {
                        id: stream_id,
                        quic: self.quic.inner(),
                        send_notify: self.quic.send_notify(),
                        recv_notify: self.quic.recv_notify(),
                    });
                }
            }

            // All readable streams are already handled, wait for new activity
            notified.await;
        }
    }

    /// Check if the tunnel is established.
    pub async fn is_established(&self) -> bool {
        self.quic.is_established().await
    }

    /// Check if the tunnel is closed.
    pub async fn is_closed(&self) -> bool {
        self.quic.is_closed().await
    }

    /// Close the tunnel.
    pub async fn close(&self) -> Result<(), TunnelError> {
        self.quic.close(true, 0, b"done").await?;
        Ok(())
    }

    /// Get access to the underlying QUIC connection.
    pub fn quic(&self) -> &QuicConnection {
        &self.quic
    }

    /// Get the TCP connection handle for adding more connections.
    pub fn tcp_handle(&self) -> &TcpConnectionHandle {
        &self.tcp_handle
    }

    /// Add a new TCP connection to the tunnel.
    pub async fn add_tcp_connection(&self, stream: TcpStream) -> Result<(), TunnelError> {
        self.tcp_handle.add_connection(stream).await
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.driver_handle.abort();
    }
}

/// A QUIC stream within the tunnel.
pub struct Stream {
    id: u64,
    quic: Arc<Mutex<quiche::Connection>>,
    send_notify: Arc<tokio::sync::Notify>,
    recv_notify: Arc<tokio::sync::Notify>,
}

impl Stream {
    /// Get the stream ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Send data on this stream.
    /// Waits if the stream is blocked due to flow control.
    pub async fn send(&self, data: &[u8]) -> Result<usize, TunnelError> {
        let mut total_written = 0;
        while total_written < data.len() {
            // Register for notification BEFORE trying to send
            let notified = self.recv_notify.notified();

            let result = {
                let mut conn = self.quic.lock().await;
                conn.stream_send(self.id, &data[total_written..], false)
            };

            match result {
                Ok(written) => {
                    total_written += written;
                    self.send_notify.notify_one();
                }
                Err(quiche::Error::Done) => {
                    // Stream is blocked (flow control), wait for any activity
                    self.send_notify.notify_one(); // Trigger driver to send
                    notified.await; // Wait for response that might free up buffer
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(total_written)
    }

    /// Send data and close the send side.
    pub async fn send_fin(&self, data: &[u8]) -> Result<usize, TunnelError> {
        // First send all the data
        if !data.is_empty() {
            self.send(data).await?;
        }

        // Then send FIN
        loop {
            let notified = self.recv_notify.notified();

            let result = {
                let mut conn = self.quic.lock().await;
                conn.stream_send(self.id, b"", true)
            };

            match result {
                Ok(_) => {
                    self.send_notify.notify_one();
                    return Ok(data.len());
                }
                Err(quiche::Error::Done) => {
                    self.send_notify.notify_one();
                    notified.await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Receive data from this stream.
    /// Returns immediately with (0, false) if no data is available.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, bool), TunnelError> {
        let mut conn = self.quic.lock().await;
        match conn.stream_recv(self.id, buf) {
            Ok((len, fin)) => Ok((len, fin)),
            Err(quiche::Error::Done) => Ok((0, false)),
            Err(e) => Err(e.into()),
        }
    }

    /// Wait for data to be available, then receive.
    /// This properly waits for QUIC packets to arrive instead of busy-polling.
    pub async fn recv_wait(&self, buf: &mut [u8]) -> Result<(usize, bool), TunnelError> {
        loop {
            // Register for notification BEFORE checking for data
            // This prevents race condition where data arrives between check and wait
            let notified = self.recv_notify.notified();

            // Now try to receive
            let result = {
                let mut conn = self.quic.lock().await;
                conn.stream_recv(self.id, buf)
            };

            match result {
                Ok((len, fin)) => return Ok((len, fin)),
                Err(quiche::Error::Done) => {
                    // No data available, wait for notification
                    // If data arrived during our check, this returns immediately
                    notified.await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Close this stream (send FIN on write side).
    pub async fn close(&self) -> Result<(), TunnelError> {
        loop {
            let notified = self.recv_notify.notified();

            let result = {
                let mut conn = self.quic.lock().await;
                conn.stream_send(self.id, b"", true)
            };

            match result {
                Ok(_) => {
                    self.send_notify.notify_one();
                    return Ok(());
                }
                Err(quiche::Error::Done) => {
                    // Stream blocked, wait for activity
                    self.send_notify.notify_one();
                    notified.await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Fully shutdown this stream (both read and write sides).
    /// This releases the stream slot immediately without waiting for peer FIN.
    pub async fn shutdown(&self) -> Result<(), TunnelError> {
        let mut conn = self.quic.lock().await;

        // Shutdown write side (send RESET_STREAM)
        let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Write, 0);

        // Shutdown read side (send STOP_SENDING)
        let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Read, 0);

        self.send_notify.notify_one();
        Ok(())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Try to shutdown the stream synchronously when dropped
        // This ensures stream slots are released even if close() wasn't called
        if let Ok(mut conn) = self.quic.try_lock() {
            // Send FIN on write side (graceful close)
            let _ = conn.stream_send(self.id, b"", true);
            // Also shutdown read side to fully release the stream
            let _ = conn.stream_shutdown(self.id, quiche::Shutdown::Read, 0);
        }
        // Notify driver to send the frames
        self.send_notify.notify_one();
    }
}

/// Spawn tasks to handle TCP IO for the QUIC connection.
/// Returns a handle that can be used to add more TCP connections dynamically.
fn spawn_tcp_io_tasks(
    tcp_streams: Vec<TcpStream>,
    mut outgoing_rx: mpsc::Receiver<Bytes>,
    incoming_tx: mpsc::Sender<Bytes>,
) -> TcpConnectionHandle {
    let mut senders = Vec::new();
    let mut receivers = Vec::new();

    for stream in tcp_streams {
        let conn = FramedConnection::new(stream);
        let (sender, receiver) = conn.split();
        senders.push(sender);
        receivers.push(receiver);
    }

    // Channel for adding new TCP connections
    let (add_connection_tx, mut add_connection_rx) = mpsc::channel::<TcpStream>(16);
    let incoming_tx_clone = incoming_tx.clone();

    // Spawn task to distribute outgoing datagrams across TCP connections
    // This task also handles adding new connections dynamically
    tokio::spawn(async move {
        let mut index = 0;
        loop {
            tokio::select! {
                biased;

                // Handle new connection additions
                new_stream = add_connection_rx.recv() => {
                    let Some(stream) = new_stream else {
                        break;
                    };
                    let conn = FramedConnection::new(stream);
                    let (sender, receiver) = conn.split();
                    senders.push(sender);

                    // Spawn a receive task for the new connection
                    let tx = incoming_tx_clone.clone();
                    tokio::spawn(spawn_recv_task(receiver, tx));

                    tracing::debug!("added new TCP connection, total: {}", senders.len());
                }

                // Handle outgoing data
                data = outgoing_rx.recv() => {
                    let Some(data) = data else {
                        break;
                    };

                    if senders.is_empty() {
                        tracing::warn!("no TCP connections available for sending");
                        break;
                    }

                    let send_index = index;
                    index = (index + 1) % senders.len();

                    if let Err(e) = senders[send_index].send(data).await {
                        tracing::warn!("TCP send error: {}", e);
                        // Remove failed sender and continue with others
                        senders.remove(send_index);
                        if senders.is_empty() {
                            tracing::warn!("all TCP connections failed");
                            break;
                        }
                        // Adjust index if needed
                        if index >= senders.len() {
                            index = 0;
                        }
                    }
                }
            }
        }
    });

    // Spawn tasks to receive from each initial TCP connection
    for receiver in receivers {
        let tx = incoming_tx.clone();
        tokio::spawn(spawn_recv_task(receiver, tx));
    }

    TcpConnectionHandle { add_connection_tx }
}

/// Spawn a receive task for a single TCP connection.
async fn spawn_recv_task(mut receiver: super::ConnectionReceiver, tx: mpsc::Sender<Bytes>) {
    loop {
        match receiver.recv().await {
            Ok(Some(data)) => {
                if tx.send(data).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("TCP recv error: {}", e);
                break;
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("QUIC error: {0}")]
    Quic(#[from] QuicError),
    #[error("quiche error: {0}")]
    QuicheError(#[from] quiche::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection failed")]
    ConnectionFailed,
    #[error("connection timeout")]
    ConnectionTimeout,
}
