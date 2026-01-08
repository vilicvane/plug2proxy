use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use super::{FramedConnection, QuicConfig, QuicConnection, QuicError};

/// Magic byte for routing header (distinguishes from QUIC packets which start with 0x80-0xFF or 0x00-0x3F).
/// We use 0x50 ('P' for plug2proxy) which is in the reserved range.
pub const ROUTING_MAGIC: u8 = 0x50;

/// ACK byte sent by server after accepting a routing header.
pub const ROUTING_ACK: u8 = 0x51;

/// A TCP connection with optional initial data already read.
pub struct TcpConnectionWithData {
    pub stream: TcpStream,
    pub initial_data: Option<Bytes>,
}

/// Handle for adding new TCP connections to an existing tunnel.
#[derive(Clone)]
pub struct TcpConnectionHandle {
    add_connection_tx: mpsc::Sender<TcpConnectionWithData>,
    /// QUIC connection ID (for routing additional connections)
    connection_id: Arc<Mutex<Option<Vec<u8>>>>,
    /// Server address for reconnection (client-side only)
    server_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// Desired number of TCP connections
    desired_count: Arc<Mutex<usize>>,
    /// Channel to request refueling
    refuel_tx: mpsc::Sender<()>,
    /// Flag indicating all TCP connections have died
    transport_dead: Arc<std::sync::atomic::AtomicBool>,
}

impl TcpConnectionHandle {
    /// Set the connection ID (called after QUIC handshake succeeds).
    pub async fn set_connection_id(&self, id: Vec<u8>) {
        let mut conn_id = self.connection_id.lock().await;
        *conn_id = Some(id);
    }

    /// Set the server address for reconnection (client-side only).
    pub async fn set_server_addr(&self, addr: SocketAddr) {
        let mut server_addr = self.server_addr.lock().await;
        *server_addr = Some(addr);
    }

    /// Set the desired connection count.
    pub async fn set_desired_count(&self, count: usize) {
        let mut desired = self.desired_count.lock().await;
        *desired = count;
    }

    /// Request a refuel (add more connections if needed).
    pub fn request_refuel(&self) {
        let _ = self.refuel_tx.try_send(());
    }

    /// Check if the transport layer (all TCP connections) is dead.
    pub fn is_transport_dead(&self) -> bool {
        self.transport_dead
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Add a new TCP connection to the tunnel.
    /// For additional connections, sends a routing header first and waits for ACK.
    pub async fn add_connection(&self, stream: TcpStream) -> Result<(), TunnelError> {
        stream.set_nodelay(true)?;

        // If we have a connection ID, send routing header first as a framed message
        if let Some(ref conn_id) = *self.connection_id.lock().await {
            // Create routing header: MAGIC + length (1 byte) + connection ID
            let mut header = vec![ROUTING_MAGIC, conn_id.len() as u8];
            header.extend_from_slice(conn_id);

            // Send as a framed message (length-prefixed)
            let mut conn = super::FramedConnection::new(stream);
            conn.send(Bytes::from(header))
                .await
                .map_err(|e| TunnelError::Io(std::io::Error::other(e.to_string())))?;

            // Wait for ACK from server
            let ack = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv()).await;
            match ack {
                Ok(Ok(Some(data))) if !data.is_empty() && data[0] == ROUTING_ACK => {
                    // ACK received, connection accepted
                }
                Ok(Ok(Some(_))) => {
                    tracing::debug!("received unexpected response instead of routing ACK");
                    return Err(TunnelError::ConnectionFailed);
                }
                Ok(Ok(None)) => {
                    // Connection closed - server rejected (likely stale connection ID)
                    tracing::debug!(
                        "connection closed while waiting for routing ACK (stale connection ID?)"
                    );
                    return Err(TunnelError::ConnectionFailed);
                }
                Ok(Err(e)) => {
                    tracing::debug!("error receiving routing ACK: {}", e);
                    return Err(TunnelError::ConnectionFailed);
                }
                Err(_) => {
                    tracing::debug!("timeout waiting for routing ACK");
                    return Err(TunnelError::ConnectionTimeout);
                }
            }

            // Get the stream back and add to the pool
            let stream = conn.into_inner();
            self.add_connection_tx
                .send(TcpConnectionWithData {
                    stream,
                    initial_data: None,
                })
                .await
                .map_err(|_| TunnelError::ConnectionFailed)?;
        } else {
            // No connection ID (shouldn't happen for additional connections)
            self.add_connection_tx
                .send(TcpConnectionWithData {
                    stream,
                    initial_data: None,
                })
                .await
                .map_err(|_| TunnelError::ConnectionFailed)?;
        }
        Ok(())
    }

    /// Add a new TCP connection with initial data already read.
    pub async fn add_connection_with_initial_data(
        &self,
        stream: TcpStream,
        initial_data: Bytes,
    ) -> Result<(), TunnelError> {
        self.add_connection_tx
            .send(TcpConnectionWithData {
                stream,
                initial_data: Some(initial_data),
            })
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
    /// Create a client tunnel connecting to a server (no certificate verification).
    pub async fn connect(
        addr: SocketAddr,
        server_name: Option<&str>,
        connection_count: usize,
    ) -> Result<Self, TunnelError> {
        Self::connect_with_cert(addr, server_name, connection_count, None, None).await
    }

    /// Create a client tunnel with optional client certificate authentication.
    ///
    /// # Arguments
    /// * `addr` - Server address to connect to
    /// * `server_name` - Optional server name for SNI
    /// * `connection_count` - Number of TCP connections to use
    /// * `pem_path` - Optional path to client PEM file (cert + key)
    /// * `ca_pem_path` - Optional path to CA PEM file (for server verification)
    pub async fn connect_with_cert(
        addr: SocketAddr,
        server_name: Option<&str>,
        connection_count: usize,
        pem_path: Option<&str>,
        ca_pem_path: Option<&str>,
    ) -> Result<Self, TunnelError> {
        let config = QuicConfig::new_client(pem_path, ca_pem_path)?;
        Self::connect_with_config(addr, server_name, connection_count, config.into_inner()).await
    }

    /// Create a client tunnel with custom QUIC config.
    ///
    /// Establishes a single TCP connection first, waits for QUIC handshake to succeed,
    /// then adds additional TCP connections in the background if `connection_count > 1`.
    /// TCP connections are automatically refueled if some disconnect while QUIC is alive.
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

        // Set server address and desired count for refueling
        tunnel.tcp_handle.set_server_addr(addr).await;
        tunnel.tcp_handle.set_desired_count(connection_count).await;

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

        // Set connection ID for routing additional connections
        let conn_id = quic.source_id().await;
        tcp_handle.set_connection_id(conn_id).await;

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

    /// Create a server tunnel from a TCP stream with initial data already read.
    ///
    /// This is used when the first frame has already been read to determine
    /// connection routing.
    pub async fn from_tcp_stream_server_with_initial_data(
        tcp_stream: TcpStream,
        initial_data: Bytes,
        config: &mut quiche::Config,
    ) -> Result<Self, TunnelError> {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let (incoming_tx, incoming_rx) = mpsc::channel(256);

        // Split TCP stream and spawn IO tasks
        let tcp_handle = spawn_tcp_io_tasks(vec![tcp_stream], outgoing_rx, incoming_tx.clone());

        // The first packet was already read, parse it for connection ID
        let mut first_packet_buf = initial_data.to_vec();
        let hdr = quiche::Header::from_slice(&mut first_packet_buf, quiche::MAX_CONN_ID_LEN)?;
        let scid = hdr.dcid.clone();

        // Send the first packet to the incoming channel
        incoming_tx
            .send(Bytes::from(first_packet_buf))
            .await
            .map_err(|_| TunnelError::ConnectionFailed)?;

        // Accept QUIC connection
        let quic = QuicConnection::accept(&scid, None, config, outgoing_tx.clone(), incoming_rx)?;

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

    /// Create a server tunnel from a TCP stream with initial data already read.
    /// Does NOT wait for QUIC handshake - call `wait_established()` separately.
    ///
    /// This is useful when you need to register the tunnel before the handshake
    /// completes, to handle additional TCP connections that arrive early.
    pub async fn from_tcp_stream_server_with_initial_data_no_wait(
        tcp_stream: TcpStream,
        initial_data: Bytes,
        config: &mut quiche::Config,
    ) -> Result<Self, TunnelError> {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let (incoming_tx, incoming_rx) = mpsc::channel(256);

        // Split TCP stream and spawn IO tasks
        let tcp_handle = spawn_tcp_io_tasks(vec![tcp_stream], outgoing_rx, incoming_tx.clone());

        // The first packet was already read, parse it for connection ID
        let mut first_packet_buf = initial_data.to_vec();
        let hdr = quiche::Header::from_slice(&mut first_packet_buf, quiche::MAX_CONN_ID_LEN)?;
        let scid = hdr.dcid.clone();

        // Send the first packet to the incoming channel
        incoming_tx
            .send(Bytes::from(first_packet_buf))
            .await
            .map_err(|_| TunnelError::ConnectionFailed)?;

        // Accept QUIC connection
        let quic = QuicConnection::accept(&scid, None, config, outgoing_tx.clone(), incoming_rx)?;

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

        // Return immediately without waiting for handshake
        Ok(Self {
            quic,
            driver_handle,
            tcp_handle,
        })
    }

    /// Wait for the QUIC connection to be established.
    pub async fn wait_established(&self) -> Result<(), TunnelError> {
        let mut attempts = 0;
        while !self.quic.is_established().await {
            if self.quic.is_closed().await {
                return Err(TunnelError::ConnectionFailed);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            attempts += 1;
            if attempts > 500 {
                return Err(TunnelError::ConnectionTimeout);
            }
        }
        tracing::info!("QUIC server connection established");
        Ok(())
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
            // Check if connection is closed
            if self.is_closed().await {
                return Err(TunnelError::ConnectionFailed);
            }

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

            // All readable streams are already handled, wait for new activity with timeout
            // Timeout allows periodic re-check of connection status
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        }
    }

    /// Check if the tunnel is established.
    pub async fn is_established(&self) -> bool {
        self.quic.is_established().await
    }

    /// Check if the tunnel is closed (either QUIC closed or all TCP connections died).
    pub async fn is_closed(&self) -> bool {
        self.quic.is_closed().await || self.tcp_handle.is_transport_dead()
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

    /// Add a new TCP connection with initial data already read.
    pub async fn add_tcp_connection_with_initial_data(
        &self,
        stream: TcpStream,
        initial_data: Bytes,
    ) -> Result<(), TunnelError> {
        self.tcp_handle
            .add_connection_with_initial_data(stream, initial_data)
            .await
    }

    /// Get the QUIC source connection ID (what clients use as dcid to reach this tunnel).
    pub async fn connection_id(&self) -> Vec<u8> {
        self.quic.source_id().await
    }

    /// Get the peer's Common Name from their TLS certificate.
    /// Returns None if no peer certificate is available (e.g., no mTLS) or if the CN cannot be extracted.
    pub async fn peer_common_name(&self) -> Option<String> {
        let cert_der = self.quic.peer_cert().await?;
        crate::cert::extract_common_name(&cert_der)
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
    let initial_count = tcp_streams.len();
    let mut senders = Vec::new();
    let mut receivers = Vec::new();

    for stream in tcp_streams {
        let conn = FramedConnection::new(stream);
        let (sender, receiver) = conn.split();
        senders.push(sender);
        receivers.push(receiver);
    }

    // Channel for adding new TCP connections (with optional initial data)
    let (add_connection_tx, mut add_connection_rx) = mpsc::channel::<TcpConnectionWithData>(16);
    let incoming_tx_clone = incoming_tx.clone();
    let connection_id = Arc::new(Mutex::new(None));
    let server_addr = Arc::new(Mutex::new(None));
    let desired_count = Arc::new(Mutex::new(initial_count));

    // Channel for refuel requests
    let (refuel_tx, mut refuel_rx) = mpsc::channel::<()>(16);

    // Track current connection count
    let current_count = Arc::new(std::sync::atomic::AtomicUsize::new(initial_count));
    let current_count_for_send = Arc::clone(&current_count);
    let current_count_for_refuel = Arc::clone(&current_count);

    // Flag to track if all TCP connections have died
    let transport_dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let transport_dead_for_send = Arc::clone(&transport_dead);

    // Clone for refueling task
    let connection_id_for_refuel = Arc::clone(&connection_id);
    let server_addr_for_refuel = Arc::clone(&server_addr);
    let desired_count_for_refuel = Arc::clone(&desired_count);
    let add_connection_tx_for_refuel = add_connection_tx.clone();
    let refuel_tx_for_send = refuel_tx.clone();

    // Spawn task to distribute outgoing datagrams across TCP connections
    // This task also handles adding new connections dynamically
    tokio::spawn(async move {
        let mut index = 0;
        loop {
            tokio::select! {
                biased;

                // Handle new connection additions
                new_conn = add_connection_rx.recv() => {
                    let Some(TcpConnectionWithData { stream, initial_data }) = new_conn else {
                        break;
                    };
                    let conn = FramedConnection::new(stream);
                    let (sender, receiver) = conn.split();
                    senders.push(sender);
                    current_count_for_send.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // If there's initial data, inject it into the incoming channel first
                    if let Some(data) = initial_data {
                        let tx = incoming_tx_clone.clone();
                        if tx.send(data).await.is_err() {
                            tracing::warn!("failed to inject initial data for new connection");
                        }
                    }

                    // Spawn a receive task for the new connection
                    let tx = incoming_tx_clone.clone();
                    let count = Arc::clone(&current_count_for_send);
                    let refuel = refuel_tx_for_send.clone();
                    tokio::spawn(spawn_recv_task_with_refuel(receiver, tx, count, refuel));

                    tracing::debug!("added new TCP connection, total: {}", senders.len());
                }

                // Handle outgoing data
                data = outgoing_rx.recv() => {
                    let Some(data) = data else {
                        break;
                    };

                    if senders.is_empty() {
                        tracing::warn!("no TCP connections available for sending, marking transport as dead");
                        transport_dead_for_send.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }

                    let send_index = index;
                    index = (index + 1) % senders.len();

                    if let Err(e) = senders[send_index].send(data).await {
                        tracing::warn!("TCP send error on connection {}: {}", send_index, e);
                        // Remove failed sender
                        senders.remove(send_index);
                        current_count_for_send.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

                        if senders.is_empty() {
                            tracing::warn!("all TCP connections failed, marking transport as dead");
                            transport_dead_for_send.store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        // Adjust index if needed
                        if index >= senders.len() {
                            index = 0;
                        }

                        // Request refuel
                        let _ = refuel_tx_for_send.try_send(());
                    }
                }
            }
        }
    });

    // Spawn tasks to receive from each initial TCP connection
    for receiver in receivers {
        let tx = incoming_tx.clone();
        let count = Arc::clone(&current_count);
        let refuel = refuel_tx.clone();
        tokio::spawn(spawn_recv_task_with_refuel(receiver, tx, count, refuel));
    }

    // Clone transport_dead for refuel task
    let transport_dead_for_refuel = Arc::clone(&transport_dead);

    // Spawn refueling task (client-side only, server_addr must be set)
    tokio::spawn(async move {
        let mut consecutive_failures = 0u32;
        const MAX_CONSECUTIVE_FAILURES: u32 = 3;

        loop {
            // Wait for refuel request
            if refuel_rx.recv().await.is_none() {
                break;
            }

            // Debounce: wait a bit and drain any additional requests
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            while refuel_rx.try_recv().is_ok() {}

            // Check if we need to refuel
            let current_before =
                current_count_for_refuel.load(std::sync::atomic::Ordering::Relaxed);
            let desired = *desired_count_for_refuel.lock().await;

            if current_before >= desired {
                consecutive_failures = 0; // Reset on success
                continue;
            }

            // Get server address (client-side only)
            let addr = {
                let addr_guard = server_addr_for_refuel.lock().await;
                match *addr_guard {
                    Some(addr) => addr,
                    None => continue, // Server-side, no refueling
                }
            };

            // Get connection ID
            let conn_id: Vec<u8> = {
                let id_guard = connection_id_for_refuel.lock().await;
                match id_guard.clone() {
                    Some(id) => id,
                    None => continue, // No connection ID yet
                }
            };

            let needed = desired - current_before;
            tracing::debug!(
                "refueling TCP connections: current={}, desired={}, adding={}",
                current_before,
                desired,
                needed
            );

            let mut added_count = 0;
            let mut rejected_count = 0;

            for i in 0..needed {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        if let Err(e) = stream.set_nodelay(true) {
                            tracing::warn!(
                                "failed to set nodelay on refuel connection {}: {}",
                                i,
                                e
                            );
                            continue;
                        }

                        // Send routing header
                        let mut header = vec![ROUTING_MAGIC, conn_id.len() as u8];
                        header.extend_from_slice(&conn_id);

                        let mut conn = FramedConnection::new(stream);
                        if let Err(e) = conn.send(Bytes::from(header)).await {
                            tracing::warn!("failed to send routing header on refuel: {}", e);
                            continue;
                        }

                        // Wait for ACK from server
                        let ack =
                            tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
                                .await;

                        match ack {
                            Ok(Ok(Some(data))) if !data.is_empty() && data[0] == ROUTING_ACK => {
                                // ACK received, connection accepted
                                let stream = conn.into_inner();
                                if add_connection_tx_for_refuel
                                    .send(TcpConnectionWithData {
                                        stream,
                                        initial_data: None,
                                    })
                                    .await
                                    .is_err()
                                {
                                    tracing::warn!(
                                        "failed to add refuel connection: channel closed"
                                    );
                                    break;
                                }
                                added_count += 1;
                                tracing::debug!("added refuel connection {}", i + 1);
                            }
                            Ok(Ok(Some(_))) => {
                                tracing::debug!("refuel {}: unexpected response instead of ACK", i);
                                rejected_count += 1;
                            }
                            Ok(Ok(None)) => {
                                // Connection closed - server rejected (stale connection ID)
                                tracing::debug!(
                                    "refuel {}: connection closed (stale connection ID?)",
                                    i
                                );
                                rejected_count += 1;
                            }
                            Ok(Err(e)) => {
                                tracing::debug!("refuel {}: error receiving ACK: {}", i, e);
                                rejected_count += 1;
                            }
                            Err(_) => {
                                tracing::debug!("refuel {}: timeout waiting for ACK", i);
                                rejected_count += 1;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("failed to establish refuel connection {}: {}", i, e);
                    }
                }
            }

            // Check if refueling was successful
            let current_after = current_count_for_refuel.load(std::sync::atomic::Ordering::Relaxed);

            if added_count > 0 {
                consecutive_failures = 0; // Reset on success
                tracing::debug!("refuel succeeded: added {} connections", added_count);
            } else if rejected_count > 0 {
                // All connections were rejected - likely stale connection ID
                consecutive_failures += 1;

                // If we have NO working connections and refuel failed, mark dead immediately
                if current_after == 0 {
                    tracing::error!(
                        "all TCP connections dead and refuel rejected ({} connections), marking transport as dead",
                        rejected_count
                    );
                    transport_dead_for_refuel.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }

                tracing::warn!(
                    "refuel failed: {} connections rejected ({}/{}), {} connections still alive",
                    rejected_count,
                    consecutive_failures,
                    MAX_CONSECUTIVE_FAILURES,
                    current_after
                );

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    tracing::error!(
                        "too many consecutive refuel failures, marking transport as dead"
                    );
                    transport_dead_for_refuel.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    TcpConnectionHandle {
        add_connection_tx,
        connection_id,
        server_addr,
        desired_count,
        refuel_tx,
        transport_dead,
    }
}

/// Spawn a receive task for a single TCP connection.
/// Receive task that also triggers refueling when the connection closes.
async fn spawn_recv_task_with_refuel(
    mut receiver: super::ConnectionReceiver,
    tx: mpsc::Sender<Bytes>,
    current_count: Arc<std::sync::atomic::AtomicUsize>,
    refuel_tx: mpsc::Sender<()>,
) {
    loop {
        match receiver.recv().await {
            Ok(Some(data)) => {
                if tx.send(data).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                // Connection closed normally
                tracing::debug!("TCP receive connection closed");
                break;
            }
            Err(e) => {
                tracing::warn!("TCP recv error: {}", e);
                break;
            }
        }
    }

    // Decrement count and request refuel
    current_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    let _ = refuel_tx.try_send(());
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
