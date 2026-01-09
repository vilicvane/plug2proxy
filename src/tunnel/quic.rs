use std::sync::Arc;

use bytes::Bytes;
use lits::duration;
use ring::rand::SecureRandom;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, Notify};

/// Maximum datagram size for QUIC over TCP.
/// Since we're over TCP, we don't have MTU concerns, but quiche has internal limits.
const MAX_DATAGRAM_SIZE: usize = 65535;

/// QUIC configuration builder for TCP transport.
pub struct QuicConfig {
    inner: quiche::Config,
}

impl QuicConfig {
    /// Create a new QUIC configuration for client connections.
    ///
    /// # Arguments
    /// * `pem_path` - Path to combined PEM file (cert + key) for client auth
    /// * `ca_pem_path` - Path to CA PEM file for server verification
    pub fn new_client(
        pem_path: Option<&str>,
        ca_pem_path: Option<&str>,
    ) -> Result<Self, QuicError> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // Load client certificate if provided (for mTLS)
        // Combined PEM file contains both cert and key
        if let Some(pem) = pem_path {
            config.load_cert_chain_from_pem_file(pem)?;
            config.load_priv_key_from_pem_file(pem)?;
        }

        // Enable all QUIC features
        config.set_application_protos(&[b"p2p"])?;
        config.set_max_idle_timeout(3_600_000); // 1 hour - TCP transport handles connection liveness
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(10_000);
        config.set_initial_max_streams_uni(10_000);
        config.set_disable_active_migration(true);
        // Use BBR congestion control since we're running over TCP
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBR);

        // Configure server certificate verification
        if let Some(ca_path) = ca_pem_path {
            config.load_verify_locations_from_file(ca_path)?;
            config.verify_peer(true);
        } else {
            config.verify_peer(false);
        }

        Ok(Self { inner: config })
    }

    /// Create a new QUIC configuration for server connections.
    ///
    /// # Arguments
    /// * `pem_path` - Path to combined PEM file (cert + key) for server
    /// * `ca_pem_path` - Path to CA PEM file for client verification (enables mTLS)
    pub fn new_server(pem_path: &str, ca_pem_path: Option<&str>) -> Result<Self, QuicError> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // Load server certificate and private key from combined PEM
        config.load_cert_chain_from_pem_file(pem_path)?;
        config.load_priv_key_from_pem_file(pem_path)?;

        // Enable all QUIC features
        config.set_application_protos(&[b"p2p"])?;
        config.set_max_idle_timeout(3_600_000); // 1 hour - TCP transport handles connection liveness
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(10_000);
        config.set_initial_max_streams_uni(10_000);
        config.set_disable_active_migration(true);
        // Use BBR congestion control since we're running over TCP
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBR);

        // Configure client certificate verification (mTLS)
        if let Some(ca_path) = ca_pem_path {
            config.load_verify_locations_from_file(ca_path)?;
            config.verify_peer(true);
        }

        Ok(Self { inner: config })
    }

    /// Get the inner quiche config.
    pub fn into_inner(self) -> quiche::Config {
        self.inner
    }
}

/// A QUIC connection running over our TCP transport.
pub struct QuicConnection {
    pub(crate) inner: Arc<Mutex<quiche::Connection>>,
    /// Channel to send outgoing datagrams
    pub(crate) outgoing_tx: mpsc::Sender<Bytes>,
    /// Channel to receive incoming datagrams (from TCP transport)
    pub(crate) incoming_rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    /// Next stream ID for bidirectional streams
    pub(crate) next_stream_id: Arc<Mutex<u64>>,
    /// Notify when there's data to send
    pub(crate) send_notify: Arc<Notify>,
    /// Notify when there's data to receive on streams
    pub(crate) recv_notify: Arc<Notify>,
}

impl QuicConnection {
    /// Create a new client QUIC connection.
    pub fn connect(
        server_name: Option<&str>,
        config: &mut quiche::Config,
        outgoing_tx: mpsc::Sender<Bytes>,
        incoming_rx: mpsc::Receiver<Bytes>,
    ) -> Result<Self, QuicError> {
        let scid = generate_connection_id();
        let local_addr = "0.0.0.0:0".parse().unwrap();
        let peer_addr = "0.0.0.0:0".parse().unwrap();

        let conn = quiche::connect(server_name, &scid, local_addr, peer_addr, config)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            outgoing_tx,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
            // Client-initiated bidi streams: 0, 4, 8, ...
            next_stream_id: Arc::new(Mutex::new(0)),
            send_notify: Arc::new(Notify::new()),
            recv_notify: Arc::new(Notify::new()),
        })
    }

    /// Accept an incoming QUIC connection (server side).
    pub fn accept(
        scid: &quiche::ConnectionId<'_>,
        odcid: Option<&quiche::ConnectionId<'_>>,
        config: &mut quiche::Config,
        outgoing_tx: mpsc::Sender<Bytes>,
        incoming_rx: mpsc::Receiver<Bytes>,
    ) -> Result<Self, QuicError> {
        let local_addr = "0.0.0.0:0".parse().unwrap();
        let peer_addr = "0.0.0.0:0".parse().unwrap();

        let conn = quiche::accept(scid, odcid, local_addr, peer_addr, config)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
            outgoing_tx,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
            // Server-initiated bidi streams: 1, 5, 9, ...
            next_stream_id: Arc::new(Mutex::new(1)),
            send_notify: Arc::new(Notify::new()),
            recv_notify: Arc::new(Notify::new()),
        })
    }

    /// Process incoming datagrams and drive the QUIC state machine.
    /// Returns when the connection is closed.
    pub async fn drive(&self) -> Result<(), QuicError> {
        let result = self.drive_inner().await;
        // Notify all waiters so streams can detect the closed state
        self.recv_notify.notify_waiters();
        self.send_notify.notify_waiters();
        result
    }

    async fn drive_inner(&self) -> Result<(), QuicError> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            // First, send any pending outgoing data
            {
                let mut conn = self.inner.lock().await;
                loop {
                    let (write, _) = match conn.send(&mut out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => break,
                        Err(e) => return Err(e.into()),
                    };

                    let data = Bytes::copy_from_slice(&out[..write]);
                    if self.outgoing_tx.send(data).await.is_err() {
                        return Err(QuicError::TransportClosed);
                    }
                }

                if conn.is_closed() {
                    return Ok(());
                }
            }

            // Calculate timeout for next event
            let timeout = {
                let conn = self.inner.lock().await;
                conn.timeout().unwrap_or(duration!("100 ms"))
            };

            // Wait for incoming data, send notification, or timeout
            // Use Option<Option<Bytes>> to distinguish: Some(Some(data))=data, Some(None)=channel closed, None=timeout
            let recv_result: Option<Option<Bytes>> = {
                let mut rx = self.incoming_rx.lock().await;
                tokio::select! {
                    biased;

                    // Check for send notification first
                    _ = self.send_notify.notified() => {
                        // Just loop back to send any pending data
                        continue;
                    }

                    result = rx.recv() => Some(result),

                    _ = tokio::time::sleep(timeout) => None,
                }
            };

            match recv_result {
                Some(Some(data)) => {
                    let mut conn = self.inner.lock().await;
                    let recv_info = quiche::RecvInfo {
                        from: "0.0.0.0:0".parse().unwrap(),
                        to: "0.0.0.0:0".parse().unwrap(),
                    };

                    buf[..data.len()].copy_from_slice(&data);
                    match conn.recv(&mut buf[..data.len()], recv_info) {
                        Ok(_) => {
                            // Notify that there might be data to read on streams
                            self.recv_notify.notify_waiters();
                        }
                        Err(quiche::Error::Done) => {}
                        Err(e) => {
                            tracing::warn!("QUIC recv error: {}", e);
                        }
                    }
                }
                Some(None) => {
                    // Channel closed - all TCP connections are gone
                    tracing::debug!("incoming channel closed, all TCP connections gone");
                    return Err(QuicError::TransportClosed);
                }
                None => {
                    // Timeout - process any pending events
                    let mut conn = self.inner.lock().await;
                    conn.on_timeout();

                    if conn.is_closed() {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Check if the connection is established.
    pub async fn is_established(&self) -> bool {
        self.inner.lock().await.is_established()
    }

    /// Check if the connection is closed.
    pub async fn is_closed(&self) -> bool {
        self.inner.lock().await.is_closed()
    }

    /// Get the source connection ID (what clients use as dcid to reach us).
    pub async fn source_id(&self) -> Vec<u8> {
        self.inner.lock().await.source_id().to_vec()
    }

    /// Open a new bidirectional stream.
    /// Returns the stream ID.
    pub async fn open_stream(&self) -> Result<u64, QuicError> {
        let mut next_id = self.next_stream_id.lock().await;
        let stream_id = *next_id;
        // Bidirectional streams increment by 4
        *next_id += 4;
        Ok(stream_id)
    }

    /// Send data on a stream.
    pub async fn stream_send(
        &self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, QuicError> {
        let written = {
            let mut conn = self.inner.lock().await;
            conn.stream_send(stream_id, data, fin)?
        };
        // Notify driver to send
        self.send_notify.notify_one();
        Ok(written)
    }

    /// Receive data from a stream.
    pub async fn stream_recv(
        &self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), QuicError> {
        let mut conn = self.inner.lock().await;
        let (read, fin) = conn.stream_recv(stream_id, buf)?;
        Ok((read, fin))
    }

    /// Get an iterator over readable streams.
    pub async fn readable_streams(&self) -> Vec<u64> {
        let conn = self.inner.lock().await;
        conn.readable().collect()
    }

    /// Close the connection.
    pub async fn close(&self, app: bool, err: u64, reason: &[u8]) -> Result<(), QuicError> {
        {
            let mut conn = self.inner.lock().await;
            conn.close(app, err, reason)?;
        }
        self.send_notify.notify_one();
        Ok(())
    }

    /// Get a clone of the inner connection for advanced usage.
    pub fn inner(&self) -> Arc<Mutex<quiche::Connection>> {
        Arc::clone(&self.inner)
    }

    /// Get a clone of the send notify for advanced usage.
    pub fn send_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.send_notify)
    }

    /// Get a clone of the recv notify for advanced usage.
    pub fn recv_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.recv_notify)
    }

    /// Get the peer's certificate (DER-encoded).
    /// Returns None if no peer certificate is available (e.g., no mTLS).
    pub async fn peer_cert(&self) -> Option<Vec<u8>> {
        let conn = self.inner.lock().await;
        conn.peer_cert().map(|cert| cert.to_vec())
    }
}

/// Generate a random connection ID.
fn generate_connection_id() -> quiche::ConnectionId<'static> {
    let mut id = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut id)
        .expect("failed to generate random connection ID");
    quiche::ConnectionId::from_vec(id.to_vec())
}

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("QUIC error: {0}")]
    Quic(#[from] quiche::Error),
    #[error("transport closed")]
    TransportClosed,
    #[error("no available streams")]
    NoAvailableStreams,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
