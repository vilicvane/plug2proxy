use std::io::Write;
use std::sync::Arc;

use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::node::InNode;
use crate::route::{BuiltInLabel, Label};
use crate::util::tcp_connect_with_mark;

/// Default GeoLite2 database URL (GitHub mirror).
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb";

/// GeoIP database updater.
pub struct GeoIpUpdater {
    url: String,
    db_path: String,
}

impl GeoIpUpdater {
    pub fn new(db_path: impl Into<String>) -> Self {
        Self {
            url: DEFAULT_GEOIP_URL.to_string(),
            db_path: db_path.into(),
        }
    }

    /// Set custom download URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Update the GeoIP database.
    /// Uses ANY available OUT tunnel if connected, otherwise downloads directly.
    pub async fn update(&self, in_node: Option<Arc<InNode>>) -> Result<(), GeoIpUpdateError> {
        tracing::info!("Starting GeoIP database update from {}", self.url);

        // Parse URL
        let url =
            url::Url::parse(&self.url).map_err(|e| GeoIpUpdateError::InvalidUrl(e.to_string()))?;

        // Check if we can use any OUT for routing
        let use_proxy = if let Some(ref in_node) = in_node {
            let outs = in_node.get_outs().await;
            !outs.is_empty()
        } else {
            false
        };

        if use_proxy {
            tracing::info!("Downloading GeoIP database via ANY available tunnel");
        } else {
            tracing::info!("Downloading GeoIP database directly");
        }

        // Download with redirect handling
        let data = self
            .download_with_redirects(in_node.clone(), use_proxy, &url)
            .await?;

        // Validate it's a valid MaxMind DB by searching for the metadata marker
        // The marker appears before the metadata section, not at the end
        const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
        let has_marker = data.windows(MARKER.len()).any(|window| window == MARKER);
        if !has_marker {
            return Err(GeoIpUpdateError::InvalidDatabase);
        }

        // Write to temp file first, then rename (atomic update)
        let temp_path = format!("{}.tmp", self.db_path);
        {
            let mut file = std::fs::File::create(&temp_path)
                .map_err(|e| GeoIpUpdateError::Io(e.to_string()))?;
            file.write_all(&data)
                .map_err(|e| GeoIpUpdateError::Io(e.to_string()))?;
        }

        std::fs::rename(&temp_path, &self.db_path)
            .map_err(|e| GeoIpUpdateError::Io(e.to_string()))?;

        tracing::info!(
            "GeoIP database updated successfully: {} ({} bytes)",
            self.db_path,
            data.len()
        );

        // Reload the database in InNode if available
        if let Some(ref in_node) = in_node {
            match in_node.reload_geoip() {
                Ok(true) => tracing::info!("GeoIP database reloaded in routing engine"),
                Ok(false) => tracing::debug!("No GeoIP database configured in routing engine"),
                Err(e) => {
                    tracing::warn!("Failed to reload GeoIP database in routing engine: {}", e)
                }
            }
        }

        Ok(())
    }

    /// Download from URL, following redirects.
    async fn download_with_redirects(
        &self,
        in_node: Option<Arc<InNode>>,
        use_proxy: bool,
        initial_url: &url::Url,
    ) -> Result<Vec<u8>, GeoIpUpdateError> {
        let mut url = initial_url.clone();
        let mut redirects = 0;
        const MAX_REDIRECTS: u32 = 10;

        loop {
            if redirects >= MAX_REDIRECTS {
                return Err(GeoIpUpdateError::Http("too many redirects".to_string()));
            }

            let host = url
                .host_str()
                .ok_or_else(|| GeoIpUpdateError::InvalidUrl("missing host".to_string()))?;
            let port = url.port().unwrap_or(443);
            let target = format!("{}:{}", host, port);

            // Connect to the target
            let result = if use_proxy && let Some(in_node1) = &in_node {
                tracing::debug!("Connecting to {} via tunnel (ANY)", target);
                let stream = in_node1
                    .connect_with_label(&target, Label::BuiltIn(BuiltInLabel::Any))
                    .await
                    .map_err(|e| {
                        tracing::debug!("Tunnel connection failed: {}", e);
                        GeoIpUpdateError::Tunnel(e.to_string())
                    })?;

                tracing::debug!("Tunnel connection established, starting TLS handshake");
                let io = ProxyStreamAdapter::new(stream);
                let tls_stream = wrap_tls(io, host).await?;
                tracing::debug!("TLS handshake complete");
                https_get(tls_stream, &url, host).await
            } else {
                // Get mark if configured
                let mark = in_node.as_ref().and_then(|n| n.mark());

                // Resolve DNS first, then connect with mark
                let addr = tokio::net::lookup_host(&target)
                    .await
                    .map_err(|e| GeoIpUpdateError::Io(format!("DNS lookup failed: {}", e)))?
                    .next()
                    .ok_or_else(|| GeoIpUpdateError::Io("no addresses found".to_string()))?;

                let tcp = tcp_connect_with_mark(addr, mark)
                    .await
                    .map_err(|e| GeoIpUpdateError::Io(e.to_string()))?;

                let tls_stream = wrap_tls(tcp, host).await?;
                https_get(tls_stream, &url, host).await
            };

            match result {
                Ok(HttpResponse::Body(data)) => return Ok(data),
                Ok(HttpResponse::Redirect(location)) => {
                    tracing::debug!("Following redirect to: {}", location);
                    url = url::Url::parse(&location)
                        .or_else(|_| url.join(&location))
                        .map_err(|e| {
                            GeoIpUpdateError::InvalidUrl(format!("invalid redirect URL: {}", e))
                        })?;
                    redirects += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// HTTP response that can be either a body or a redirect.
enum HttpResponse {
    Body(Vec<u8>),
    Redirect(String),
}

/// Wrap a stream with TLS using rustls.
async fn wrap_tls<S>(
    stream: S,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<S>, GeoIpUpdateError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set ALPN to http/1.1 - required for some servers like GitHub
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| GeoIpUpdateError::Tls(e.to_string()))?;

    connector.connect(server_name, stream).await.map_err(|e| {
        tracing::debug!("TLS handshake failed for {}: {}", host, e);
        GeoIpUpdateError::Tls(e.to_string())
    })
}

/// Make an HTTPS GET request using hyper.
/// Returns either the body or a redirect location.
async fn https_get<S>(
    tls_stream: tokio_rustls::client::TlsStream<S>,
    url: &url::Url,
    host: &str,
) -> Result<HttpResponse, GeoIpUpdateError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use http_body_util::BodyExt;

    tracing::debug!("https_get: starting HTTP handshake to {}", host);

    let io = TokioIo::new(tls_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            tracing::debug!("https_get: HTTP handshake failed: {}", e);
            GeoIpUpdateError::Http(format!("handshake failed: {}", e))
        })?;

    tracing::debug!("https_get: HTTP handshake complete");

    // Build request - include query string in URI
    let path_and_query = if let Some(query) = url.query() {
        format!("{}?{}", url.path(), query)
    } else {
        url.path().to_string()
    };

    let req = Request::builder()
        .method("GET")
        .uri(&path_and_query)
        .header("Host", host)
        .header("User-Agent", "curl/7.68.0")
        .header("Accept", "*/*")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| GeoIpUpdateError::Http(e.to_string()))?;

    tracing::debug!("https_get: sending request to {}{}", host, path_and_query);

    // Drive the connection alongside our request/response
    // This ensures the connection driver runs while we're sending/receiving
    let mut conn = conn.with_upgrades();

    let response = tokio::select! {
        result = sender.send_request(req) => {
            result.map_err(|e| {
                tracing::debug!("https_get: send_request failed: {}", e);
                GeoIpUpdateError::Http(e.to_string())
            })?
        }
        result = &mut conn => {
            // Connection closed before we got a response
            let msg = match result {
                Ok(()) => "connection closed unexpectedly".to_string(),
                Err(e) => format!("connection error: {}", e),
            };
            tracing::debug!("https_get: {}", msg);
            return Err(GeoIpUpdateError::Http(msg));
        }
    };

    let status = response.status();
    tracing::debug!("https_get: received response status: {}", status);

    // Handle redirects
    if status.is_redirection() {
        if let Some(location) = response.headers().get("location") {
            let location = location
                .to_str()
                .map_err(|e| GeoIpUpdateError::Http(format!("invalid location header: {}", e)))?
                .to_string();
            tracing::debug!("https_get: redirect to {}", location);
            return Ok(HttpResponse::Redirect(location));
        }
        return Err(GeoIpUpdateError::Http(
            "redirect without location header".to_string(),
        ));
    }

    if !status.is_success() {
        return Err(GeoIpUpdateError::Http(format!("HTTP error: {}", status)));
    }

    // Collect body while driving the connection
    tracing::debug!("https_get: collecting response body");
    let body = tokio::select! {
        result = response.into_body().collect() => {
            result.map_err(|e| {
                tracing::debug!("https_get: body collection failed: {}", e);
                GeoIpUpdateError::Http(e.to_string())
            })?.to_bytes()
        }
        result = &mut conn => {
            // For Connection: close, the server will close after sending the response
            // This is expected, so we check if we already got the body
            tracing::debug!("https_get: connection closed during body collection: {:?}", result);
            return Err(GeoIpUpdateError::Http("connection closed during body read".to_string()));
        }
    };

    tracing::debug!("https_get: body collected, {} bytes", body.len());
    Ok(HttpResponse::Body(body.to_vec()))
}

/// Adapter to make ProxyStream implement AsyncRead + AsyncWrite.
struct ProxyStreamAdapter {
    read_half: tokio::io::DuplexStream,
    write_half: tokio::io::DuplexStream,
    relay_handle: tokio::task::JoinHandle<()>,
}

impl Drop for ProxyStreamAdapter {
    fn drop(&mut self) {
        self.relay_handle.abort();
    }
}

impl ProxyStreamAdapter {
    fn new(stream: crate::tunnel::ProxyStream) -> Self {
        let (client_read, server_write) = tokio::io::duplex(1024 * 1024); // 1MB buffer for large downloads
        let (server_read, client_write) = tokio::io::duplex(65536);

        let relay_handle = tokio::spawn(async move {
            let mut stream = stream;
            let mut server_read = server_read;
            let mut server_write = server_write;

            let mut read_buf = vec![0u8; 65536];
            let mut write_buf = vec![0u8; 65536];

            let mut stream_fin_received = false;
            let mut client_closed = false;
            let mut total_from_stream = 0usize;
            let mut total_to_stream = 0usize;

            loop {
                tokio::select! {
                    biased; // Prefer reading from stream (server response) over client writes

                    // Read from proxy stream, write to client
                    result = stream.recv_wait(&mut read_buf), if !stream_fin_received => {
                        use tokio::io::AsyncWriteExt;
                        match result {
                            Ok((0, true)) => {
                                // Stream finished, flush and shutdown write to client
                                tracing::debug!(
                                    "ProxyStreamAdapter: stream finished (FIN), total received: {} bytes",
                                    total_from_stream
                                );
                                stream_fin_received = true;
                                let _ = server_write.flush().await;
                                let _ = server_write.shutdown().await;
                            }
                            Ok((n, fin)) => {
                                total_from_stream += n;
                                if let Err(e) = server_write.write_all(&read_buf[..n]).await {
                                    tracing::debug!(
                                        "ProxyStreamAdapter: write to client failed: {}, total received: {} bytes",
                                        e, total_from_stream
                                    );
                                    break;
                                }
                                if fin {
                                    tracing::debug!(
                                        "ProxyStreamAdapter: stream finished with data (FIN), total received: {} bytes",
                                        total_from_stream
                                    );
                                    stream_fin_received = true;
                                    let _ = server_write.flush().await;
                                    let _ = server_write.shutdown().await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "ProxyStreamAdapter: recv_wait error: {}, total received: {} bytes",
                                    e, total_from_stream
                                );
                                stream_fin_received = true;
                                let _ = server_write.shutdown().await;
                            }
                        }
                    }
                    // Read from client, write to proxy stream
                    result = {
                        use tokio::io::AsyncReadExt;
                        server_read.read(&mut write_buf)
                    }, if !client_closed => {
                        match result {
                            Ok(0) => {
                                tracing::debug!(
                                    "ProxyStreamAdapter: client closed, total sent: {} bytes",
                                    total_to_stream
                                );
                                client_closed = true;
                                let _ = stream.close().await;
                            }
                            Ok(n) => {
                                total_to_stream += n;
                                if let Err(e) = stream.send(&write_buf[..n]).await {
                                    tracing::debug!(
                                        "ProxyStreamAdapter: send to stream failed: {}, total sent: {} bytes",
                                        e, total_to_stream
                                    );
                                    client_closed = true;
                                    let _ = stream.close().await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "ProxyStreamAdapter: read from client failed: {}, total sent: {} bytes",
                                    e, total_to_stream
                                );
                                client_closed = true;
                                let _ = stream.close().await;
                            }
                        }
                    }

                    else => {
                        // Both directions done
                        tracing::debug!(
                            "ProxyStreamAdapter: relay complete, sent: {} bytes, received: {} bytes",
                            total_to_stream, total_from_stream
                        );
                        break;
                    }
                }
            }
        });

        Self {
            read_half: client_read,
            write_half: client_write,
            relay_handle,
        }
    }
}

impl AsyncRead for ProxyStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.read_half).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.write_half).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.write_half).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.write_half).poll_shutdown(cx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeoIpUpdateError {
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("tunnel error: {0}")]
    Tunnel(String),

    #[error("invalid MaxMind database format")]
    InvalidDatabase,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Test that data flows correctly from proxy stream (TCP) through the adapter.
    #[tokio::test]
    async fn test_proxy_stream_adapter_data_relay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server sends data
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"Hello from server!").await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        });

        // Client connects and wraps in ProxyStreamAdapter
        let tcp = TcpStream::connect(addr).await.unwrap();
        let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
        let mut adapter = ProxyStreamAdapter::new(proxy_stream);

        // Read through the adapter
        let mut buf = vec![0u8; 1024];
        let n = adapter.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Hello from server!");

        // Verify EOF is received
        let n = adapter.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        server_task.await.unwrap();
    }

    /// Test that large data transfers work correctly (simulating file download).
    #[tokio::test]
    async fn test_proxy_stream_adapter_large_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create test data (1MB to simulate realistic download)
        let test_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let expected_data = test_data.clone();

        // Server sends large data
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&test_data).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        });

        // Client reads through adapter
        let tcp = TcpStream::connect(addr).await.unwrap();
        let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
        let mut adapter = ProxyStreamAdapter::new(proxy_stream);

        // Read all data
        let mut received = Vec::new();
        loop {
            let mut buf = vec![0u8; 65536];
            let n = adapter.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        assert_eq!(received.len(), expected_data.len());
        assert_eq!(received, expected_data);

        server_task.await.unwrap();
    }

    /// Test bidirectional data flow through the adapter.
    #[tokio::test]
    async fn test_proxy_stream_adapter_bidirectional() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server echoes data back
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        });

        // Client sends and receives through adapter
        let tcp = TcpStream::connect(addr).await.unwrap();
        let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
        let mut adapter = ProxyStreamAdapter::new(proxy_stream);

        // Write through adapter
        adapter.write_all(b"Echo this!").await.unwrap();
        adapter.flush().await.unwrap();
        adapter.shutdown().await.unwrap();

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = adapter.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Echo this!");

        server_task.await.unwrap();
    }

    /// Test that the adapter properly handles server closing the connection mid-stream.
    #[tokio::test]
    async fn test_proxy_stream_adapter_early_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server sends partial data then closes
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"Partial data").await.unwrap();
            stream.flush().await.unwrap();
            // Close without shutdown to simulate abrupt close
            drop(stream);
        });

        // Client reads through adapter
        let tcp = TcpStream::connect(addr).await.unwrap();
        let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
        let mut adapter = ProxyStreamAdapter::new(proxy_stream);

        // Should still receive the data that was sent
        let mut buf = vec![0u8; 1024];
        let n = adapter.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"Partial data");

        server_task.await.unwrap();
    }

    /// Test that HTTP request/response pattern works through the adapter.
    /// This simulates what happens during GeoIP download.
    #[tokio::test]
    async fn test_proxy_stream_adapter_http_pattern() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Simulate HTTP response
        let response_body = b"This is the response body content";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            response_body.len()
        );

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read request (simple)
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap();

            // Send response headers and body
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(response_body).await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
        });

        // Client makes request through adapter
        let tcp = TcpStream::connect(addr).await.unwrap();
        let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
        let mut adapter = ProxyStreamAdapter::new(proxy_stream);

        // Send request
        adapter
            .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        adapter.flush().await.unwrap();

        // Read full response
        let mut received = Vec::new();
        loop {
            let mut buf = vec![0u8; 1024];
            let n = adapter.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        // Verify we got the complete response
        let response_str = String::from_utf8_lossy(&received);
        assert!(response_str.contains("HTTP/1.1 200 OK"));
        assert!(response_str.contains("This is the response body content"));

        server_task.await.unwrap();
    }

    /// Test multiple small writes followed by reads (chunked pattern).
    #[tokio::test]
    async fn test_proxy_stream_adapter_chunked_writes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server sends data in chunks
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for i in 0..10 {
                let chunk = format!("Chunk {}\n", i);
                stream.write_all(chunk.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            stream.shutdown().await.unwrap();
        });

        // Client reads through adapter
        let tcp = TcpStream::connect(addr).await.unwrap();
        let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
        let mut adapter = ProxyStreamAdapter::new(proxy_stream);

        // Read all chunks
        let mut received = Vec::new();
        loop {
            let mut buf = vec![0u8; 1024];
            let n = adapter.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        let result = String::from_utf8_lossy(&received);
        for i in 0..10 {
            assert!(
                result.contains(&format!("Chunk {}", i)),
                "Missing chunk {}",
                i
            );
        }

        server_task.await.unwrap();
    }

    /// Integration test that downloads the actual GeoIP database from the default URL.
    /// This test is ignored by default since it requires network access.
    /// Run with: cargo test test_download_real_geoip -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn test_download_real_geoip() {
        use super::*;

        // Initialize logging for debugging
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        // Download directly (no tunnel) to test the HTTP layer
        let url = url::Url::parse(DEFAULT_GEOIP_URL).unwrap();

        println!("Downloading from {} ...", DEFAULT_GEOIP_URL);

        // Follow redirects manually
        let mut current_url = url.clone();
        let mut redirects = 0;
        const MAX_REDIRECTS: u32 = 10;

        let data = loop {
            if redirects >= MAX_REDIRECTS {
                panic!("Too many redirects");
            }

            let host = current_url.host_str().unwrap();
            let port = current_url.port().unwrap_or(443);
            let target = format!("{}:{}", host, port);

            println!("Connecting to {} ...", target);

            // Connect directly
            let tcp = TcpStream::connect(&target).await.unwrap();
            let tls_stream = wrap_tls(tcp, host).await.unwrap();

            println!("TLS connected, sending request...");

            let result = https_get(tls_stream, &current_url, host).await;

            match result {
                Ok(HttpResponse::Body(data)) => {
                    println!("Downloaded {} bytes", data.len());
                    break data;
                }
                Ok(HttpResponse::Redirect(location)) => {
                    println!("Redirect to: {}", location);
                    current_url = url::Url::parse(&location)
                        .or_else(|_| current_url.join(&location))
                        .unwrap();
                    redirects += 1;
                }
                Err(e) => {
                    panic!("Download failed: {:?}", e);
                }
            }
        };

        // Verify it's a valid MaxMind database
        const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
        let has_marker = data.windows(MARKER.len()).any(|window| window == MARKER);
        assert!(
            has_marker,
            "Downloaded file is not a valid MaxMind database"
        );

        // GeoLite2-Country.mmdb is typically 5-7MB
        assert!(
            data.len() > 1_000_000,
            "Database too small: {} bytes",
            data.len()
        );
        assert!(
            data.len() < 20_000_000,
            "Database too large: {} bytes",
            data.len()
        );

        println!(
            "✅ Successfully downloaded valid GeoIP database: {} bytes",
            data.len()
        );
    }

    /// Integration test that downloads through a TCP ProxyStream (simulates tunnel path).
    /// This tests the ProxyStreamAdapter with real HTTPS traffic.
    /// Run with: cargo test test_download_geoip_through_adapter -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn test_download_geoip_through_adapter() {
        use super::*;

        println!("Testing GeoIP download through ProxyStreamAdapter...");

        let mut current_url = url::Url::parse(DEFAULT_GEOIP_URL).unwrap();
        let mut redirects = 0;
        const MAX_REDIRECTS: u32 = 10;

        let data = loop {
            if redirects >= MAX_REDIRECTS {
                panic!("Too many redirects");
            }

            let host = current_url.host_str().unwrap();
            let port = current_url.port().unwrap_or(443);
            let target = format!("{}:{}", host, port);

            println!("Connecting to {} via ProxyStreamAdapter...", target);

            // Connect through TCP, wrap in ProxyStream, then in adapter
            let tcp = TcpStream::connect(&target).await.unwrap();
            let proxy_stream = crate::tunnel::ProxyStream::from_tcp(tcp);
            let adapter = ProxyStreamAdapter::new(proxy_stream);

            // Wrap in TLS
            let tls_stream = wrap_tls(adapter, host).await.unwrap();

            println!("TLS connected through adapter, sending request...");

            let result = https_get(tls_stream, &current_url, host).await;

            match result {
                Ok(HttpResponse::Body(data)) => {
                    println!("Downloaded {} bytes through adapter", data.len());
                    break data;
                }
                Ok(HttpResponse::Redirect(location)) => {
                    println!("Redirect to: {}", location);
                    current_url = url::Url::parse(&location)
                        .or_else(|_| current_url.join(&location))
                        .unwrap();
                    redirects += 1;
                }
                Err(e) => {
                    panic!("Download through adapter failed: {:?}", e);
                }
            }
        };

        // Verify it's a valid MaxMind database
        const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
        let has_marker = data.windows(MARKER.len()).any(|window| window == MARKER);
        assert!(
            has_marker,
            "Downloaded file is not a valid MaxMind database"
        );

        // GeoLite2-Country.mmdb is typically 5-7MB
        assert!(
            data.len() > 1_000_000,
            "Database too small: {} bytes",
            data.len()
        );

        println!(
            "✅ Successfully downloaded valid GeoIP database through adapter: {} bytes",
            data.len()
        );
    }
}
