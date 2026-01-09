use std::io::Write;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::node::InNode;
use crate::util::tcp_connect_with_mark;

/// Default GeoLite2 database URL (GitHub mirror).
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb";

/// Special label for GeoIP update tunnel.
pub const GEOIP_LABEL: &str = "geoip";

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
    /// Uses the "geoip" label tunnel if available, otherwise downloads directly.
    pub async fn update(&self, in_node: Option<Arc<InNode>>) -> Result<(), GeoIpUpdateError> {
        tracing::info!("Starting GeoIP database update from {}", self.url);

        // Parse URL
        let url =
            url::Url::parse(&self.url).map_err(|e| GeoIpUpdateError::InvalidUrl(e.to_string()))?;

        // Check if we can use the geoip label for routing
        let use_proxy = if let Some(ref in_node) = in_node {
            let outs = in_node.get_outs().await;
            outs.iter()
                .any(|out| out.labels.contains(&GEOIP_LABEL.to_string()))
        } else {
            false
        };

        if use_proxy {
            tracing::info!("Downloading GeoIP database via '{}' tunnel", GEOIP_LABEL);
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
                let stream = in_node1
                    .connect_with_label(&target, GEOIP_LABEL)
                    .await
                    .map_err(|e| GeoIpUpdateError::Tunnel(e.to_string()))?;

                let io = ProxyStreamAdapter::new(stream);
                let tls_stream = wrap_tls(io, host).await?;
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

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| GeoIpUpdateError::Tls(e.to_string()))?;

    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| GeoIpUpdateError::Tls(e.to_string()))
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

    let io = TokioIo::new(tls_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| GeoIpUpdateError::Http(e.to_string()))?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("HTTP connection error: {}", e);
        }
    });

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
        .header("User-Agent", "plug2proxy")
        .header("Connection", "close")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| GeoIpUpdateError::Http(e.to_string()))?;

    // Send request
    let response: Response<Incoming> = sender
        .send_request(req)
        .await
        .map_err(|e| GeoIpUpdateError::Http(e.to_string()))?;

    let status = response.status();

    // Handle redirects
    if status.is_redirection() {
        if let Some(location) = response.headers().get("location") {
            let location = location
                .to_str()
                .map_err(|e| GeoIpUpdateError::Http(format!("invalid location header: {}", e)))?
                .to_string();
            return Ok(HttpResponse::Redirect(location));
        }
        return Err(GeoIpUpdateError::Http(
            "redirect without location header".to_string(),
        ));
    }

    if !status.is_success() {
        return Err(GeoIpUpdateError::Http(format!("HTTP error: {}", status)));
    }

    // Collect body
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| GeoIpUpdateError::Http(e.to_string()))?
        .to_bytes();

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
        let (client_read, server_write) = tokio::io::duplex(8192);
        let (server_read, client_write) = tokio::io::duplex(8192);

        let relay_handle = tokio::spawn(async move {
            let mut stream = stream;
            let mut server_read = server_read;
            let mut server_write = server_write;

            let mut read_buf = vec![0u8; 8192];
            let mut write_buf = vec![0u8; 8192];

            loop {
                tokio::select! {
                    // Read from proxy stream, write to client
                    result = stream.recv_wait(&mut read_buf) => {
                        match result {
                            Ok((0, true)) | Err(_) => break,
                            Ok((n, _)) => {
                                use tokio::io::AsyncWriteExt;
                                if server_write.write_all(&read_buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    // Read from client, write to proxy stream
                    result = {
                        use tokio::io::AsyncReadExt;
                        server_read.read(&mut write_buf)
                    } => {
                        match result {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.send(&write_buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
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
