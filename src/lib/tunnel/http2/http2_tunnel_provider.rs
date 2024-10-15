use std::{
    net::SocketAddr,
    os::fd::{AsFd as _, AsRawFd as _},
    sync::Arc,
    time::Duration,
};

use rustls::pki_types::pem::PemObject;

use crate::{
    match_server::{
        AnyInMatchServer, InMatchServer as _, MatchIn, MatchInId, MatchOut, MatchOutId,
        OutMatchServer, OutMatchServerTrait as _,
    },
    route::config::OutRuleConfig,
    tunnel::{
        http2::{Http2InTunnel, Http2OutTunnel},
        tunnel_provider::{InTunnelProvider, OutTunnelProvider},
        InTunnel, OutTunnel,
    },
    utils::stun::probe_external_ip,
};

use super::match_pair::{Http2InData, Http2OutData};

pub struct Http2InTunnelConfig {
    pub connections: usize,
    pub priority: Option<i64>,
    pub priority_default: i64,
    pub traffic_mark: u32,
}

pub struct Http2InTunnelProvider {
    id: MatchInId,
    match_server: Arc<AnyInMatchServer>,
    config: Http2InTunnelConfig,
}

impl Http2InTunnelProvider {
    pub async fn new(
        match_server: Arc<AnyInMatchServer>,
        config: Http2InTunnelConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            id: MatchInId::new(),
            match_server,
            config,
        })
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for Http2InTunnelProvider {
    fn name(&self) -> &'static str {
        "http2"
    }

    async fn accept_out(&self) -> anyhow::Result<(MatchOutId, usize)> {
        self.match_server
            .accept_out::<Http2InData, Http2OutData>()
            .await
            .map(|out_id| (out_id, self.config.connections))
    }

    async fn accept(
        &self,
        out_id: MatchOutId,
    ) -> anyhow::Result<Option<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))>> {
        let Some(MatchOut {
            id,
            tunnel_id,
            tunnel_labels,
            tunnel_priority,
            routing_priority,
            routing_rules,
            data: Http2OutData { address, cert, key },
        }) = self
            .match_server
            .match_out(out_id, self.id, Http2InData {})
            .await?
        else {
            return Ok(None);
        };

        let socket = match address {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }?;

        nix::sys::socket::setsockopt(
            &socket,
            nix::sys::socket::sockopt::Mark,
            &self.config.traffic_mark,
        )?;

        socket.set_nodelay(true)?;

        let fd = socket.as_fd().as_raw_fd();

        let stream = socket.connect(address).await?;

        log::debug!("http2 tunnel {tunnel_id} underlying TCP connected.");

        let client_config = {
            let cert =
                tokio_rustls::rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid cert."))?;
            let key =
                tokio_rustls::rustls::pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid key."))?;

            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();

            root_store.add(cert.clone())?;

            let cert_chain = vec![cert];

            let mut client_config = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(cert_chain, key)?;

            client_config.alpn_protocols = vec![b"h2".to_vec()];

            Arc::new(client_config)
        };

        let tls_connector = tokio_rustls::TlsConnector::from(client_config);

        let stream = tls_connector
            .connect("localhost".try_into()?, stream)
            .await?;

        log::debug!("http2 tunnel {tunnel_id} underlying TLS connection established.");

        let (request_sender, h2_connection) = h2::client::Builder::new()
            .initial_connection_window_size(4 * 1024 * 1024)
            .initial_window_size(4 * 1024 * 1024)
            .handshake(stream)
            .await?;

        let priority = self
            .config
            .priority
            .unwrap_or(tunnel_priority.unwrap_or(self.config.priority_default));

        let tunnel = Http2InTunnel::new(
            tunnel_id,
            id,
            tunnel_labels,
            priority,
            request_sender,
            h2_connection,
            fd,
        );

        log::info!("tunnel {tunnel} established.");

        Ok(Some((Box::new(tunnel), (routing_rules, routing_priority))))
    }
}

pub struct Http2OutTunnelConfig {
    pub stun_server_addresses: Vec<SocketAddr>,
    pub priority: Option<i64>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
}

pub struct Http2OutTunnelProvider {
    id: MatchOutId,
    match_server: Arc<OutMatchServer>,
    server_config: Arc<tokio_rustls::rustls::ServerConfig>,
    cert: String,
    key: String,
    config: Http2OutTunnelConfig,
}

impl Http2OutTunnelProvider {
    pub fn new(match_server: Arc<OutMatchServer>, config: Http2OutTunnelConfig) -> Self {
        let (server_config, cert, key) = {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();

            let cert_chain = vec![cert.cert.der().clone()];
            let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.key_pair.serialize_der(),
            );

            let root_store = {
                let mut root_store = tokio_rustls::rustls::RootCertStore::empty();

                let cert =
                    tokio_rustls::rustls::pki_types::CertificateDer::from_slice(cert.cert.der());

                root_store.add(cert).unwrap();

                Arc::new(root_store)
            };

            let client_cert_verifier =
                tokio_rustls::rustls::server::WebPkiClientVerifier::builder(root_store)
                    .build()
                    .unwrap();

            let server_config = Arc::new(
                tokio_rustls::rustls::ServerConfig::builder_with_protocol_versions(
                    tokio_rustls::rustls::DEFAULT_VERSIONS,
                )
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(cert_chain, key.into())
                .unwrap(),
            );

            let key = cert.key_pair.serialize_pem();
            let cert = cert.cert.pem();

            (server_config, cert, key)
        };

        Self {
            id: MatchOutId::new(),
            match_server,
            server_config,
            cert,
            key,
            config,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for Http2OutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let ip = probe_external_ip(&self.config.stun_server_addresses).await?;

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;

        let external_address = SocketAddr::new(ip, listener.local_addr()?.port());

        let MatchIn {
            id: _,
            tunnel_id,
            data: Http2InData {},
        } = self
            .match_server
            .match_in(
                self.id,
                Http2OutData {
                    address: external_address,
                    cert: self.cert.clone(),
                    key: self.key.clone(),
                },
                self.config.priority,
                &self.config.routing_rules,
                self.config.routing_priority,
            )
            .await?;

        let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;

        stream.set_nodelay(true)?;

        let fd = stream.as_fd().as_raw_fd();

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());

        let stream = tls_acceptor.accept(stream).await?;

        let connection = h2::server::Builder::new()
            .initial_connection_window_size(4 * 1024 * 1024)
            .initial_window_size(4 * 1024 * 1024)
            .handshake(stream)
            .await?;

        let tunnel = Http2OutTunnel::new(tunnel_id, connection, fd);

        log::info!("tunnel {tunnel} established.");

        return Ok(Box::new(tunnel));
    }
}
