use std::{io::Cursor, net::SocketAddr, sync::Arc, time::Duration};

use futures::TryFutureExt;
use rustls::pki_types::pem::PemObject;
use stun::message::Getter as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::TokioAsyncReadCompatExt as _;

use crate::{
    match_server::{
        AnyInMatchServer, InMatchServer as _, MatchIn, MatchInId, MatchOut, MatchOutId,
        OutMatchServer, OutMatchServerTrait as _,
    },
    route::config::OutRuleConfig,
    tunnel::{
        byte_stream_tunnel::{ByteStreamInTunnel, ByteStreamOutTunnel},
        tunnel_provider::{InTunnelProvider, OutTunnelProvider},
        InTunnel, OutTunnel,
    },
    utils::stun::probe_external_ip,
};

use super::{
    match_pair::{YamuxInData, YamuxOutData},
    YamuxInTunnelConnection, YamuxOutTunnelConnection,
};

// const H2_HANDSHAKE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct YamuxInTunnelConfig {
    pub stun_server_addresses: Vec<SocketAddr>,
    pub priority: Option<i64>,
    pub priority_default: i64,
    pub listen: SocketAddr,
    pub connections: usize,
    pub traffic_mark: u32,
}

pub struct YamuxInTunnelProvider {
    id: MatchInId,
    match_server: Arc<AnyInMatchServer>,
    listener: tokio::net::TcpListener,
    connections_semaphore: Arc<tokio::sync::Semaphore>,
    server_config: Arc<tokio_rustls::rustls::ServerConfig>,
    cert: String,
    config: YamuxInTunnelConfig,
}

impl YamuxInTunnelProvider {
    pub async fn new(
        match_server: Arc<AnyInMatchServer>,
        config: YamuxInTunnelConfig,
    ) -> anyhow::Result<Self> {
        let (server_config, cert) = {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();

            let cert_chain = vec![cert.cert.der().clone()];
            let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.key_pair.serialize_der(),
            );

            let server_config = Arc::new(
                tokio_rustls::rustls::ServerConfig::builder_with_protocol_versions(
                    tokio_rustls::rustls::DEFAULT_VERSIONS,
                )
                .with_no_client_auth()
                .with_single_cert(cert_chain, key.into())
                .unwrap(),
            );

            let cert = cert.cert.pem();

            (server_config, cert)
        };

        let listener = {
            let socket = match config.listen {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };

            socket.set_reuseport(true)?;

            nix::sys::socket::setsockopt(
                &socket,
                nix::sys::socket::sockopt::Mark,
                &config.traffic_mark,
            )?;

            socket.bind(config.listen)?;

            socket.listen(1024)?
        };

        Ok(Self {
            id: MatchInId::new(),
            match_server,
            listener,
            connections_semaphore: Arc::new(tokio::sync::Semaphore::new(config.connections)),
            server_config,
            cert,
            config,
        })
    }

    async fn _accept(&self) -> anyhow::Result<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))> {
        let token = uuid::Uuid::new_v4().as_simple().to_string();

        let external_ip = probe_external_ip(&self.config.stun_server_addresses).await?;

        let external_address = SocketAddr::new(external_ip, self.listener.local_addr()?.port());

        let MatchOut {
            id,
            tunnel_id,
            tunnel_labels,
            tunnel_priority,
            routing_priority,
            routing_rules,
            data: _,
        } = self
            .match_server
            .match_out(
                self.id,
                YamuxInData {
                    address: external_address,
                    cert: self.cert.clone(),
                    token: token.clone(),
                },
            )
            .await?;

        let (stream, _) =
            tokio::time::timeout(Duration::from_secs(5), self.listener.accept()).await??;

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());

        let mut stream = tls_acceptor.accept(stream).await?;

        // {
        //     let mut buffer = vec![0; H2_HANDSHAKE.len()];

        //     stream.read_exact(&mut buffer).await?;

        //     if buffer != H2_HANDSHAKE {
        //         anyhow::bail!("invalid h2 handshake.");
        //     }
        // }

        // {
        //     let token_length = token.as_bytes().len();

        //     let mut token_buffer = vec![0; token_length];

        //     stream.read_exact(&mut token_buffer).await?;

        //     println!("token: {:?}", token_buffer);

        //     if token_buffer != token.as_bytes() {
        //         println!("invalid token");

        //         anyhow::bail!("invalid token.");
        //     }
        // }

        let yamux_connection = {
            let mut config = yamux::Config::default();

            // config.set_max_num_streams(1024);

            yamux::Connection::new(stream.compat(), config, yamux::Mode::Server)
        };

        let connection = YamuxInTunnelConnection::new(yamux_connection);

        let tunnel = ByteStreamInTunnel::new(
            tunnel_id,
            id,
            tunnel_labels,
            self.config
                .priority
                .unwrap_or(tunnel_priority.unwrap_or(self.config.priority_default)),
            connection,
        );

        log::info!("yamux tunnel {tunnel} established.");

        Ok((Box::new(tunnel), (routing_rules, routing_priority)))
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for YamuxInTunnelProvider {
    async fn accept(&self) -> anyhow::Result<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))> {
        let permit = self.connections_semaphore.clone().acquire_owned().await?;

        let result = self._accept().await;

        match &result {
            Ok((tunnel, _)) => tunnel.handle_permit(permit),
            Err(_) => {}
        }

        result
    }
}

pub struct YamuxOutTunnelConfig {
    pub priority: Option<i64>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
}

pub struct YamuxOutTunnelProvider {
    id: MatchOutId,
    match_server: Arc<OutMatchServer>,
    config: YamuxOutTunnelConfig,
}

impl YamuxOutTunnelProvider {
    pub fn new(match_server: Arc<OutMatchServer>, config: YamuxOutTunnelConfig) -> Self {
        Self {
            id: MatchOutId::new(),
            match_server,
            config,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for YamuxOutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let MatchIn {
            id,
            tunnel_id,
            data:
                YamuxInData {
                    address,
                    cert,
                    token,
                },
        } = self
            .match_server
            .match_in(
                self.id,
                YamuxOutData {},
                self.config.priority,
                &self.config.routing_rules,
                self.config.routing_priority,
            )
            .await?;

        let stream = tokio::net::TcpStream::connect(address).await?;

        println!("yamux tunnel {tunnel_id} underlying TCP connected.");

        let root_store = {
            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();

            let cert =
                tokio_rustls::rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid cert."))?;

            root_store.add(cert)?;

            root_store
        };

        let mut client_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_config.alpn_protocols = vec![b"h2".to_vec()];

        let client_config = Arc::new(client_config);

        let tls_connector = tokio_rustls::TlsConnector::from(client_config);

        let mut stream = tls_connector
            .connect("localhost".try_into()?, stream)
            .await?;

        // stream.write_all(H2_HANDSHAKE).await?;
        // stream.flush().await?;

        // stream.write_all(token.as_bytes()).await?;
        // stream.flush().await?;

        println!("yamux tunnel {tunnel_id} underlying TLS connection established.");

        let yamux_connection = {
            let mut config = yamux::Config::default();

            // config.set_max_num_streams(1024);

            yamux::Connection::new(stream.compat(), config, yamux::Mode::Client)
        };

        let (closed_sender, mut closed_receiver) = tokio::sync::mpsc::unbounded_channel();

        let connection = YamuxOutTunnelConnection::new(yamux_connection, closed_sender);

        log::info!("yamux tunnel {tunnel_id} established.");

        self.match_server.register_in(id).await?;

        tokio::spawn({
            let match_server = self.match_server.clone();

            async move {
                closed_receiver.recv().await;

                match_server.unregister_in(&id).await?;

                anyhow::Ok(())
            }
            .inspect_err(|error| log::error!("{}", error))
        });

        return Ok(Box::new(ByteStreamOutTunnel::new(tunnel_id, connection)));
    }
}
