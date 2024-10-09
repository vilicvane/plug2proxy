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
};

use super::{
    match_pair::{YamuxInData, YamuxOutData},
    YamuxInTunnelConnection, YamuxOutTunnelConnection,
};

pub struct YamuxInTunnelConfig {
    pub priority: Option<i64>,
    pub priority_default: i64,
    pub traffic_mark: u32,
}

pub struct YamuxInTunnelProvider {
    id: MatchInId,
    index: usize,
    match_server: Arc<AnyInMatchServer>,
    config: YamuxInTunnelConfig,
}

impl YamuxInTunnelProvider {
    pub fn new(
        match_server: Arc<AnyInMatchServer>,
        config: YamuxInTunnelConfig,
        index: usize,
    ) -> Self {
        Self {
            id: MatchInId::new(),
            index,
            match_server,
            config,
        }
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for YamuxInTunnelProvider {
    async fn accept(&self) -> anyhow::Result<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))> {
        let MatchOut {
            id,
            tunnel_id,
            tunnel_labels,
            tunnel_priority,
            routing_priority,
            routing_rules,
            data:
                YamuxOutData {
                    address,
                    cert,
                    token,
                },
        } = self
            .match_server
            .match_out(self.id, YamuxInData { index: self.index })
            .await?;

        let stream = {
            let socket = match address {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };

            nix::sys::socket::setsockopt(
                &socket,
                nix::sys::socket::sockopt::Mark,
                &self.config.traffic_mark,
            )?;

            socket.connect(address).await?
        };

        println!("yamux tunnel {tunnel_id} underlying TCP connected.");

        let root_store = {
            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();

            let cert =
                tokio_rustls::rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid cert."))?;

            root_store.add(cert)?;

            root_store
        };

        let client_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let client_config = Arc::new(client_config);

        let tls_connector = tokio_rustls::TlsConnector::from(client_config);

        let mut stream = tls_connector
            .connect("localhost".try_into()?, stream)
            .await?;

        println!("yamux tunnel {tunnel_id} underlying TLS connection established.");

        stream.write_all(token.as_bytes()).await?;
        stream.flush().await?;

        let yamux_connection = {
            let mut config = yamux::Config::default();

            config.set_max_num_streams(1024);

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

        return Ok((Box::new(tunnel), (routing_rules, routing_priority)));
    }
}

pub struct YamuxOutTunnelConfig {
    pub priority: Option<i64>,
    pub stun_server_addresses: Vec<SocketAddr>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
}

pub struct YamuxOutTunnelProvider {
    id: MatchOutId,
    match_server: Arc<OutMatchServer>,
    config: YamuxOutTunnelConfig,
    server_config: Arc<tokio_rustls::rustls::ServerConfig>,
    cert: String,
}

impl YamuxOutTunnelProvider {
    pub fn new(match_server: Arc<OutMatchServer>, config: YamuxOutTunnelConfig) -> Self {
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

        Self {
            id: MatchOutId::new(),
            match_server,
            server_config,
            config,
            cert,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for YamuxOutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let (out_local_address, out_address) =
            assign_local_and_public_addresses(&self.config.stun_server_addresses).await?;

        println!("yamux tunnel assigned addresses {out_local_address}/{out_address}.");

        let socket = tokio::net::TcpSocket::new_v4()?;

        socket.set_reuseport(true)?;

        socket.bind(out_local_address)?;

        let listener = socket.listen(1024)?;

        let token = uuid::Uuid::new_v4().as_simple().to_string();

        let MatchIn {
            id,
            tunnel_id,
            data: _,
        } = self
            .match_server
            .match_in(
                self.id,
                YamuxOutData {
                    address: out_address,
                    cert: self.cert.clone(),
                    token: token.clone(),
                },
                self.config.priority,
                &self.config.routing_rules,
                self.config.routing_priority,
            )
            .await?;

        let (stream, _) = tokio::select! {
            result = listener.accept() => result?,
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                anyhow::bail!("accept timeout.")
            }
        };

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());

        let mut stream = tls_acceptor.accept(stream).await?;

        {
            let token_length = token.as_bytes().len();

            let mut token_buffer = vec![0; token_length];

            stream.read_exact(&mut token_buffer).await?;

            if token_buffer != token.as_bytes() {
                anyhow::bail!("invalid token.");
            }
        }

        let yamux_connection = {
            let mut config = yamux::Config::default();

            config.set_max_num_streams(1024);

            yamux::Connection::new(stream.compat(), config, yamux::Mode::Server)
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

const STUN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

async fn assign_local_and_public_addresses(
    stun_server_addresses: &[SocketAddr],
) -> anyhow::Result<(SocketAddr, SocketAddr)> {
    let request_buffer = {
        let mut request = stun::message::Message::new();

        request.build(&[
            Box::new(stun::agent::TransactionId::new()),
            Box::new(stun::message::BINDING_REQUEST),
        ])?;

        let mut request_buffer = Vec::new();

        request.write_to(&mut request_buffer)?;

        request_buffer
    };

    for stun_server_address in stun_server_addresses {
        let result = async {
            let socket = tokio::net::TcpSocket::new_v4()?;

            socket.set_reuseport(true)?;

            socket.bind("0.0.0.0:0".parse()?)?;

            println!("connecting to STUN server {stun_server_address}.");

            let mut stream = socket.connect(*stun_server_address).await?;

            println!("connected to STUN server {stun_server_address}.");

            let local_address = stream.local_addr()?;

            stream.write_all(&request_buffer).await?;
            stream.shutdown().await?;

            let mut response_buffer = Vec::new();

            stream.read_to_end(&mut response_buffer).await?;

            let mut response = stun::message::Message::new();

            response.read_from(&mut Cursor::new(response_buffer))?;

            let mut xor_addr = stun::xoraddr::XorMappedAddress::default();

            xor_addr.get_from(&response)?;

            anyhow::Ok((local_address, SocketAddr::new(xor_addr.ip, xor_addr.port)))
        };

        let result = tokio::select! {
            result = result => result,
            _ = tokio::time::sleep(STUN_RESPONSE_TIMEOUT) => Err(anyhow::anyhow!("request timeout.")),
        };

        match result {
            Ok(addresses) => {
                return Ok(addresses);
            }
            Err(error) => {
                log::error!("STUN request to {stun_server_address} failed: {}", error);
            }
        }
    }

    anyhow::bail!("failed to assign local and public addresses.");
}
