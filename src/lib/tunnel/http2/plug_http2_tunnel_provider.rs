use std::{
    net::SocketAddr,
    os::fd::{AsFd as _, AsRawFd as _},
    str::FromStr,
    sync::Arc,
};

use itertools::Itertools;
use lits::duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    match_server::{
        AnyInMatchServer, InMatchServer as _, MatchIn, MatchOut, MatchOutId, MatchPair,
        OutMatchServer, OutMatchServerTrait as _,
    },
    route::config::OutRuleConfig,
    tunnel::{
        common::{create_rustls_client_config, create_rustls_server_config_and_cert},
        http2::{Http2InTunnel, Http2OutTunnel},
        tunnel_provider::{InTunnelProvider, OutTunnelProvider},
        InTunnel, OutTunnel, TunnelId,
    },
    utils::{
        net::{bind_tcp_listener_reuseaddr, socket::set_keepalive_options},
        stun::probe_external_ip,
    },
};

const TUNNEL_NAME: &str = "plug-http2";

const TLS_NAME: &str = "localhost";

pub struct PlugHttp2InTunnelConfig {
    pub listen_address: SocketAddr,
    pub external_port: Option<u16>,
    pub connections: usize,
    pub priority: Option<i64>,
    pub priority_default: i64,
    pub stun_server_addresses: Vec<SocketAddr>,
    pub traffic_mark: u32,
}

pub struct PlugHttp2InTunnelProvider {
    match_server: Arc<AnyInMatchServer>,
    config: PlugHttp2InTunnelConfig,
    external_port: u16,
    pending_stream: Arc<
        tokio::sync::Mutex<
            Option<(
                TunnelId,
                tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            )>,
        >,
    >,
    cert: String,
    key: String,
    handle: tokio::task::JoinHandle<()>,
}

impl PlugHttp2InTunnelProvider {
    pub async fn new(
        match_server: Arc<AnyInMatchServer>,
        config: PlugHttp2InTunnelConfig,
    ) -> anyhow::Result<Self> {
        let (tls_server_config, cert, key) =
            create_rustls_server_config_and_cert([TLS_NAME.to_owned()]);

        let tls_server_config = Arc::new(tls_server_config);

        let external_port = config
            .external_port
            .unwrap_or_else(|| config.listen_address.port());

        let listener = bind_tcp_listener_reuseaddr(config.listen_address)?;

        let pending_stream = Arc::new(tokio::sync::Mutex::new(None));

        let handle = tokio::spawn({
            let pending_stream = pending_stream.clone();

            async move {
                loop {
                    let stream = match listener.accept().await {
                        Ok((stream, _)) => stream,
                        Err(error) => {
                            log::error!("error accepting plug-http2 socket: {:?}", error);
                            tokio::time::sleep(duration!("1s")).await;
                            continue;
                        }
                    };

                    nix::sys::socket::setsockopt(
                        &stream,
                        nix::sys::socket::sockopt::Mark,
                        &config.traffic_mark,
                    )
                    .unwrap();

                    stream.set_nodelay(true).unwrap();

                    set_keepalive_options(&stream, 5, 5, 3).unwrap();

                    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_server_config.clone());

                    let mut stream = match tls_acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::error!("error accepting plug-http2 TLS stream: {:?}", error);
                            continue;
                        }
                    };

                    let mut tunnel_id_buffer = [0; 16];

                    let tunnel_id = match tokio::time::timeout(
                        duration!("1s"),
                        stream.read_exact(&mut tunnel_id_buffer),
                    )
                    .await
                    {
                        Ok(read_result) => match read_result {
                            Ok(_) => TunnelId::from(tunnel_id_buffer),
                            Err(error) => {
                                log::error!("error reading plug-http2 tunnel id: {:?}", error);
                                continue;
                            }
                        },
                        Err(_) => {
                            log::error!("read timeout for plug-http2 tunnel id");
                            continue;
                        }
                    };

                    pending_stream.lock().await.replace((tunnel_id, stream));
                }
            }
        });

        Ok(Self {
            match_server,
            config,
            external_port,
            pending_stream,
            cert,
            key,
            handle,
        })
    }

    async fn wait_for_pending_stream(
        &self,
        tunnel_id: TunnelId,
    ) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
        loop {
            let Some((pending_tunnel_id, stream)) = self.pending_stream.lock().await.take() else {
                tokio::time::sleep(duration!("100ms")).await;
                continue;
            };

            if pending_tunnel_id == tunnel_id {
                return stream;
            }
        }
    }
}

impl Drop for PlugHttp2InTunnelProvider {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for PlugHttp2InTunnelProvider {
    fn name(&self) -> &'static str {
        TUNNEL_NAME
    }

    async fn accept_out(&self) -> anyhow::Result<(MatchOutId, usize)> {
        self.match_server
            .accept_out::<PlugHttp2InData, PlugHttp2OutData>()
            .await
            .map(|out_id| (out_id, self.config.connections))
    }

    async fn accept(
        &self,
        out_id: MatchOutId,
    ) -> anyhow::Result<Option<(Box<dyn InTunnel>, (Vec<OutRuleConfig>, i64))>> {
        let ip = probe_external_ip(&self.config.stun_server_addresses).await?;

        let Some(MatchOut {
            id,
            tunnel_id,
            tunnel_labels,
            tunnel_priority,
            routing_priority,
            routing_rules,
            data: PlugHttp2OutData {},
        }) = self
            .match_server
            .match_out(
                out_id,
                PlugHttp2InData {
                    address: SocketAddr::new(ip, self.external_port),
                    cert: self.cert.clone(),
                    key: self.key.clone(),
                },
            )
            .await?
        else {
            return Ok(None);
        };

        let stream =
            tokio::time::timeout(duration!("3s"), self.wait_for_pending_stream(tunnel_id)).await?;

        let fd = stream.as_raw_fd();

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
            TUNNEL_NAME,
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

pub struct PlugHttp2OutTunnelConfig {
    pub priority: Option<i64>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
}

pub struct PlugHttp2OutTunnelProvider {
    match_server: Arc<OutMatchServer>,
    config: PlugHttp2OutTunnelConfig,
}

impl PlugHttp2OutTunnelProvider {
    pub fn new(match_server: Arc<OutMatchServer>, config: PlugHttp2OutTunnelConfig) -> Self {
        Self {
            match_server,
            config,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for PlugHttp2OutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let MatchIn {
            id: _,
            tunnel_id,
            data: PlugHttp2InData { address, cert, key },
        } = self
            .match_server
            .match_in(
                PlugHttp2OutData {},
                self.config.priority,
                &self.config.routing_rules,
                self.config.routing_priority,
            )
            .await?;

        let socket = match address {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }?;

        socket.set_nodelay(true)?;

        set_keepalive_options(&socket, 5, 5, 3)?;

        let fd = socket.as_fd().as_raw_fd();

        let stream = socket.connect(address).await?;

        let client_config = {
            let mut client_config = create_rustls_client_config(&cert, &key)?;

            client_config.alpn_protocols = vec![b"h2".to_vec()];

            Arc::new(client_config)
        };

        let tls_connector = tokio_rustls::TlsConnector::from(client_config);

        let mut stream = tls_connector.connect(TLS_NAME.try_into()?, stream).await?;

        stream.write_all(tunnel_id.as_bytes()).await?;

        let connection = h2::server::Builder::new()
            .initial_connection_window_size(4 * 1024 * 1024)
            .initial_window_size(4 * 1024 * 1024)
            .handshake(stream)
            .await?;

        let tunnel = Http2OutTunnel::new(TUNNEL_NAME, tunnel_id, connection, fd);

        log::info!("tunnel {tunnel} established.");

        return Ok(Box::new(tunnel));
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PlugHttp2InData {
    pub address: SocketAddr,
    pub cert: String,
    pub key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PlugHttp2OutData {}

impl MatchPair<PlugHttp2InData, PlugHttp2OutData> for (PlugHttp2InData, PlugHttp2OutData) {
    fn get_match_name() -> &'static str {
        "plug-http2"
    }

    fn get_redis_out_pattern() -> &'static str {
        "plug-http2:out:*"
    }

    fn get_redis_out_key(out_id: &MatchOutId) -> String {
        format!("plug-http2:out:{}", out_id)
    }

    fn get_out_id_from_redis_out_key(out_key: &str) -> anyhow::Result<MatchOutId> {
        out_key
            .split(":")
            .collect_vec()
            .last()
            .map(|out_id| MatchOutId::from_str(out_id))
            .unwrap()
    }

    fn get_redis_in_announcement_channel_name(out_id: &MatchOutId) -> String {
        format!("plug-http2:in:out:{}", out_id)
    }
}
