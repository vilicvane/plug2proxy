use std::{net::SocketAddr, sync::Arc};

use quinn::crypto::rustls::QuicServerConfig;

use crate::{
    match_server::{
        AnyInMatchServer, InMatchServer as _, MatchIn, MatchOut, MatchOutId, OutMatchServer,
        OutMatchServerTrait as _,
    },
    route::config::OutRuleConfig,
    tunnel::{
        byte_stream_tunnel::{ByteStreamInTunnel, ByteStreamOutTunnel},
        common::{create_rustls_client_config, create_rustls_server_config_and_cert},
        tunnel_provider::{InTunnelProvider, OutTunnelProvider},
        InTunnel, OutTunnel,
    },
    utils::{net::get_any_address, stun::probe_external_ip},
};

use super::{
    match_pair::{QuicInData, QuicOutData},
    quinn::{create_client_endpoint, create_server_endpoint},
    QuicInTunnelConnection, QuicOutTunnelConnection,
};

const TUNNEL_NAME: &str = "quic";

const TLS_NAME: &str = "localhost";

pub struct QuicInTunnelConfig {
    pub priority: Option<i64>,
    pub priority_default: i64,
    pub stun_server_addresses: Vec<SocketAddr>,
    pub traffic_mark: u32,
}

pub struct QuicInTunnelProvider {
    match_server: Arc<AnyInMatchServer>,
    config: QuicInTunnelConfig,
}

impl QuicInTunnelProvider {
    pub fn new(match_server: Arc<AnyInMatchServer>, config: QuicInTunnelConfig) -> Self {
        Self {
            match_server,
            config,
        }
    }
}

#[async_trait::async_trait]
impl InTunnelProvider for QuicInTunnelProvider {
    fn name(&self) -> &'static str {
        TUNNEL_NAME
    }

    async fn accept_out(&self) -> anyhow::Result<(MatchOutId, usize)> {
        self.match_server
            .accept_out::<QuicInData, QuicOutData>()
            .await
            .map(|out_id| (out_id, 1))
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
            data: QuicOutData { address, cert, key },
        }) = self.match_server.match_out(out_id, QuicInData {}).await?
        else {
            return Ok(None);
        };

        let socket = std::net::UdpSocket::bind(get_any_address(&address))?;

        let client_config = create_rustls_client_config(&cert, &key)?;

        let endpoint = create_client_endpoint(socket, client_config)?;

        let connection = endpoint.connect(address, TLS_NAME)?.await?;

        let tunnel = ByteStreamInTunnel::new(
            TUNNEL_NAME,
            tunnel_id,
            id,
            tunnel_labels,
            self.config
                .priority
                .unwrap_or(tunnel_priority.unwrap_or(self.config.priority_default)),
            QuicInTunnelConnection::new(connection),
        );

        log::info!("tunnel {tunnel} established.");

        return Ok(Some((Box::new(tunnel), (routing_rules, routing_priority))));
    }
}

pub struct QuicOutTunnelConfig {
    pub priority: Option<i64>,
    pub stun_server_addresses: Vec<SocketAddr>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
}

pub struct QuicOutTunnelProvider {
    match_server: Arc<OutMatchServer>,
    server_config: Arc<QuicServerConfig>,
    cert: String,
    key: String,
    config: QuicOutTunnelConfig,
}

impl QuicOutTunnelProvider {
    pub fn new(match_server: Arc<OutMatchServer>, config: QuicOutTunnelConfig) -> Self {
        let (server_config, cert, key) =
            create_rustls_server_config_and_cert([TLS_NAME.to_owned()]);

        Self {
            match_server,
            server_config: Arc::new(QuicServerConfig::try_from(server_config).unwrap()),
            cert,
            key,
            config,
        }
    }
}

#[async_trait::async_trait]
impl OutTunnelProvider for QuicOutTunnelProvider {
    async fn accept(&self) -> anyhow::Result<Box<dyn OutTunnel>> {
        let ip = probe_external_ip(&self.config.stun_server_addresses).await?;

        let socket = tokio::net::UdpSocket::bind("0:0").await?;

        let external_address = SocketAddr::new(ip, socket.local_addr()?.port());

        let MatchIn {
            id: _,
            tunnel_id,
            data: QuicInData {},
        } = self
            .match_server
            .match_in(
                QuicOutData {
                    address: external_address,
                    cert: self.cert.clone(),
                    key: self.key.clone(),
                },
                self.config.priority,
                &self.config.routing_rules,
                self.config.routing_priority,
            )
            .await?;

        let endpoint = create_server_endpoint(socket.into_std()?, self.server_config.clone())?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("incoming not available"))?;

        let connection = incoming.accept()?.await?;

        let tunnel = ByteStreamOutTunnel::new(
            TUNNEL_NAME,
            tunnel_id,
            QuicOutTunnelConnection::new(connection),
        );

        log::info!("tunnel {tunnel} established.");

        return Ok(Box::new(tunnel));
    }
}
