use std::{net::UdpSocket, sync::Arc, time::Duration};

use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TokioRuntime,
    TransportConfig, VarInt,
};

pub fn create_server_endpoint(
    socket: UdpSocket,
    server_config: Arc<QuicServerConfig>,
) -> anyhow::Result<Endpoint> {
    let server_config = {
        let mut server_config = ServerConfig::with_crypto(server_config);

        server_config.transport_config(Arc::new(create_transport_config()));

        server_config
    };

    Ok(Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )?)
}

pub fn create_client_endpoint(
    socket: UdpSocket,
    client_config: rustls::ClientConfig,
) -> anyhow::Result<Endpoint> {
    let client_config = {
        let client_config = Arc::new(QuicClientConfig::try_from(client_config).unwrap());

        let mut client_config = ClientConfig::new(client_config);

        client_config.transport_config(Arc::new(create_transport_config()));

        client_config
    };

    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )?;

    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

fn create_transport_config() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config
        .max_concurrent_bidi_streams(VarInt::from_u32(1024))
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
        ));

    transport_config
}
