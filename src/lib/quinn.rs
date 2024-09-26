use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use quinn::{
    crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, EndpointConfig, IdleTimeout,
    ServerConfig, TokioRuntime, TransportConfig, VarInt,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const KEEPALIVE_INTERVAL_PERIOD_MILLIS: u64 = 1000;
pub const MAX_IDLE_TIMEOUT_MILLIS: u32 = 4000;

pub fn make_endpoint(socket: tokio::net::UdpSocket, being_server: bool) -> io::Result<Endpoint> {
    let runtime = Arc::new(TokioRuntime);

    let (client_config, server_config) = if being_server {
        (None, Some(configure_server().0))
    } else {
        (Some(configure_client()), None)
    };

    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        server_config,
        socket.into_std()?,
        runtime,
    )?;

    if let Some(client_config) = client_config {
        endpoint.set_default_client_config(client_config);
    }

    Ok(endpoint)
}

pub fn configure_client() -> ClientConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let crypto = Arc::new(QuicClientConfig::try_from(crypto).unwrap());

    ClientConfig::new(crypto)
}

pub fn configure_server<'a>() -> (ServerConfig, CertificateDer<'a>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![cert_der.clone()], key.into()).unwrap();
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    (server_config, cert_der)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
