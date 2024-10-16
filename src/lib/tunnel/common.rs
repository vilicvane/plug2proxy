use std::sync::Arc;

use itertools::Itertools;
use rustls::pki_types::pem::PemObject as _;

use super::TunnelId;

pub fn get_tunnel_string(r#type: &'static str, id: TunnelId, labels: &[String]) -> String {
    let id_short = &id.0.as_bytes()[..4]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .join("");

    let name = format!("{} {id_short}", r#type);

    if labels.is_empty() {
        name
    } else {
        format!("{} ({})", name, labels.join(","))
    }
}

pub fn create_rustls_client_config(
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<rustls::ClientConfig> {
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid cert."))?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid key."))?;

    let mut root_store = rustls::RootCertStore::empty();

    root_store.add(cert.clone())?;

    let cert_chain = vec![cert];

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key)?;

    Ok(client_config)
}

pub fn create_rustls_server_config_and_cert(
    cert_names: impl Into<Vec<String>>,
) -> (rustls::ServerConfig, String, String) {
    let cert = rcgen::generate_simple_self_signed(cert_names).unwrap();

    let cert_chain = vec![cert.cert.der().clone()];
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let root_store = {
        let mut root_store = rustls::RootCertStore::empty();

        let cert = rustls::pki_types::CertificateDer::from_slice(cert.cert.der());

        root_store.add(cert).unwrap();

        root_store
    };

    let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    let server_config =
        rustls::ServerConfig::builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(cert_chain, key.into())
            .unwrap();

    let key = cert.key_pair.serialize_pem();
    let cert = cert.cert.pem();

    (server_config, cert, key)
}
