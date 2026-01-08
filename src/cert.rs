//! Certificate generation utilities for plug2proxy mTLS authentication.
//!
//! This module provides functions to generate:
//! - CA certificates (for HUB to sign and verify node certificates)
//! - Node certificates (for IN/OUT nodes to authenticate to HUB)

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use thiserror::Error;

use x509_parser::prelude::*;

/// Default validity period for CA certificates (99 years).
const CA_VALIDITY_YEARS: i64 = 99;

/// Default validity period for node certificates (10 years).
const NODE_VALIDITY_YEARS: i64 = 10;

#[derive(Error, Debug)]
pub enum CertError {
    #[error("Failed to generate key pair: {0}")]
    KeyGeneration(#[from] rcgen::Error),

    #[error("Failed to read file: {0}")]
    FileRead(#[from] std::io::Error),

    #[error("Failed to parse certificate: {0}")]
    CertParse(String),
}

/// Generated certificate and key pair.
pub struct GeneratedCert {
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

impl GeneratedCert {
    /// Get combined PEM (certificate + private key in one string).
    pub fn combined_pem(&self) -> String {
        format!("{}{}", self.cert_pem, self.key_pem)
    }

    /// Get combined PEM with CA certificate appended (for node certs).
    /// Result: node cert + node key + CA cert
    pub fn combined_pem_with_ca(&self, ca_cert_pem: &str) -> String {
        format!("{}{}{}", self.cert_pem, self.key_pem, ca_cert_pem)
    }

    /// Write combined certificate and key to a single PEM file.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::write(path, self.combined_pem())?;
        Ok(())
    }

    /// Write combined certificate, key, and CA certificate to a single PEM file.
    pub fn write_to_file_with_ca(
        &self,
        path: impl AsRef<Path>,
        ca_cert_pem: &str,
    ) -> std::io::Result<()> {
        std::fs::write(path, self.combined_pem_with_ca(ca_cert_pem))?;
        Ok(())
    }

    /// Write the certificate and key to separate files.
    pub fn write_to_files(
        &self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> std::io::Result<()> {
        std::fs::write(cert_path, &self.cert_pem)?;
        std::fs::write(key_path, &self.key_pem)?;
        Ok(())
    }
}

/// Generate a self-signed CA certificate.
///
/// This certificate is used by HUB to:
/// - Sign certificates for IN/OUT nodes
/// - Verify client certificates during mTLS handshake
pub fn generate_ca(common_name: &str) -> Result<GeneratedCert, CertError> {
    let mut params = CertificateParams::default();

    // Set distinguished name
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "plug2proxy");

    // Set validity period
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + ::time::Duration::days(CA_VALIDITY_YEARS * 365);

    // Mark as CA certificate
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // Set key usage for CA
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Generate key pair
    let key_pair = KeyPair::generate()?;

    // Self-sign the certificate
    let cert = params.self_signed(&key_pair)?;

    Ok(GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// Generate a node certificate signed by a CA.
///
/// This certificate is used by IN/OUT nodes to authenticate to HUB,
/// and by HUB as its server certificate.
///
/// # Arguments
/// * `common_name` - The node identifier (e.g., "hub-main", "in-home", "out-us")
/// * `ca_cert_pem` - PEM-encoded CA certificate
/// * `ca_key_pem` - PEM-encoded CA private key
/// * `is_server` - Whether this is a server certificate (for HUB) or client certificate (for IN/OUT)
pub fn generate_node_cert(
    common_name: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    is_server: bool,
) -> Result<GeneratedCert, CertError> {
    // Parse CA certificate and key
    let ca_key_pair = KeyPair::from_pem(ca_key_pem)?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let ca_cert = ca_cert_params.self_signed(&ca_key_pair)?;

    // Create node certificate parameters
    let mut params = CertificateParams::default();

    // Set distinguished name
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "plug2proxy");

    // Set validity period
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + ::time::Duration::days(NODE_VALIDITY_YEARS * 365);

    // Not a CA
    params.is_ca = IsCa::NoCa;

    // Set key usage
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    // Set extended key usage based on certificate type
    if is_server {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Add localhost and common name as subject alternative names for server cert
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(
                common_name
                    .try_into()
                    .unwrap_or_else(|_| "localhost".try_into().unwrap()),
            ),
            rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        ];
    } else {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    }

    // Generate key pair for the node
    let key_pair = KeyPair::generate()?;

    // Sign with CA
    let cert = params.signed_by(&key_pair, &ca_cert, &ca_key_pair)?;

    Ok(GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// Load CA certificate and key from a combined PEM file.
///
/// The PEM file should contain both the certificate and private key.
pub fn load_ca_from_pem(path: impl AsRef<Path>) -> Result<(String, String), CertError> {
    let content = std::fs::read_to_string(path)?;
    split_pem(&content)
}

/// Load CA certificate and key from separate files.
pub fn load_ca_from_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(String, String), CertError> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;
    Ok((cert_pem, key_pem))
}

/// Split a combined PEM into certificate and key parts.
fn split_pem(content: &str) -> Result<(String, String), CertError> {
    let cert_start = content
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| CertError::CertParse("No certificate found in PEM".to_string()))?;
    let cert_end = content
        .find("-----END CERTIFICATE-----")
        .ok_or_else(|| CertError::CertParse("No certificate end found in PEM".to_string()))?
        + "-----END CERTIFICATE-----".len();

    let key_start = content
        .find("-----BEGIN PRIVATE KEY-----")
        .ok_or_else(|| CertError::CertParse("No private key found in PEM".to_string()))?;
    let key_end = content
        .find("-----END PRIVATE KEY-----")
        .ok_or_else(|| CertError::CertParse("No private key end found in PEM".to_string()))?
        + "-----END PRIVATE KEY-----".len();

    let cert_pem = content[cert_start..cert_end].to_string() + "\n";
    let key_pem = content[key_start..key_end].to_string() + "\n";

    Ok((cert_pem, key_pem))
}

/// Extract the Common Name (CN) from a DER-encoded X.509 certificate.
///
/// Returns the first CN found in the subject, or None if no CN is present.
pub fn extract_common_name(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let ca = generate_ca("test-ca").unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_node_cert() {
        let ca = generate_ca("test-ca").unwrap();

        // Generate server cert
        let server = generate_node_cert("hub-main", &ca.cert_pem, &ca.key_pem, true).unwrap();
        assert!(server.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(server.key_pem.contains("BEGIN PRIVATE KEY"));

        // Generate client cert
        let client = generate_node_cert("out-us", &ca.cert_pem, &ca.key_pem, false).unwrap();
        assert!(client.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(client.key_pem.contains("BEGIN PRIVATE KEY"));
    }
}
