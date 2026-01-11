use std::path::{Path, PathBuf};

use lits::duration;
use rcgen::{
  BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
  KeyUsagePurpose,
};

use crate::constants::{ORGANIZATION_NAME, SERVER_COMMON_NAME};

pub const CA_COMMON_NAME: &str = "Plug2Proxy CA";

const CA_PEM_FILE_NAME: &str = "ca.pem";
const NODE_PEM_FILE_NAME: &str = "node.pem";

pub async fn generate_ca_pem_file(dir: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
  let dir = dir.as_ref();

  tokio::fs::create_dir_all(dir).await?;

  let mut params = CertificateParams::default();

  params
    .distinguished_name
    .push(DnType::CommonName, CA_COMMON_NAME);
  params
    .distinguished_name
    .push(DnType::OrganizationName, ORGANIZATION_NAME);

  let now = time::OffsetDateTime::now_utc();

  params.not_before = now;
  params.not_after = now + duration!("100 years");

  params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

  params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

  let key_pair = KeyPair::generate()?;

  let cert = params.self_signed(&key_pair)?;

  let pem_file_path = dir.join(CA_PEM_FILE_NAME);

  tokio::fs::write(
    &pem_file_path,
    [cert.pem(), key_pair.serialize_pem()].join("\n"),
  )
  .await?;

  Ok(pem_file_path)
}

pub async fn generate_node_pem_file(
  dir: impl AsRef<Path>,
  common_name: &str,
) -> anyhow::Result<PathBuf> {
  let dir = dir.as_ref();
  let node_dir = dir.join(common_name);

  tokio::fs::create_dir_all(&node_dir).await?;

  let ca_pems = pem::parse_many(tokio::fs::read_to_string(dir.join(CA_PEM_FILE_NAME)).await?)?;

  let ca_cert_pem = ca_pems
    .iter()
    .find(|p| p.tag() == "CERTIFICATE")
    .ok_or(anyhow::anyhow!("CERTIFICATE not found"))?
    .to_string();

  let ca_key_pem = ca_pems
    .iter()
    .find(|p| p.tag() == "PRIVATE KEY")
    .ok_or(anyhow::anyhow!("PRIVATE KEY not found"))?
    .to_string();

  let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;
  let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair)?;

  let mut params = CertificateParams::default();

  params
    .distinguished_name
    .push(DnType::OrganizationName, ORGANIZATION_NAME);

  params
    .distinguished_name
    .push(DnType::CommonName, common_name);

  let now = time::OffsetDateTime::now_utc();

  params.not_before = now;
  params.not_after = now + duration!("100 years");

  params.is_ca = IsCa::NoCa;

  params.key_usages = vec![
    KeyUsagePurpose::DigitalSignature,
    KeyUsagePurpose::KeyEncipherment,
  ];

  params.extended_key_usages = vec![
    ExtendedKeyUsagePurpose::ServerAuth,
    ExtendedKeyUsagePurpose::ClientAuth,
  ];
  params.subject_alt_names = vec![rcgen::SanType::DnsName(SERVER_COMMON_NAME.try_into()?)];

  let node_key_pair = KeyPair::generate()?;

  let node_cert = params.signed_by(&node_key_pair, &issuer)?;

  let node_pem_file_path = node_dir.join(NODE_PEM_FILE_NAME);

  tokio::fs::write(
    &node_pem_file_path,
    [node_cert.pem(), node_key_pair.serialize_pem(), ca_cert_pem].join("\n"),
  )
  .await?;

  Ok(node_pem_file_path)
}
