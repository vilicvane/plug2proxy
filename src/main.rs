use anyhow::Context;
use clap::Parser;
use colored::Colorize;
use plug2proxy::{
  cert::generate_node_pem_file,
  hub::{HubConfig, run_hub},
  out::{OutConfig, run_out},
};
use serde::Deserialize;
use tokio::fs::read_to_string;

#[derive(Debug, Parser)]
struct Args {
  #[arg(long)]
  node_cert: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Config {
  #[serde(rename = "hub")]
  Hub(HubConfig),
  #[serde(rename = "out")]
  Out(OutConfig),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    .format_timestamp(None)
    .format_target(false)
    .init();

  let Args {
    node_cert: node_cert_common_name,
  } = Args::parse();

  if let Some(node_cert_common_name) = node_cert_common_name {
    generate_node_cert(node_cert_common_name).await?;
    return Ok(());
  } else {
    let config = serde_yaml::from_str::<Config>(&read_to_string("config.yaml").await.context(
      format!("failed to read config file {}.", "config.yaml".yellow()),
    )?)?;

    match config {
      Config::Hub(hub_config) => {
        run_hub("", hub_config).await?;
      }
      Config::Out(out_config) => {
        run_out("", out_config).await?;
      }
    }
  }

  Ok(())
}

#[allow(clippy::disallowed_macros)]
async fn generate_node_cert(node_cert_common_name: String) -> anyhow::Result<()> {
  let path = generate_node_pem_file("", &node_cert_common_name, true).await?;

  println!(
    "Node PEM file generated as {}.",
    path.to_str().unwrap().yellow()
  );
  println!(
    "{}",
    format!(
      "> Please copy this file to node's working directory that contains {}.",
      "config.yaml".yellow()
    )
    .dimmed()
  );

  Ok(())
}
