use anyhow::Context;
use clap::Parser;
use colored::Colorize;
use plug2proxy::{
  cert::generate_node_pem_file,
  hub::{HubConfig, run_hub},
  r#in::{InConfig, run_in},
  out::{OutConfig, run_out},
};
use serde::Deserialize;
use tokio::fs::read_to_string;

const CONFIG_FILE: &str = "config.json";

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
  #[serde(rename = "in")]
  In(InConfig),
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
    let config_source = read_to_string(CONFIG_FILE)
      .await
      .with_context(|| format!("failed to read config file {}.", CONFIG_FILE.yellow()))?;
    let config = parse_config(config_source)?;

    match config {
      Config::Hub(hub_config) => {
        run_hub("", hub_config).await?;
      }
      Config::Out(out_config) => {
        run_out("", out_config).await?;
      }
      Config::In(in_config) => {
        run_in("", in_config).await?;
      }
    }
  }

  Ok(())
}

fn parse_config(mut source: String) -> anyhow::Result<Config> {
  json_strip_comments::strip(&mut source).context("failed to strip JSONC comments")?;

  serde_json::from_str(&source).context("failed to parse JSONC config")
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
      CONFIG_FILE.yellow()
    )
    .dimmed()
  );

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_jsonc_comments_and_trailing_commas() {
    let config = parse_config(
      r#"{
        // Comments and trailing commas are accepted.
        "type": "hub",
        "listen": "127.0.0.1:1122",
        /*
         * Comment markers inside strings must remain untouched.
         */
        "inbounds": {
          "socks5": {
            "listen": "127.0.0.1:1080",
          },
        },
      }"#
        .to_owned(),
    )
    .unwrap();

    let Config::Hub(config) = config else {
      panic!("expected HUB config");
    };

    assert_eq!(config.listen.to_string(), "127.0.0.1:1122");
    assert!(config.inbounds.is_some());
  }

  #[test]
  fn parses_recommended_configuration_examples() {
    let documentation = include_str!("../docs/configuration.md");
    let mut parsed = 0;

    for (index, section) in documentation.split("```jsonc\n").skip(1).enumerate() {
      let (source, _) = section
        .split_once("\n```")
        .unwrap_or_else(|| panic!("JSONC block {} is not closed", index + 1));

      // Some blocks intentionally show one field rather than a full config.
      if !source.trim_start().starts_with('{') {
        continue;
      }

      parse_config(source.to_owned())
        .unwrap_or_else(|error| panic!("invalid config JSONC block {}: {error:#}", index + 1));
      parsed += 1;
    }

    assert_eq!(parsed, 5, "unexpected number of complete config examples");
  }
}
