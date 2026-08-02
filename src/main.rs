use anyhow::Context;
use clap::{Parser, Subcommand};
use colored::Colorize;
use plug2proxy::{
  cert::generate_node_pem_file,
  hub::{HubConfig, run_hub},
  r#in::{InConfig, run_in},
  inbound::{
    TproxyInboundConfig, TproxyNetworkPlan, apply_tproxy_network, check_tproxy_network,
    remove_tproxy_network, resolve_bypass_user, tproxy_network_status,
  },
  out::{OutConfig, run_out},
};
use serde::Deserialize;
use tokio::fs::read_to_string;

const CONFIG_FILE: &str = "config.json";

#[derive(Debug, Parser)]
struct Args {
  #[arg(long)]
  node_cert: Option<String>,
  #[arg(long, default_value = CONFIG_FILE)]
  config: std::path::PathBuf,
  #[command(subcommand)]
  command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
  /// Validate, install, inspect, or remove the Linux TPROXY network state.
  Network {
    #[command(subcommand)]
    action: NetworkAction,
  },
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum NetworkAction {
  /// Render the generated nftables transaction without applying it.
  Render,
  /// Validate ownership, conflicts, and generated rules without changing the host.
  Check,
  /// Idempotently install policy routing and nftables state.
  Apply,
  /// Re-apply the desired state after an external ruleset reload.
  Reconcile,
  /// Remove only network objects owned by Plug2Proxy.
  Remove,
  /// Inspect whether the owned network objects are present.
  Status,
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
    config: config_path,
    command,
  } = Args::parse();

  if node_cert_common_name.is_some() && command.is_some() {
    anyhow::bail!("--node-cert cannot be combined with a subcommand");
  }

  if let Some(Command::Network { action }) = command {
    run_network_action(&config_path, action).await?;
    return Ok(());
  } else if let Some(node_cert_common_name) = node_cert_common_name {
    generate_node_cert(node_cert_common_name).await?;
    return Ok(());
  } else {
    let config_source = read_to_string(&config_path).await.with_context(|| {
      format!(
        "failed to read config file {}.",
        config_path.display().to_string().yellow()
      )
    })?;
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

impl Config {
  fn tproxy(&self) -> Option<&TproxyInboundConfig> {
    match self {
      Config::Hub(config) => config.inbounds.as_ref()?.tproxy.as_ref(),
      Config::In(config) => config.inbounds.as_ref()?.tproxy.as_ref(),
      Config::Out(_) => None,
    }
  }

  fn dns_listen(&self) -> Option<std::net::SocketAddr> {
    match self {
      Config::Hub(config) => config.dns.as_ref().map(|dns| *dns.listen),
      Config::In(config) => config.dns.as_ref().map(|dns| *dns.listen),
      Config::Out(_) => None,
    }
  }
}

#[allow(clippy::disallowed_macros)]
async fn run_network_action(
  config_path: &std::path::Path,
  action: NetworkAction,
) -> anyhow::Result<()> {
  match action {
    NetworkAction::Remove => {
      remove_tproxy_network().await?;
      return Ok(());
    }
    NetworkAction::Status => {
      println!("{}", tproxy_network_status().await?);
      return Ok(());
    }
    _ => {}
  }

  let config_source = if matches!(action, NetworkAction::Apply | NetworkAction::Reconcile) {
    read_privileged_config(config_path)?
  } else {
    read_to_string(config_path)
      .await
      .with_context(|| format!("failed to read config file {}", config_path.display()))?
  };
  let config = parse_config(config_source)?;
  let dns_listen = config.dns_listen();
  let tproxy = config
    .tproxy()
    .context("configuration does not contain an inbounds.tproxy section")?;
  let bypass_uid = resolve_bypass_user(&tproxy.network.bypass_user).await?;
  let plan = TproxyNetworkPlan::from_config(tproxy, dns_listen, bypass_uid)?;

  match action {
    NetworkAction::Render => print!("{}", plan.render_nft_batch()),
    NetworkAction::Check => println!("{}", check_tproxy_network(&plan).await?),
    NetworkAction::Apply | NetworkAction::Reconcile => apply_tproxy_network(&plan).await?,
    NetworkAction::Remove | NetworkAction::Status => unreachable!(),
  }
  Ok(())
}

#[cfg(target_os = "linux")]
fn read_privileged_config(path: &std::path::Path) -> anyhow::Result<String> {
  use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
  };

  if !path.is_absolute() {
    anyhow::bail!(
      "privileged network actions require an absolute config path, got {}",
      path.display()
    );
  }

  let parent = path
    .parent()
    .context("privileged network config has no parent directory")?;
  for directory in parent.ancestors() {
    let metadata = std::fs::symlink_metadata(directory).with_context(|| {
      format!(
        "failed to inspect privileged config directory {}",
        directory.display()
      )
    })?;
    if !metadata.is_dir()
      || metadata.file_type().is_symlink()
      || metadata.uid() != 0
      || metadata.mode() & 0o022 != 0
    {
      anyhow::bail!(
        "privileged config directory {} and every ancestor must be root-owned, non-writable by group/other, and not a symlink",
        directory.display()
      );
    }
  }

  let mut file = std::fs::OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(path)
    .with_context(|| format!("failed to open privileged config {}", path.display()))?;
  let metadata = file.metadata()?;
  if !metadata.is_file() || metadata.uid() != 0 {
    anyhow::bail!(
      "privileged network config {} must be a root-owned regular file, not a symlink",
      path.display()
    );
  }
  if metadata.mode() & 0o022 != 0 {
    anyhow::bail!(
      "privileged network config {} must not be writable by group or other users",
      path.display()
    );
  }

  let mut source = String::new();
  file
    .read_to_string(&mut source)
    .with_context(|| format!("failed to read privileged config {}", path.display()))?;
  Ok(source)
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
