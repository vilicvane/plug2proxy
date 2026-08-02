use std::{
  collections::BTreeSet,
  fs::File,
  io::{Read, Write},
  net::{IpAddr, SocketAddr},
  os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
  },
  path::Path,
  process::Output,
  time::Duration,
};

use anyhow::{Context, bail};
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

use crate::inbound::{
  TPROXY_BYPASS_MARK, TPROXY_MARK_MASK, TPROXY_OUTPUT_ROUTE_MARK, TPROXY_PREROUTING_ROUTE_MARK,
  TproxyInboundConfig,
};

const NFT: &str = "/usr/sbin/nft";
const IP: &str = "/usr/sbin/ip";
const ID: &str = "/usr/bin/id";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const DATA_PLANE_READY_TIMEOUT: Duration = Duration::from_secs(10);
const DATA_PLANE_READY_RETRY: Duration = Duration::from_millis(50);
const NETWORK_LOCK_TIMEOUT: Duration = Duration::from_secs(240);
const NETWORK_LOCK_RETRY: Duration = Duration::from_millis(50);

pub const TPROXY_NFT_FAMILY: &str = "inet";
pub const TPROXY_NFT_TABLE: &str = "plug2proxy_tproxy";
const LEGACY_TPROXY_NFT_SENTINEL: &str = "managed-by=plug2proxy;schema=1";
pub const TPROXY_NFT_SENTINEL: &str = "managed-by=plug2proxy;schema=2";
pub const TPROXY_ROUTE_TABLE: u32 = 20230;
pub const TPROXY_SOURCE_VALIDATION_RULE_PRIORITY: u32 = 98;
pub const TPROXY_PREROUTING_RULE_PRIORITY: u32 = 99;
pub const TPROXY_OUTPUT_RULE_PRIORITY: u32 = 100;

const STATE_DIRECTORY: &str = "/run/plug2proxy-netctl";
const STATE_FILE: &str = "/run/plug2proxy-netctl/network-state.json";
const NETWORK_LOCK_FILE: &str = "/run/plug2proxy-netctl/network.lock";

const BUILTIN_EXCLUDES: [&str; 5] = [
  "0.0.0.0/8",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "224.0.0.0/4",
  "240.0.0.0/4",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TproxyNetworkPlan {
  pub listen: SocketAddr,
  #[serde(default)]
  pub dns_listen: Option<SocketAddr>,
  pub bypass_uid: u32,
  pub exclude_ipv4: Vec<Ipv4Net>,
}

impl TproxyNetworkPlan {
  pub fn from_config(
    config: &TproxyInboundConfig,
    dns_listen: Option<SocketAddr>,
    bypass_uid: u32,
  ) -> anyhow::Result<Self> {
    let listen: SocketAddr = *config.listen;
    if !listen.is_ipv4() {
      bail!("TPROXY network management currently supports IPv4 listeners only");
    }
    if !listen.ip().is_loopback() {
      bail!("TPROXY listener must use an IPv4 loopback address");
    }

    let mut excludes = BTreeSet::new();
    for network in BUILTIN_EXCLUDES {
      excludes.insert(network.parse::<Ipv4Net>().unwrap().trunc());
    }
    for network in &config.network.exclude_ipv4 {
      match **network {
        IpNet::V4(network) => {
          excludes.insert(network.trunc());
        }
        IpNet::V6(network) => {
          bail!("TPROXY IPv4 exclude list contains IPv6 network {network}");
        }
      }
    }

    let networks = excludes.into_iter().collect::<Vec<_>>();
    let exclude_ipv4 = networks
      .iter()
      .copied()
      .filter(|candidate| {
        !networks.iter().any(|other| {
          other != candidate
            && other.prefix_len() <= candidate.prefix_len()
            && other.contains(&candidate.network())
        })
      })
      .collect();

    Ok(Self {
      listen,
      dns_listen,
      bypass_uid,
      exclude_ipv4,
    })
  }

  pub fn render_nft_batch(&self) -> String {
    self.render_nft_batch_for(NftState::Exact)
  }

  fn render_nft_batch_for(&self, previous: NftState) -> String {
    self.render_nft_batch_with_marks(previous, TPROXY_NFT_SENTINEL, TPROXY_PREROUTING_ROUTE_MARK)
  }

  fn render_legacy_nft_batch(&self) -> String {
    self.render_nft_batch_with_marks(
      NftState::Exact,
      LEGACY_TPROXY_NFT_SENTINEL,
      TPROXY_OUTPUT_ROUTE_MARK,
    )
  }

  fn render_nft_batch_with_marks(
    &self,
    previous: NftState,
    sentinel: &str,
    prerouting_mark: u32,
  ) -> String {
    let excluded = self
      .exclude_ipv4
      .iter()
      .map(ToString::to_string)
      .collect::<Vec<_>>()
      .join(", ");
    let port = self.listen.port();
    let listen_ip = self.listen.ip();
    let keep_mask = !TPROXY_MARK_MASK;
    let prepare_table = match previous {
      NftState::Absent => format!(
        "create table {TPROXY_NFT_FAMILY} {TPROXY_NFT_TABLE} {{ comment \"{sentinel}\"; }}\n"
      ),
      NftState::Legacy | NftState::Exact => {
        // `delete` followed by the table declaration is one atomic nft batch.
        // Unlike `destroy`, it also works with nftables 1.0.9 and older kernels;
        // the caller has already proved that this owned table exists.
        format!("delete table {TPROXY_NFT_FAMILY} {TPROXY_NFT_TABLE}\n")
      }
    };
    let split_route_marks = prerouting_mark != TPROXY_OUTPUT_ROUTE_MARK;
    let premarked_prerouting_rules = if split_route_marks {
      format!(
        r#"    meta l4proto {{ tcp, udp }} meta mark & {mark_mask:#010x} == {output_mark:#010x} iifname "lo" tproxy ip to {listen_ip}:{port} counter accept
    meta l4proto {{ tcp, udp }} meta mark & {mark_mask:#010x} == {output_mark:#010x} ct mark set (ct mark & {keep_mask:#010x}) | {prerouting_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {prerouting_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept
    meta l4proto {{ tcp, udp }} meta mark & {mark_mask:#010x} == {prerouting_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept"#,
        mark_mask = TPROXY_MARK_MASK,
        output_mark = TPROXY_OUTPUT_ROUTE_MARK,
      )
    } else {
      format!(
        "    meta l4proto {{ tcp, udp }} meta mark & {:#010x} == {:#010x} tproxy ip to {listen_ip}:{port} counter accept",
        TPROXY_MARK_MASK, TPROXY_OUTPUT_ROUTE_MARK
      )
    };
    let conntrack_prerouting_rules = if split_route_marks {
      format!(
        r#"    meta l4proto {{ tcp, udp }} ct mark & {mark_mask:#010x} == {output_mark:#010x} iifname "lo" meta mark set (meta mark & {keep_mask:#010x}) | {output_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept
    meta l4proto {{ tcp, udp }} ct mark & {mark_mask:#010x} == {output_mark:#010x} ct mark set (ct mark & {keep_mask:#010x}) | {prerouting_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {prerouting_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept
    meta l4proto {{ tcp, udp }} ct mark & {mark_mask:#010x} == {prerouting_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {prerouting_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept"#,
        mark_mask = TPROXY_MARK_MASK,
        output_mark = TPROXY_OUTPUT_ROUTE_MARK,
      )
    } else {
      format!(
        "    meta l4proto {{ tcp, udp }} ct mark & {:#010x} == {:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {:#010x} tproxy ip to {listen_ip}:{port} counter accept",
        TPROXY_MARK_MASK, TPROXY_OUTPUT_ROUTE_MARK, TPROXY_OUTPUT_ROUTE_MARK
      )
    };

    // Interception is deliberately flow-stateful. Only the first, still
    // unconfirmed packet of a new TCP/UDP conntrack entry receives our mark;
    // later packets copy it to the packet mark. Entries confirmed before
    // activation remain unmarked, so installing the table cannot splice an
    // existing local or forwarded connection into TPROXY halfway through.
    format!(
      r#"{prepare_table}table {family} {table} {{
  comment "{sentinel}"

  set bypass4 {{
    type ipv4_addr
    flags interval
    elements = {{ {excluded} }}
  }}

  chain output {{
    type route hook output priority mangle; policy accept;
    meta nfproto != ipv4 return
    meta l4proto != {{ tcp, udp }} return
    ct direction reply counter return
    meta mark & {mark_mask:#010x} == {bypass_mark:#010x} counter return
    meta mark & 0x00ff0000 == 0x00080000 counter return
    meta mark != 0 counter return
    ct mark & {mark_mask:#010x} == {output_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {output_mark:#010x} counter return
    ct mark != 0 counter return
    ct status confirmed counter return
    fib daddr type local return
    fib daddr type broadcast return
    fib daddr type multicast return
    ip daddr @bypass4 return
    meta skuid {uid} counter return
    meta l4proto tcp ct state new tcp flags & (fin | syn | rst | ack) == syn ct mark set (ct mark & {keep_mask:#010x}) | {output_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {output_mark:#010x} counter
    meta l4proto udp ct state new ct mark set (ct mark & {keep_mask:#010x}) | {output_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {output_mark:#010x} counter
  }}

  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    meta nfproto != ipv4 return
    meta l4proto != {{ tcp, udp }} return
    meta mark & {mark_mask:#010x} == {bypass_mark:#010x} counter return
    ct direction reply counter return
{premarked_prerouting_rules}
{conntrack_prerouting_rules}
    meta mark & {mark_mask:#010x} != 0 counter return
    ct mark & {mark_mask:#010x} != 0 counter return
    ct status confirmed counter return
    fib daddr type local return
    fib daddr type broadcast return
    fib daddr type multicast return
    ip daddr @bypass4 return
    meta l4proto tcp socket transparent 1 socket wildcard 0 meta mark set (meta mark & {keep_mask:#010x}) | {prerouting_mark:#010x} counter accept
    meta l4proto tcp ct state new tcp flags & (fin | syn | rst | ack) == syn ct mark set (ct mark & {keep_mask:#010x}) | {prerouting_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {prerouting_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept
    meta l4proto udp ct state new ct mark set (ct mark & {keep_mask:#010x}) | {prerouting_mark:#010x} meta mark set (meta mark & {keep_mask:#010x}) | {prerouting_mark:#010x} tproxy ip to {listen_ip}:{port} counter accept
  }}
}}
"#,
      family = TPROXY_NFT_FAMILY,
      table = TPROXY_NFT_TABLE,
      sentinel = sentinel,
      uid = self.bypass_uid,
      mark_mask = TPROXY_MARK_MASK,
      bypass_mark = TPROXY_BYPASS_MARK,
      output_mark = TPROXY_OUTPUT_ROUTE_MARK,
      prerouting_mark = prerouting_mark,
      listen_ip = listen_ip,
      prepare_table = prepare_table,
      premarked_prerouting_rules = premarked_prerouting_rules,
      conntrack_prerouting_rules = conntrack_prerouting_rules,
    )
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectState {
  Absent,
  Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NftState {
  Absent,
  Legacy,
  Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRuleKind {
  SourceValidationGuard,
  PreroutingRoute,
  OutputRoute,
}

const POLICY_RULE_INSTALL_ORDER: [PolicyRuleKind; 3] = [
  PolicyRuleKind::OutputRoute,
  PolicyRuleKind::SourceValidationGuard,
  PolicyRuleKind::PreroutingRoute,
];
#[cfg(test)]
const POLICY_RULE_DELETE_ORDER: [PolicyRuleKind; 3] = [
  PolicyRuleKind::PreroutingRoute,
  PolicyRuleKind::SourceValidationGuard,
  PolicyRuleKind::OutputRoute,
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PolicyRuleSet {
  source_validation_guard: bool,
  prerouting_route: bool,
  output_route: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRuleState {
  Absent,
  Legacy,
  Partial,
  Exact,
}

impl PolicyRuleSet {
  fn state(self) -> PolicyRuleState {
    match (
      self.source_validation_guard,
      self.prerouting_route,
      self.output_route,
    ) {
      (false, false, false) => PolicyRuleState::Absent,
      (false, false, true) => PolicyRuleState::Legacy,
      (true, true, true) => PolicyRuleState::Exact,
      _ => PolicyRuleState::Partial,
    }
  }

  fn contains(self, kind: PolicyRuleKind) -> bool {
    match kind {
      PolicyRuleKind::SourceValidationGuard => self.source_validation_guard,
      PolicyRuleKind::PreroutingRoute => self.prerouting_route,
      PolicyRuleKind::OutputRoute => self.output_route,
    }
  }

  fn set(&mut self, kind: PolicyRuleKind) {
    match kind {
      PolicyRuleKind::SourceValidationGuard => self.source_validation_guard = true,
      PolicyRuleKind::PreroutingRoute => self.prerouting_route = true,
      PolicyRuleKind::OutputRoute => self.output_route = true,
    }
  }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkState {
  schema: u32,
  boot_id: String,
  phase: String,
  plan: TproxyNetworkPlan,
}

struct NetworkLock(File);

impl NetworkLock {
  async fn acquire() -> anyhow::Result<Self> {
    ensure_state_directory()?;
    let file = std::fs::OpenOptions::new()
      .read(true)
      .write(true)
      .create(true)
      .mode(0o600)
      .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
      .open(NETWORK_LOCK_FILE)
      .context("failed to open TPROXY network lock")?;
    validate_root_private_file(&file, NETWORK_LOCK_FILE)?;

    let deadline = tokio::time::Instant::now() + NETWORK_LOCK_TIMEOUT;
    loop {
      let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
      if result == 0 {
        return Ok(Self(file));
      }
      let error = std::io::Error::last_os_error();
      if error.kind() != std::io::ErrorKind::WouldBlock {
        return Err(error).context("failed to lock TPROXY network state");
      }
      if tokio::time::Instant::now() >= deadline {
        bail!("timed out waiting for another Plug2Proxy network operation to finish");
      }
      tokio::time::sleep(NETWORK_LOCK_RETRY).await;
    }
  }
}

impl Drop for NetworkLock {
  fn drop(&mut self) {
    unsafe {
      libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
    }
  }
}

pub async fn resolve_bypass_user(user: &str) -> anyhow::Result<u32> {
  if let Ok(uid) = user.parse::<u32>() {
    return Ok(uid);
  }
  if user.is_empty() {
    bail!("TPROXY bypass_user must not be empty");
  }

  let output = run_command(ID, &["-u", "--", user], None).await?;
  ensure_success(ID, &output)?;
  String::from_utf8(output.stdout)?
    .trim()
    .parse()
    .with_context(|| format!("invalid uid returned for TPROXY bypass user {user:?}"))
}

pub async fn check_tproxy_network(plan: &TproxyNetworkPlan) -> anyhow::Result<String> {
  let nft = check_nft_owner().await?;
  let route = check_route().await?;
  let rules = check_policy_rules().await?;
  check_nft_batch(&plan.render_nft_batch_for(nft)).await?;

  Ok(format!(
    "TPROXY network plan is valid: nft={nft:?}, route={route:?}, rules={:?}",
    rules.state()
  ))
}

pub async fn apply_tproxy_network(plan: &TproxyNetworkPlan) -> anyhow::Result<()> {
  // Serialize the readiness wait as part of the operation. A later remove
  // must not finish first and then be followed by this older apply.
  let _lock = NetworkLock::acquire().await?;
  wait_for_data_plane_ready(plan).await?;
  ensure_data_plane_ready(plan)?;

  let nft = check_nft_owner().await?;
  let route = check_route().await?;
  let rules = check_policy_rules().await?;
  let previous_state = read_state()?;
  if previous_state.is_none()
    && (nft != NftState::Absent
      || route == ObjectState::Exact
      || rules.state() != PolicyRuleState::Absent)
  {
    bail!(
      "reserved TPROXY network objects exist without a same-boot ownership journal; run `network remove` to recover an owned nft table, or resolve foreign route/rule objects manually"
    );
  }

  let batch = plan.render_nft_batch_for(nft);
  check_nft_batch(&batch).await?;
  write_state(plan, "preparing")?;

  let mut route_may_be_new = false;
  let mut mutation_result_uncertain = false;
  let pre_activation_result = async {
    if route == ObjectState::Absent {
      write_state(plan, "installing-route")?;
      run_ip_mutation_checked(
        &[
          "-4",
          "route",
          "add",
          "local",
          "0.0.0.0/0",
          "dev",
          "lo",
          "table",
          &TPROXY_ROUTE_TABLE.to_string(),
          "proto",
          "static",
        ],
        &mut mutation_result_uncertain,
      )
      .await?;
      route_may_be_new = true;
    }

    if rules.state() != PolicyRuleState::Exact {
      write_state(plan, "installing-rules")?;
      install_missing_policy_rules(rules, &mut mutation_result_uncertain).await?;
    }

    if check_route().await? != ObjectState::Exact {
      bail!("TPROXY route disappeared before activation");
    }
    if check_policy_rules().await?.state() != PolicyRuleState::Exact {
      bail!("TPROXY policy rules disappeared before activation");
    }
    verify_marked_routes().await?;
    ensure_data_plane_ready(plan)?;
    if check_nft_owner().await? != nft {
      bail!("TPROXY nft table changed concurrently before activation");
    }
    write_state(plan, "activating")?;
    anyhow::Ok(())
  }
  .await;

  if let Err(error) = pre_activation_result {
    let rollback_errors = rollback_pre_activation(
      route_may_be_new,
      rules,
      mutation_result_uncertain,
      previous_state.as_ref(),
    )
    .await;
    return Err(apply_failure_with_rollback(error, rollback_errors));
  }

  if let Err(error) = apply_nft_batch(&batch).await {
    let mut rollback_errors = rollback_nft(nft, previous_state.as_ref()).await;
    rollback_errors.extend(
      rollback_pre_activation(
        route_may_be_new,
        rules,
        mutation_result_uncertain,
        previous_state.as_ref(),
      )
      .await,
    );
    return Err(apply_failure_with_rollback(error, rollback_errors));
  }

  if let Err(error) = ensure_data_plane_ready(plan) {
    let cleanup_errors = deactivate_owned_network().await;
    let cleanup = if cleanup_errors.is_empty() {
      "the newly active network state was removed".to_owned()
    } else {
      format!(
        "automatic deactivation was incomplete: {}",
        cleanup_errors.join("; ")
      )
    };
    return Err(error.context(format!(
      "TPROXY data plane disappeared while activating; {cleanup}"
    )));
  }

  if let Err(error) = write_state(plan, "applied") {
    log::warn!(
      "TPROXY network state is active, but the final journal update failed ({error}); the durable activating journal is retained for cleanup"
    );
  }

  log::info!(
    "TPROXY network state applied: listener={}, uid={}, output_mark={:#x}/{:#x}, prerouting_mark={:#x}/{:#x}, table={}",
    plan.listen,
    plan.bypass_uid,
    TPROXY_OUTPUT_ROUTE_MARK,
    TPROXY_MARK_MASK,
    TPROXY_PREROUTING_ROUTE_MARK,
    TPROXY_MARK_MASK,
    TPROXY_ROUTE_TABLE
  );
  Ok(())
}

pub async fn remove_tproxy_network() -> anyhow::Result<()> {
  let _lock = NetworkLock::acquire().await?;
  let mut errors = vec![];
  let nft = match check_nft_owner().await {
    Ok(nft) => nft,
    Err(error) => {
      // We cannot safely delete an unverified table, but a valid journal can
      // still authorize removal of the exact rule/route below. In particular,
      // an unavailable nft binary must not prevent policy-routing cleanup.
      errors.push(format!("nft inspection failed: {error:#}"));
      NftState::Absent
    }
  };

  // Removing the owned nft table is the fail-open boundary: once its
  // sentinel has authenticated the table, stop intercepting new traffic
  // before inspecting or cleaning the auxiliary policy-routing objects.
  // A failure below must not prevent an independent cleanup attempt for the
  // rule and route.
  let nft_was_owned = nft != NftState::Absent;
  if nft_was_owned && let Err(error) = delete_nft_table().await {
    errors.push(format!("nft cleanup failed: {error:#}"));
  }

  let journal_was_owned = match read_state() {
    Ok(state) => state.is_some(),
    Err(error) => {
      errors.push(format!("journal inspection failed: {error:#}"));
      false
    }
  };
  let may_remove_reserved_objects =
    reserved_objects_may_be_removed(nft_was_owned, journal_was_owned);

  match check_policy_rules().await {
    Ok(rules) if rules.state() == PolicyRuleState::Absent => {}
    Ok(rules) if may_remove_reserved_objects => {
      errors.extend(delete_policy_rules(rules).await);
    }
    Ok(_) => errors.push(
      "rule cleanup refused: reserved TPROXY rules have no Plug2Proxy nft ownership sentinel or same-boot journal"
        .to_owned(),
    ),
    Err(error) => errors.push(format!("rule inspection failed: {error:#}")),
  }

  match check_route().await {
    Ok(ObjectState::Absent) => {}
    Ok(ObjectState::Exact) if may_remove_reserved_objects => {
      if let Err(error) = delete_route().await {
        errors.push(format!("route cleanup failed: {error:#}"));
      }
    }
    Ok(ObjectState::Exact) => errors.push(
      "route cleanup refused: reserved TPROXY route has no Plug2Proxy nft ownership sentinel or same-boot journal"
        .to_owned(),
    ),
    Err(error) => errors.push(format!("route inspection failed: {error:#}")),
  }

  // Keep the journal whenever any owned object could not be inspected or
  // removed. It is the durable authorization and recovery record for the
  // next cleanup attempt.
  if errors.is_empty()
    && let Err(error) = remove_state_file()
  {
    errors.push(format!("journal cleanup failed: {error:#}"));
  }
  ensure_cleanup_complete(errors)?;

  log::info!("TPROXY network state removed.");
  Ok(())
}

pub async fn tproxy_network_status() -> anyhow::Result<String> {
  let nft = check_nft_owner().await?;
  let route = check_route().await?;
  let rules = check_policy_rules().await?;
  let state = read_state()?;
  Ok(format!(
    "nft={nft:?}, route={route:?}, rules={:?}, state_phase={}",
    rules.state(),
    state
      .as_ref()
      .map(|state| state.phase.as_str())
      .unwrap_or("Absent")
  ))
}

async fn rollback_pre_activation(
  route_may_be_new: bool,
  previous_rules: PolicyRuleSet,
  mutation_result_uncertain: bool,
  previous_state: Option<&NetworkState>,
) -> Vec<String> {
  let mut errors = vec![];
  errors.extend(rollback_policy_rules(previous_rules).await);
  if route_may_be_new && let Err(error) = delete_route_if_exact().await {
    errors.push(format!("route rollback failed: {error:#}"));
  }
  if mutation_result_uncertain {
    errors.push(
      "an ip mutation result was uncertain; retained the ownership journal for `network remove`"
        .to_owned(),
    );
  }
  // If any object rollback failed, retain the current durable phase as the
  // authorization for a later `network remove`. Restoring or deleting the
  // previous journal here would orphan the exact object that remains.
  if errors.is_empty()
    && let Err(error) = restore_state(previous_state)
  {
    errors.push(format!("journal rollback failed: {error:#}"));
  }
  errors
}

async fn rollback_nft(
  previous_nft: NftState,
  previous_state: Option<&NetworkState>,
) -> Vec<String> {
  let result = match previous_nft {
    NftState::Absent => remove_owned_nft_table().await,
    NftState::Legacy => match previous_state {
      Some(state) => apply_nft_batch(&state.plan.render_legacy_nft_batch()).await,
      None => Err(anyhow::anyhow!(
        "cannot restore the previous legacy nft table without an ownership journal"
      )),
    },
    NftState::Exact => match previous_state {
      Some(state) => apply_nft_batch(&state.plan.render_nft_batch()).await,
      None => Err(anyhow::anyhow!(
        "cannot restore the previous owned nft table without an ownership journal"
      )),
    },
  };
  result
    .err()
    .map(|error| vec![format!("nft rollback failed: {error:#}")])
    .unwrap_or_default()
}

async fn deactivate_owned_network() -> Vec<String> {
  let mut errors = vec![];
  if let Err(error) = remove_owned_nft_table().await {
    errors.push(format!("nft cleanup failed: {error:#}"));
  }
  match check_policy_rules().await {
    Ok(rules) => errors.extend(delete_policy_rules(rules).await),
    Err(error) => errors.push(format!("rule inspection failed: {error:#}")),
  }
  if let Err(error) = delete_route_if_exact().await {
    errors.push(format!("route cleanup failed: {error:#}"));
  }
  if errors.is_empty()
    && let Err(error) = remove_state_file()
  {
    errors.push(format!("journal cleanup failed: {error:#}"));
  }
  errors
}

fn apply_failure_with_rollback(
  error: anyhow::Error,
  rollback_errors: Vec<String>,
) -> anyhow::Error {
  if rollback_errors.is_empty() {
    error.context("failed to apply TPROXY network state; new changes were rolled back")
  } else {
    error.context(format!(
      "failed to apply TPROXY network state; rollback was incomplete: {}",
      rollback_errors.join("; ")
    ))
  }
}

fn reserved_objects_may_be_removed(nft_was_owned: bool, journal_was_owned: bool) -> bool {
  nft_was_owned || journal_was_owned
}

fn ensure_cleanup_complete(errors: Vec<String>) -> anyhow::Result<()> {
  if errors.is_empty() {
    Ok(())
  } else {
    bail!(
      "failed to fully remove TPROXY network state: {}",
      errors.join("; ")
    )
  }
}

fn ensure_data_plane_ready(plan: &TproxyNetworkPlan) -> anyhow::Result<()> {
  let mut required = vec![
    (plan.listen, true, "TPROXY TCP LISTEN"),
    (plan.listen, false, "TPROXY UDP UNCONN"),
  ];
  if let Some(dns_listen) = plan.dns_listen {
    required.extend([
      (dns_listen, true, "DNS TCP LISTEN"),
      (dns_listen, false, "DNS UDP UNCONN"),
    ]);
  }

  let mut missing = vec![];
  for (address, tcp, label) in required {
    let expected_state = if tcp { "0A" } else { "07" };
    if !proc_net_socket_is_ready(address, plan.bypass_uid, tcp, expected_state)? {
      missing.push(format!("{label} at {address}"));
    }
  }

  if !missing.is_empty() {
    bail!(
      "TPROXY data plane is not ready for uid {} (missing {}); start the daemon before applying network interception",
      plan.bypass_uid,
      missing.join(" and ")
    );
  }
  Ok(())
}

async fn wait_for_data_plane_ready(plan: &TproxyNetworkPlan) -> anyhow::Result<()> {
  let deadline = tokio::time::Instant::now() + DATA_PLANE_READY_TIMEOUT;
  loop {
    match ensure_data_plane_ready(plan) {
      Ok(()) => return Ok(()),
      Err(error) if tokio::time::Instant::now() >= deadline => {
        return Err(error).context(format!(
          "TPROXY data plane did not become ready within {DATA_PLANE_READY_TIMEOUT:?}"
        ));
      }
      Err(_) => tokio::time::sleep(DATA_PLANE_READY_RETRY).await,
    }
  }
}

fn proc_net_socket_is_ready(
  address: SocketAddr,
  uid: u32,
  tcp: bool,
  expected_state: &str,
) -> anyhow::Result<bool> {
  let path = match (address.is_ipv6(), tcp) {
    (false, true) => "/proc/net/tcp",
    (false, false) => "/proc/net/udp",
    (true, true) => "/proc/net/tcp6",
    (true, false) => "/proc/net/udp6",
  };
  let source = std::fs::read_to_string(path)
    .with_context(|| format!("failed to inspect socket listeners in {path}"))?;
  Ok(proc_net_has_socket(&source, address, uid, expected_state))
}

fn proc_net_has_socket(source: &str, address: SocketAddr, uid: u32, expected_state: &str) -> bool {
  let expected_address = proc_net_encoded_ip(address.ip());

  source.lines().skip(1).any(|line| {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() < 8 || !fields[3].eq_ignore_ascii_case(expected_state) {
      return false;
    }
    let Some((encoded_address, encoded_port)) = fields[1].split_once(':') else {
      return false;
    };
    encoded_address.eq_ignore_ascii_case(&expected_address)
      && u16::from_str_radix(encoded_port, 16).ok() == Some(address.port())
      && fields[7].parse::<u32>().ok() == Some(uid)
  })
}

fn proc_net_encoded_ip(address: IpAddr) -> String {
  match address {
    IpAddr::V4(address) => format!("{:08X}", u32::from_ne_bytes(address.octets())),
    IpAddr::V6(address) => address
      .octets()
      .chunks_exact(4)
      .map(|chunk| format!("{:08X}", u32::from_ne_bytes(chunk.try_into().unwrap())))
      .collect(),
  }
}

async fn check_nft_owner() -> anyhow::Result<NftState> {
  let output = run_command(NFT, &["-j", "list", "tables"], None).await?;
  ensure_success(NFT, &output)?;
  let document: Value = serde_json::from_slice(&output.stdout).context("invalid nft JSON")?;
  let exists = document["nftables"]
    .as_array()
    .into_iter()
    .flatten()
    .filter_map(|item| item.get("table"))
    .any(|table| table["family"] == TPROXY_NFT_FAMILY && table["name"] == TPROXY_NFT_TABLE);
  if !exists {
    return Ok(NftState::Absent);
  }

  let output = run_command(
    NFT,
    &["-j", "list", "table", TPROXY_NFT_FAMILY, TPROXY_NFT_TABLE],
    None,
  )
  .await?;
  ensure_success(NFT, &output)?;
  let document: Value = serde_json::from_slice(&output.stdout).context("invalid nft JSON")?;
  let sentinel = document["nftables"]
    .as_array()
    .into_iter()
    .flatten()
    .filter_map(|item| item.get("table"))
    .find(|table| table["family"] == TPROXY_NFT_FAMILY && table["name"] == TPROXY_NFT_TABLE)
    .and_then(|table| table.get("comment"))
    .and_then(Value::as_str);
  match sentinel {
    Some(TPROXY_NFT_SENTINEL) => Ok(NftState::Exact),
    Some(LEGACY_TPROXY_NFT_SENTINEL) => Ok(NftState::Legacy),
    _ => bail!(
      "nft table {}/{} exists without a supported Plug2Proxy ownership sentinel; refusing to modify it",
      TPROXY_NFT_FAMILY,
      TPROXY_NFT_TABLE
    ),
  }
}

async fn check_policy_rules() -> anyhow::Result<PolicyRuleSet> {
  let output = run_command(IP, &["-j", "-4", "rule", "show"], None).await?;
  ensure_success(IP, &output)?;
  let rules: Vec<Value> = serde_json::from_slice(&output.stdout).context("invalid ip rule JSON")?;
  classify_policy_rules(&rules)
}

fn classify_policy_rules(rules: &[Value]) -> anyhow::Result<PolicyRuleSet> {
  let mut managed = PolicyRuleSet::default();

  for rule in rules {
    let priority = json_u32(rule.get("priority").or_else(|| rule.get("pref")));
    let mark = json_u32(rule.get("fwmark"));
    let mask = json_u32(rule.get("fwmask"));
    let table = json_u32(rule.get("table"));
    let goto = json_u32(rule.get("goto"));
    let iif = rule
      .get("iif")
      .or_else(|| rule.get("iifname"))
      .and_then(Value::as_str);
    let touches_ours = matches!(
      priority,
      Some(
        TPROXY_SOURCE_VALIDATION_RULE_PRIORITY
          | TPROXY_PREROUTING_RULE_PRIORITY
          | TPROXY_OUTPUT_RULE_PRIORITY
      )
    ) || matches!(
      mark,
      Some(TPROXY_OUTPUT_ROUTE_MARK | TPROXY_PREROUTING_ROUTE_MARK)
    ) || table == Some(TPROXY_ROUTE_TABLE);
    if !touches_ours {
      continue;
    }

    let kind = if priority == Some(TPROXY_SOURCE_VALIDATION_RULE_PRIORITY)
      && mark == Some(TPROXY_PREROUTING_ROUTE_MARK)
      && mask == Some(TPROXY_MARK_MASK)
      && iif == Some("lo")
      && goto == Some(TPROXY_OUTPUT_RULE_PRIORITY)
      && table.is_none_or(|table| table == 0)
      && policy_rule_action_matches(rule, true)
      && !has_extra_policy_rule_selectors(rule, true)
    {
      PolicyRuleKind::SourceValidationGuard
    } else if priority == Some(TPROXY_PREROUTING_RULE_PRIORITY)
      && mark == Some(TPROXY_PREROUTING_ROUTE_MARK)
      && mask == Some(TPROXY_MARK_MASK)
      && iif.is_none()
      && table == Some(TPROXY_ROUTE_TABLE)
      && goto.is_none()
      && policy_rule_action_matches(rule, false)
      && !has_extra_policy_rule_selectors(rule, false)
    {
      PolicyRuleKind::PreroutingRoute
    } else if priority == Some(TPROXY_OUTPUT_RULE_PRIORITY)
      && mark == Some(TPROXY_OUTPUT_ROUTE_MARK)
      && mask == Some(TPROXY_MARK_MASK)
      && iif.is_none()
      && table == Some(TPROXY_ROUTE_TABLE)
      && goto.is_none()
      && policy_rule_action_matches(rule, false)
      && !has_extra_policy_rule_selectors(rule, false)
    {
      PolicyRuleKind::OutputRoute
    } else {
      bail!("policy routing rule conflicts with Plug2Proxy's reserved rule: {rule}");
    };

    if managed.contains(kind) {
      bail!("duplicate Plug2Proxy TPROXY policy rule found: {rule}");
    }
    managed.set(kind);
  }

  Ok(managed)
}

fn policy_rule_action_matches(rule: &Value, guard: bool) -> bool {
  // iproute2 omits `action` for the normal table-lookup form. In that case
  // the required `table` or `goto` attribute checked by the caller is the
  // action discriminator. If an action is emitted, accept only its expected
  // spelling and reject blackhole/prohibit/unreachable variants.
  let Some(action) = rule.get("action").and_then(Value::as_str) else {
    return true;
  };
  if guard {
    action == "goto"
  } else {
    matches!(action, "lookup" | "to-table" | "to_tbl" | "unicast")
  }
}

fn has_extra_policy_rule_selectors(rule: &Value, allow_iif: bool) -> bool {
  let non_default_prefix = |keys: &[&str]| {
    keys
      .iter()
      .find_map(|key| rule.get(*key))
      .and_then(Value::as_str)
      .is_some_and(|prefix| prefix != "all" && prefix != "0.0.0.0/0")
  };
  let has_non_null = |keys: &[&str]| {
    keys
      .iter()
      .any(|key| rule.get(*key).is_some_and(|value| !value.is_null()))
  };
  let iif = rule.get("iif").or_else(|| rule.get("iifname"));

  (!allow_iif && iif.is_some_and(|value| !value.is_null()))
    || has_non_null(&[
      "oif",
      "oifname",
      "uidrange",
      "uid_range",
      "ipproto",
      "sport",
      "dport",
      "tun_id",
      "l3mdev",
      "suppress_prefixlength",
      "suppress_ifgroup",
    ])
    || rule
      .get("not")
      .or_else(|| rule.get("invert"))
      .is_some_and(|value| value.as_bool().unwrap_or(true))
    || non_default_prefix(&["src", "from"])
    || non_default_prefix(&["dst", "to"])
}

async fn install_missing_policy_rules(
  existing: PolicyRuleSet,
  mutation_result_uncertain: &mut bool,
) -> anyhow::Result<()> {
  for kind in POLICY_RULE_INSTALL_ORDER {
    if !existing.contains(kind) {
      add_policy_rule(kind, mutation_result_uncertain).await?;
    }
  }
  Ok(())
}

async fn check_route() -> anyhow::Result<ObjectState> {
  let table = TPROXY_ROUTE_TABLE.to_string();
  let output = run_command(IP, &["-j", "-4", "route", "show", "table", &table], None).await?;
  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("FIB table does not exist") {
      return Ok(ObjectState::Absent);
    }
    ensure_success(IP, &output)?;
  }

  let routes: Vec<Value> =
    serde_json::from_slice(&output.stdout).context("invalid ip route JSON")?;
  if routes.is_empty() {
    return Ok(ObjectState::Absent);
  }
  if routes.len() != 1 {
    bail!("routing table {TPROXY_ROUTE_TABLE} contains foreign routes: {routes:?}");
  }
  let route = &routes[0];
  let exact = route["type"] == "local"
    && (route["dst"] == "default" || route["dst"] == "0.0.0.0/0")
    && route["dev"] == "lo"
    && (route.get("protocol").is_none() || route["protocol"] == "static");
  if !exact {
    bail!("routing table {TPROXY_ROUTE_TABLE} conflicts with Plug2Proxy: {route}");
  }
  Ok(ObjectState::Exact)
}

async fn check_nft_batch(batch: &str) -> anyhow::Result<()> {
  let output = run_command(NFT, &["-c", "-f", "-"], Some(batch)).await?;
  ensure_success(NFT, &output).context("generated TPROXY nftables batch failed validation")
}

async fn apply_nft_batch(batch: &str) -> anyhow::Result<()> {
  let output = run_command(NFT, &["-f", "-"], Some(batch)).await?;
  ensure_success(NFT, &output).context("failed to atomically install TPROXY nftables table")
}

async fn remove_owned_nft_table() -> anyhow::Result<()> {
  if check_nft_owner().await? == NftState::Absent {
    return Ok(());
  }
  delete_nft_table().await
}

async fn delete_nft_table() -> anyhow::Result<()> {
  let batch = format!("delete table {TPROXY_NFT_FAMILY} {TPROXY_NFT_TABLE}\n");
  let output = run_command(NFT, &["-f", "-"], Some(&batch)).await?;
  ensure_success(NFT, &output).context("failed to remove TPROXY nftables table")
}

fn policy_rule_arguments(kind: PolicyRuleKind, operation: &str) -> Vec<String> {
  let mut arguments = vec![
    "-4".to_owned(),
    "rule".to_owned(),
    operation.to_owned(),
    "priority".to_owned(),
  ];
  match kind {
    PolicyRuleKind::SourceValidationGuard => arguments.extend([
      TPROXY_SOURCE_VALIDATION_RULE_PRIORITY.to_string(),
      "iif".to_owned(),
      "lo".to_owned(),
      "fwmark".to_owned(),
      format!("{TPROXY_PREROUTING_ROUTE_MARK:#x}/{TPROXY_MARK_MASK:#x}"),
      "goto".to_owned(),
      TPROXY_OUTPUT_RULE_PRIORITY.to_string(),
    ]),
    PolicyRuleKind::PreroutingRoute => arguments.extend([
      TPROXY_PREROUTING_RULE_PRIORITY.to_string(),
      "fwmark".to_owned(),
      format!("{TPROXY_PREROUTING_ROUTE_MARK:#x}/{TPROXY_MARK_MASK:#x}"),
      "lookup".to_owned(),
      TPROXY_ROUTE_TABLE.to_string(),
    ]),
    PolicyRuleKind::OutputRoute => arguments.extend([
      TPROXY_OUTPUT_RULE_PRIORITY.to_string(),
      "fwmark".to_owned(),
      format!("{TPROXY_OUTPUT_ROUTE_MARK:#x}/{TPROXY_MARK_MASK:#x}"),
      "lookup".to_owned(),
      TPROXY_ROUTE_TABLE.to_string(),
    ]),
  }
  arguments
}

async fn add_policy_rule(
  kind: PolicyRuleKind,
  mutation_result_uncertain: &mut bool,
) -> anyhow::Result<()> {
  let arguments = policy_rule_arguments(kind, "add");
  let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
  run_ip_mutation_checked(&arguments, mutation_result_uncertain).await
}

async fn delete_policy_rule(kind: PolicyRuleKind) -> anyhow::Result<()> {
  let arguments = policy_rule_arguments(kind, "del");
  let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
  run_ip_checked(&arguments).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PolicyRuleDeletionDecision {
  remove_source_validation_guard: bool,
  source_validation_guard_blocked: bool,
  remove_output_route: bool,
}

fn policy_rule_removal_targets(previous: PolicyRuleSet, current: PolicyRuleSet) -> PolicyRuleSet {
  PolicyRuleSet {
    source_validation_guard: current.source_validation_guard && !previous.source_validation_guard,
    prerouting_route: current.prerouting_route && !previous.prerouting_route,
    output_route: current.output_route && !previous.output_route,
  }
}

fn policy_rule_deletion_decision(
  targets: PolicyRuleSet,
  current_after_prerouting_delete: PolicyRuleSet,
) -> PolicyRuleDeletionDecision {
  let source_validation_guard_blocked =
    targets.source_validation_guard && current_after_prerouting_delete.prerouting_route;
  PolicyRuleDeletionDecision {
    remove_source_validation_guard: targets.source_validation_guard
      && !source_validation_guard_blocked,
    source_validation_guard_blocked,
    remove_output_route: targets.output_route,
  }
}

async fn delete_policy_rules(rules: PolicyRuleSet) -> Vec<String> {
  delete_policy_rule_targets(rules, "cleanup").await
}

async fn delete_policy_rule_targets(targets: PolicyRuleSet, operation: &str) -> Vec<String> {
  let mut errors = vec![];
  let mut decision = PolicyRuleDeletionDecision {
    remove_source_validation_guard: false,
    source_validation_guard_blocked: false,
    remove_output_route: targets.output_route,
  };

  if targets.prerouting_route
    && let Err(error) = delete_policy_rule(PolicyRuleKind::PreroutingRoute).await
  {
    errors.push(format!(
      "PreroutingRoute rule {operation} failed: {error:#}"
    ));
  }

  if targets.source_validation_guard {
    match check_policy_rules().await {
      Ok(current) => {
        decision = policy_rule_deletion_decision(targets, current);
        if decision.remove_source_validation_guard
          && let Err(error) = delete_policy_rule(PolicyRuleKind::SourceValidationGuard).await
        {
          errors.push(format!(
            "SourceValidationGuard rule {operation} failed: {error:#}"
          ));
        }
        if decision.source_validation_guard_blocked {
          errors.push(format!(
            "SourceValidationGuard rule {operation} was skipped because PreroutingRoute is still present"
          ));
        }
      }
      Err(error) => errors.push(format!(
        "SourceValidationGuard rule {operation} was skipped because PreroutingRoute absence could not be confirmed: {error:#}"
      )),
    }
  }

  // OUTPUT has a separate mark and no dependency on the PREROUTING guard.
  // Always make this best-effort attempt even when the dependent cleanup
  // above failed, so nft removal failures still converge toward fail-open.
  if decision.remove_output_route
    && let Err(error) = delete_policy_rule(PolicyRuleKind::OutputRoute).await
  {
    errors.push(format!("OutputRoute rule {operation} failed: {error:#}"));
  }

  errors
}

async fn rollback_policy_rules(previous: PolicyRuleSet) -> Vec<String> {
  let current = match check_policy_rules().await {
    Ok(current) => current,
    Err(error) => return vec![format!("rule rollback inspection failed: {error:#}")],
  };
  delete_policy_rule_targets(policy_rule_removal_targets(previous, current), "rollback").await
}

async fn delete_route() -> anyhow::Result<()> {
  run_ip_checked(&[
    "-4",
    "route",
    "del",
    "local",
    "0.0.0.0/0",
    "dev",
    "lo",
    "table",
    &TPROXY_ROUTE_TABLE.to_string(),
    "proto",
    "static",
  ])
  .await
}

async fn delete_route_if_exact() -> anyhow::Result<()> {
  if check_route().await? == ObjectState::Exact {
    delete_route().await?;
  }
  Ok(())
}

async fn run_ip_checked(arguments: &[&str]) -> anyhow::Result<()> {
  let output = run_command(IP, arguments, None).await?;
  ensure_success(IP, &output)
}

async fn run_ip_mutation_checked(
  arguments: &[&str],
  result_uncertain: &mut bool,
) -> anyhow::Result<()> {
  let output = match run_command(IP, arguments, None).await {
    Ok(output) => output,
    Err(error) => {
      // This error does not prove that a spawned `ip` process failed before
      // its netlink mutation reached the kernel. Conservatively retain the
      // installing journal instead of claiming a complete rollback.
      *result_uncertain = true;
      return Err(error);
    }
  };
  ensure_success(IP, &output)
}

async fn verify_marked_routes() -> anyhow::Result<()> {
  let output = run_command(
    IP,
    &[
      "-j",
      "-4",
      "route",
      "get",
      "198.51.100.1",
      "mark",
      &format!("{TPROXY_OUTPUT_ROUTE_MARK:#x}"),
    ],
    None,
  )
  .await?;
  ensure_success(IP, &output)?;
  let routes: Vec<Value> =
    serde_json::from_slice(&output.stdout).context("invalid route-get JSON")?;
  let valid = routes.first().is_some_and(|route| {
    route["type"] == "local"
      && route["dev"] == "lo"
      && json_u32(route.get("table")) == Some(TPROXY_ROUTE_TABLE)
  });
  if !valid {
    bail!(
      "marked route did not resolve through Plug2Proxy's local table: {}",
      String::from_utf8_lossy(&output.stdout)
    );
  }

  let arguments = source_validation_route_get_arguments();
  let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
  let output = run_command(IP, &arguments, None).await?;
  ensure_success(IP, &output)?;
  let routes: Vec<Value> =
    serde_json::from_slice(&output.stdout).context("invalid guarded route-get JSON")?;
  let incorrectly_local = routes.first().is_some_and(|route| {
    route["type"] == "local"
      && route["dev"] == "lo"
      && json_u32(route.get("table")) == Some(TPROXY_ROUTE_TABLE)
  });
  if incorrectly_local {
    bail!(
      "PREROUTING mark source-validation guard still resolved through Plug2Proxy's local table: {}",
      String::from_utf8_lossy(&output.stdout)
    );
  }
  Ok(())
}

fn source_validation_route_get_arguments() -> Vec<String> {
  // An output route lookup has loopback as its RPDB input interface, which
  // exercises the same guard selector used by fib_validate_source(). Passing
  // an explicit `iif lo` instead asks the kernel for an input-route lookup and
  // can fail its own nested source validation before exposing the guard result.
  [
    "-j".to_owned(),
    "-4".to_owned(),
    "route".to_owned(),
    "get".to_owned(),
    "198.51.100.1".to_owned(),
    "mark".to_owned(),
    format!("{TPROXY_PREROUTING_ROUTE_MARK:#x}"),
  ]
  .into()
}

fn json_u32(value: Option<&Value>) -> Option<u32> {
  let value = value?;
  if let Some(number) = value.as_u64() {
    return u32::try_from(number).ok();
  }
  let value = value.as_str()?;
  value
    .strip_prefix("0x")
    .map(|value| u32::from_str_radix(value, 16).ok())
    .unwrap_or_else(|| value.parse().ok())
}

async fn run_command(
  program: &str,
  arguments: &[&str],
  stdin: Option<&str>,
) -> anyhow::Result<Output> {
  let mut command = Command::new(program);
  command
    .args(arguments)
    .env("LC_ALL", "C")
    .kill_on_drop(true)
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
  if stdin.is_some() {
    command.stdin(std::process::Stdio::piped());
  }

  let mut child = command
    .spawn()
    .with_context(|| format!("failed to start {program}"))?;
  let execution = async move {
    if let Some(input) = stdin {
      child
        .stdin
        .take()
        .context("child stdin was unavailable")?
        .write_all(input.as_bytes())
        .await?;
    }

    child.wait_with_output().await.map_err(anyhow::Error::from)
  };
  let output = timeout(COMMAND_TIMEOUT, execution)
    .await
    .with_context(|| format!("{program} timed out after {COMMAND_TIMEOUT:?}"))??;
  Ok(output)
}

fn ensure_success(program: &str, output: &Output) -> anyhow::Result<()> {
  if output.status.success() {
    return Ok(());
  }
  bail!(
    "{program} exited with {}: {}",
    output.status,
    String::from_utf8_lossy(&output.stderr).trim()
  )
}

fn write_state(plan: &TproxyNetworkPlan, phase: &str) -> anyhow::Result<()> {
  ensure_state_directory()?;
  let boot_id = current_boot_id()?;
  let encoded = serde_json::to_vec_pretty(&NetworkState {
    schema: 1,
    boot_id,
    phase: phase.to_owned(),
    plan: plan.clone(),
  })?;
  let temporary = format!("{STATE_FILE}.{}.tmp", uuid::Uuid::new_v4());
  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(&temporary)
    .with_context(|| format!("failed to create {temporary}"))?;
  let write_result = (|| -> std::io::Result<()> {
    file.write_all(&encoded)?;
    file.sync_all()?;
    std::fs::rename(&temporary, STATE_FILE)?;
    std::fs::File::open(STATE_DIRECTORY)?.sync_all()
  })();
  if write_result.is_err() {
    let _ = std::fs::remove_file(&temporary);
  }
  write_result.context("failed to atomically write TPROXY network state")
}

fn read_state() -> anyhow::Result<Option<NetworkState>> {
  let mut file = match std::fs::OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(STATE_FILE)
  {
    Ok(file) => file,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
    Err(error) => return Err(error).context("failed to open TPROXY ownership journal"),
  };
  validate_root_private_file(&file, STATE_FILE)?;

  let mut encoded = Vec::new();
  file
    .read_to_end(&mut encoded)
    .context("failed to read TPROXY ownership journal")?;
  let state: NetworkState =
    serde_json::from_slice(&encoded).context("invalid TPROXY ownership journal")?;
  if state.schema != 1 {
    bail!(
      "unsupported TPROXY ownership journal schema {}",
      state.schema
    );
  }
  if state.boot_id != current_boot_id()? {
    bail!("TPROXY ownership journal belongs to a different system boot");
  }
  if !network_state_phase_is_supported(&state.phase) {
    bail!("invalid TPROXY ownership journal phase {:?}", state.phase);
  }
  if !state.plan.listen.is_ipv4()
    || !state.plan.listen.ip().is_loopback()
    || state.plan.listen.port() == 0
  {
    bail!("invalid TPROXY ownership journal listener");
  }
  Ok(Some(state))
}

fn network_state_phase_is_supported(phase: &str) -> bool {
  matches!(
    phase,
    "preparing"
      | "installing-route"
      | "installing-rule"
      | "installing-rules"
      | "activating"
      | "applied"
  )
}

fn restore_state(previous_state: Option<&NetworkState>) -> anyhow::Result<()> {
  match previous_state {
    Some(state) => write_state(&state.plan, &state.phase),
    None => remove_state_file(),
  }
}

fn current_boot_id() -> anyhow::Result<String> {
  Ok(
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
      .context("failed to read boot id")?
      .trim()
      .to_owned(),
  )
}

fn validate_root_private_file(file: &File, path: &str) -> anyhow::Result<()> {
  let metadata = file.metadata()?;
  if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
    bail!("{path} must be a root-owned private regular file");
  }
  Ok(())
}

fn ensure_state_directory() -> anyhow::Result<()> {
  let path = Path::new(STATE_DIRECTORY);
  if !path.exists() {
    match std::fs::create_dir(path) {
      Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?,
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
      Err(error) => return Err(error).context("failed to create TPROXY network state directory"),
    }
  }
  let metadata = std::fs::symlink_metadata(path)?;
  if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
    bail!("{STATE_DIRECTORY} must be a root-owned directory, not a symlink");
  }
  if metadata.mode() & 0o077 != 0 {
    bail!("{STATE_DIRECTORY} must not be accessible by group or other users");
  }
  Ok(())
}

fn remove_state_file() -> anyhow::Result<()> {
  match std::fs::remove_file(STATE_FILE) {
    Ok(()) => Ok(()),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(error) => Err(error.into()),
  }
}

#[cfg(test)]
mod tests {
  use lowkit::SerdeSocketAddress;

  use crate::inbound::TproxyNetworkConfig;

  use super::*;

  fn plan() -> TproxyNetworkPlan {
    TproxyNetworkPlan::from_config(
      &TproxyInboundConfig {
        listen: SerdeSocketAddress::from("127.0.0.1:12345".parse::<SocketAddr>().unwrap()),
        sniff: true,
        hijack_dns: false,
        network: TproxyNetworkConfig::default(),
      },
      None,
      989,
    )
    .unwrap()
  }

  fn guard_rule() -> Value {
    serde_json::json!({
      "priority": 98,
      "src": "all",
      "fwmark": "0x53000000",
      "fwmask": "0xff000000",
      "iif": "lo",
      "goto": 100
    })
  }

  fn prerouting_rule() -> Value {
    serde_json::json!({
      "priority": 99,
      "src": "all",
      "fwmark": "0x53000000",
      "fwmask": "0xff000000",
      "table": "20230"
    })
  }

  fn output_rule() -> Value {
    serde_json::json!({
      "priority": 100,
      "src": "all",
      "fwmark": "0x51000000",
      "fwmask": "0xff000000",
      "table": "20230"
    })
  }

  #[test]
  fn renders_split_route_marks_and_legacy_flow_migration() {
    let plan = plan();
    let rules = plan.render_nft_batch();
    assert!(rules.starts_with("delete table inet plug2proxy_tproxy\n"));
    assert!(plan.render_nft_batch_for(NftState::Absent).starts_with(
      "create table inet plug2proxy_tproxy { comment \"managed-by=plug2proxy;schema=2\"; }\n"
    ));
    assert!(rules.contains(&format!("comment \"{TPROXY_NFT_SENTINEL}\"")));
    assert!(rules.contains("meta skuid 989 counter return"));
    assert!(rules.contains(
      "ct mark & 0xff000000 == 0x51000000 meta mark set (meta mark & 0x00ffffff) | 0x51000000"
    ));
    assert_eq!(
      rules.matches("ct status confirmed counter return").count(),
      2
    );
    assert_eq!(
      rules.matches("ct direction reply counter return").count(),
      2
    );
    assert!(rules.contains(
      "tcp flags & (fin | syn | rst | ack) == syn ct mark set (ct mark & 0x00ffffff) | 0x51000000"
    ));
    assert!(
      rules
        .contains("meta l4proto udp ct state new ct mark set (ct mark & 0x00ffffff) | 0x51000000")
    );
    assert!(rules.contains("meta mark & 0xff000000 == 0x52000000"));
    assert!(rules.contains("tproxy ip to 127.0.0.1:12345"));
    assert!(rules.contains(
      "meta mark & 0xff000000 == 0x51000000 iifname \"lo\" tproxy ip to 127.0.0.1:12345"
    ));
    assert!(rules.contains(
      "meta mark & 0xff000000 == 0x51000000 ct mark set (ct mark & 0x00ffffff) | 0x53000000 meta mark set (meta mark & 0x00ffffff) | 0x53000000 tproxy ip to 127.0.0.1:12345"
    ));
    assert!(rules.contains(
      "ct mark & 0xff000000 == 0x51000000 iifname \"lo\" meta mark set (meta mark & 0x00ffffff) | 0x51000000 tproxy ip to 127.0.0.1:12345"
    ));
    assert!(rules.contains(
      "ct mark & 0xff000000 == 0x51000000 ct mark set (ct mark & 0x00ffffff) | 0x53000000 meta mark set (meta mark & 0x00ffffff) | 0x53000000 tproxy ip to 127.0.0.1:12345"
    ));
    assert!(rules.contains(
      "ct mark & 0xff000000 == 0x53000000 meta mark set (meta mark & 0x00ffffff) | 0x53000000 tproxy ip to 127.0.0.1:12345"
    ));
    assert!(rules.contains(
      "tcp flags & (fin | syn | rst | ack) == syn ct mark set (ct mark & 0x00ffffff) | 0x53000000"
    ));
    let prerouting = rules.split("chain prerouting").nth(1).unwrap();
    assert!(
      prerouting.find("ct direction reply").unwrap()
        < prerouting
          .find("ct mark & 0xff000000 == 0x51000000")
          .unwrap()
    );
    assert_eq!(rules.matches("meta mark != 0 counter return").count(), 1);
    assert!(rules.contains("meta mark & 0xff000000 != 0 counter return"));
    assert!(rules.contains("ct mark & 0xff000000 != 0 counter return"));
    assert!(!rules.contains("10.0.0.0/8"));
    assert!(!rules.contains("100.64.0.0/10"));
  }

  #[test]
  fn legacy_renderer_keeps_schema_one_and_single_route_mark() {
    let rules = plan().render_legacy_nft_batch();

    assert!(rules.contains(&format!("comment \"{LEGACY_TPROXY_NFT_SENTINEL}\"")));
    assert!(!rules.contains(TPROXY_NFT_SENTINEL));
    assert!(!rules.contains("0x53000000"));
    assert!(!rules.contains("iifname \"lo\""));
    assert!(rules.contains(
      "ct mark & 0xff000000 == 0x51000000 meta mark set (meta mark & 0x00ffffff) | 0x51000000 tproxy ip to 127.0.0.1:12345"
    ));
  }

  #[test]
  fn adds_user_excludes_and_rejects_ipv6() {
    let config = TproxyNetworkConfig {
      exclude_ipv4: serde_json::from_str(r#"["192.168.0.0/16"]"#).unwrap(),
      ..TproxyNetworkConfig::default()
    };
    let tproxy = TproxyInboundConfig {
      listen: SerdeSocketAddress::from("127.0.0.1:12345".parse::<SocketAddr>().unwrap()),
      sniff: true,
      hijack_dns: false,
      network: config,
    };
    assert!(
      TproxyNetworkPlan::from_config(&tproxy, None, 989)
        .unwrap()
        .render_nft_batch()
        .contains("192.168.0.0/16")
    );

    let config = TproxyNetworkConfig {
      exclude_ipv4: serde_json::from_str(r#"["2001:db8::/32"]"#).unwrap(),
      ..TproxyNetworkConfig::default()
    };
    let tproxy = TproxyInboundConfig {
      listen: SerdeSocketAddress::from("127.0.0.1:12345".parse::<SocketAddr>().unwrap()),
      sniff: true,
      hijack_dns: false,
      network: config,
    };
    assert!(
      TproxyNetworkPlan::from_config(&tproxy, None, 989)
        .unwrap_err()
        .to_string()
        .contains("IPv6")
    );
  }

  #[test]
  fn removes_ipv4_excludes_covered_by_broader_networks() {
    let config = TproxyNetworkConfig {
      exclude_ipv4: serde_json::from_str(r#"["100.64.1.1/10", "100.100.2.3/16"]"#).unwrap(),
      ..TproxyNetworkConfig::default()
    };
    let tproxy = TproxyInboundConfig {
      listen: SerdeSocketAddress::from("127.0.0.1:12345".parse::<SocketAddr>().unwrap()),
      sniff: true,
      hijack_dns: false,
      network: config,
    };

    let plan = TproxyNetworkPlan::from_config(&tproxy, None, 989).unwrap();

    assert!(
      plan
        .exclude_ipv4
        .contains(&"100.64.0.0/10".parse().unwrap())
    );
    assert!(
      !plan
        .exclude_ipv4
        .contains(&"100.100.0.0/16".parse().unwrap())
    );
  }

  #[test]
  fn keeps_dns_listener_in_readiness_plan() {
    let config = TproxyInboundConfig {
      listen: SerdeSocketAddress::from("127.0.0.1:12345".parse::<SocketAddr>().unwrap()),
      sniff: true,
      hijack_dns: false,
      network: TproxyNetworkConfig::default(),
    };
    let dns_listen = "[::1]:5353".parse().unwrap();

    let plan = TproxyNetworkPlan::from_config(&config, Some(dns_listen), 989).unwrap();

    assert_eq!(plan.dns_listen, Some(dns_listen));
  }

  #[test]
  fn parses_numeric_and_hex_json_values() {
    assert_eq!(json_u32(Some(&Value::from(20230))), Some(20230));
    assert_eq!(
      json_u32(Some(&Value::from("0x51000000"))),
      Some(TPROXY_OUTPUT_ROUTE_MARK)
    );
    assert_eq!(json_u32(Some(&Value::from("20230"))), Some(20230));
  }

  #[test]
  fn classifies_exact_legacy_and_partial_policy_rule_sets() {
    assert_eq!(
      classify_policy_rules(&[]).unwrap().state(),
      PolicyRuleState::Absent
    );
    assert_eq!(
      classify_policy_rules(&[output_rule()]).unwrap().state(),
      PolicyRuleState::Legacy
    );
    assert_eq!(
      classify_policy_rules(&[output_rule(), prerouting_rule()])
        .unwrap()
        .state(),
      PolicyRuleState::Partial
    );
    assert_eq!(
      classify_policy_rules(&[guard_rule(), prerouting_rule(), output_rule()])
        .unwrap()
        .state(),
      PolicyRuleState::Exact
    );
  }

  #[test]
  fn rejects_duplicate_or_non_exact_reserved_policy_rules() {
    let duplicate = classify_policy_rules(&[output_rule(), output_rule()])
      .unwrap_err()
      .to_string();
    assert!(duplicate.contains("duplicate"));

    let mut extra_selector = prerouting_rule();
    extra_selector["oif"] = Value::from("eth0");
    assert!(
      classify_policy_rules(&[extra_selector])
        .unwrap_err()
        .to_string()
        .contains("conflicts")
    );

    let mut wrong_goto = guard_rule();
    wrong_goto["goto"] = Value::from(99);
    assert!(classify_policy_rules(&[wrong_goto]).is_err());

    let mut wrong_action = output_rule();
    wrong_action["action"] = Value::from("blackhole");
    assert!(classify_policy_rules(&[wrong_action]).is_err());

    let foreign_reserved_priority = serde_json::json!({
      "priority": 99,
      "src": "all",
      "table": "main"
    });
    assert!(classify_policy_rules(&[foreign_reserved_priority]).is_err());
  }

  #[test]
  fn policy_rule_commands_preserve_legacy_output_priority_and_safe_order() {
    assert_eq!(
      POLICY_RULE_INSTALL_ORDER,
      [
        PolicyRuleKind::OutputRoute,
        PolicyRuleKind::SourceValidationGuard,
        PolicyRuleKind::PreroutingRoute,
      ]
    );
    assert_eq!(
      POLICY_RULE_DELETE_ORDER,
      [
        PolicyRuleKind::PreroutingRoute,
        PolicyRuleKind::SourceValidationGuard,
        PolicyRuleKind::OutputRoute,
      ]
    );
    assert_eq!(
      policy_rule_arguments(PolicyRuleKind::SourceValidationGuard, "add"),
      [
        "-4",
        "rule",
        "add",
        "priority",
        "98",
        "iif",
        "lo",
        "fwmark",
        "0x53000000/0xff000000",
        "goto",
        "100",
      ]
    );
    assert_eq!(
      policy_rule_arguments(PolicyRuleKind::PreroutingRoute, "add"),
      [
        "-4",
        "rule",
        "add",
        "priority",
        "99",
        "fwmark",
        "0x53000000/0xff000000",
        "lookup",
        "20230",
      ]
    );
    assert_eq!(
      policy_rule_arguments(PolicyRuleKind::OutputRoute, "add"),
      [
        "-4",
        "rule",
        "add",
        "priority",
        "100",
        "fwmark",
        "0x51000000/0xff000000",
        "lookup",
        "20230",
      ]
    );
  }

  #[test]
  fn prerouting_delete_failure_blocks_guard_but_not_output_cleanup() {
    let targets = PolicyRuleSet {
      source_validation_guard: true,
      prerouting_route: true,
      output_route: true,
    };

    let after_failed_prerouting_delete = targets;
    assert_eq!(
      policy_rule_deletion_decision(targets, after_failed_prerouting_delete),
      PolicyRuleDeletionDecision {
        remove_source_validation_guard: false,
        source_validation_guard_blocked: true,
        remove_output_route: true,
      }
    );

    let after_successful_prerouting_delete = PolicyRuleSet {
      prerouting_route: false,
      ..targets
    };
    assert_eq!(
      policy_rule_deletion_decision(targets, after_successful_prerouting_delete),
      PolicyRuleDeletionDecision {
        remove_source_validation_guard: true,
        source_validation_guard_blocked: false,
        remove_output_route: true,
      }
    );
  }

  #[test]
  fn partial_rollback_never_removes_a_guard_while_prerouting_remains() {
    let previous = PolicyRuleSet {
      source_validation_guard: false,
      prerouting_route: true,
      output_route: true,
    };
    let current = PolicyRuleSet {
      source_validation_guard: true,
      prerouting_route: true,
      output_route: true,
    };
    let targets = policy_rule_removal_targets(previous, current);

    assert_eq!(
      targets,
      PolicyRuleSet {
        source_validation_guard: true,
        prerouting_route: false,
        output_route: false,
      }
    );
    assert_eq!(
      policy_rule_deletion_decision(targets, current),
      PolicyRuleDeletionDecision {
        remove_source_validation_guard: false,
        source_validation_guard_blocked: true,
        remove_output_route: false,
      }
    );
  }

  #[test]
  fn legacy_rollback_removes_prerouting_before_its_guard() {
    let previous = PolicyRuleSet {
      output_route: true,
      ..PolicyRuleSet::default()
    };
    let current = PolicyRuleSet {
      source_validation_guard: true,
      prerouting_route: true,
      output_route: true,
    };
    let targets = policy_rule_removal_targets(previous, current);
    assert!(targets.prerouting_route);

    let after_prerouting_delete = PolicyRuleSet {
      prerouting_route: false,
      ..current
    };
    assert!(
      policy_rule_deletion_decision(targets, after_prerouting_delete)
        .remove_source_validation_guard
    );
  }

  #[test]
  fn source_validation_route_probe_uses_the_local_output_lookup() {
    assert_eq!(
      source_validation_route_get_arguments(),
      [
        "-j",
        "-4",
        "route",
        "get",
        "198.51.100.1",
        "mark",
        "0x53000000",
      ]
    );
  }

  #[test]
  fn ownership_journal_accepts_legacy_and_current_rule_installation_phases() {
    assert!(network_state_phase_is_supported("installing-rule"));
    assert!(network_state_phase_is_supported("installing-rules"));
    assert!(!network_state_phase_is_supported("installing-policy"));
  }

  #[test]
  fn reserved_objects_require_an_owned_table_or_valid_journal() {
    assert!(!reserved_objects_may_be_removed(false, false));
    assert!(reserved_objects_may_be_removed(true, false));
    assert!(reserved_objects_may_be_removed(false, true));
    assert!(reserved_objects_may_be_removed(true, true));
  }

  #[test]
  fn cleanup_failure_reports_every_failed_step() {
    let error = ensure_cleanup_complete(vec![
      "nft cleanup failed: simulated nft failure".to_owned(),
      "route inspection failed: simulated route failure".to_owned(),
    ])
    .unwrap_err()
    .to_string();

    assert!(error.contains("nft cleanup failed: simulated nft failure"));
    assert!(error.contains("route inspection failed: simulated route failure"));
    assert!(ensure_cleanup_complete(vec![]).is_ok());
  }

  #[test]
  fn parses_exact_proc_net_listener_address_state_and_uid() {
    let source = concat!(
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
      "   0: 0100007F:3039 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12345\n",
      "   1: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   999        0 12346\n",
    );
    let address = "127.0.0.1:12345".parse().unwrap();

    assert!(proc_net_has_socket(source, address, 999, "0A"));
    assert!(!proc_net_has_socket(source, address, 998, "0A"));
    assert!(!proc_net_has_socket(source, address, 999, "07"));
    assert!(!proc_net_has_socket(
      source,
      "127.0.0.2:12345".parse().unwrap(),
      999,
      "0A",
    ));

    let ipv6_source = concat!(
      "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
      "   0: 00000000000000000000000001000000:3039 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12347\n",
    );
    assert!(proc_net_has_socket(
      ipv6_source,
      "[::1]:12345".parse().unwrap(),
      999,
      "0A",
    ));
  }
}
