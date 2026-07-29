use std::sync::LazyLock;

use hickory_resolver::{
  TokioResolver,
  config::{ResolverConfig, ResolverOpts},
  net::{NetError, runtime::TokioRuntimeProvider},
  proto::{
    op::{Message, MessageType, OpCode},
    rr::{Name, RecordType},
  },
  system_conf,
};

use crate::node::{NodeResolveAnswers, ResolveQuery};

/// systemd-resolved 的真实上行列表（/etc/resolv.conf 是本地 stub 时使用）。
const SYSTEMD_RESOLVED_UPLINK_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";

static LOCAL_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
  let (config, options) = load_upstream_config().expect("failed to load DNS upstream config");
  let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
  *builder.options_mut() = options;
  builder.build().expect("failed to build DNS resolver")
});

pub fn local_resolver() -> &'static TokioResolver {
  &LOCAL_RESOLVER
}

/// 本机解析：避免 本机 -> sing-box -> plug2proxy -> 本机 的循环。
///
/// systemd-resolved 的 /etc/resolv.conf 是 loopback stub，其上行查询会被
/// TUN 劫持送回 plug2proxy；此时改用真实上行文件。plug2proxy 自身 UID 已被
/// sing-box exclude_uid 排除，其上游查询不会被劫持回来。
fn load_upstream_config() -> Result<(ResolverConfig, ResolverOpts), NetError> {
  let (config, options) = system_conf::read_system_conf()?;

  let loopback_only = config
    .name_servers()
    .iter()
    .all(|server| server.ip.is_loopback());

  if !loopback_only {
    return Ok((config, options));
  }

  let Ok(data) = std::fs::read(SYSTEMD_RESOLVED_UPLINK_RESOLV_CONF) else {
    return Ok((config, options));
  };

  let (uplink_config, _) = system_conf::parse_resolv_conf(data)?;

  let uplink_loopback_only = uplink_config
    .name_servers()
    .iter()
    .all(|server| server.ip.is_loopback());

  if uplink_loopback_only {
    return Ok((config, options));
  }

  log::info!(
    "system DNS resolver is a loopback stub; using systemd-resolved uplinks from \
     {SYSTEMD_RESOLVED_UPLINK_RESOLV_CONF} to avoid the sing-box DNS loop"
  );

  Ok((uplink_config, options))
}

/// 在本机执行解析，把应答 records 编码为 DNS wire format 的完整 Message。
pub async fn resolve_locally(query: &ResolveQuery) -> NodeResolveAnswers {
  let Ok(name) = Name::from_str_relaxed(&query.name) else {
    return NodeResolveAnswers::Failure;
  };
  let record_type = RecordType::from(query.record_type);

  match local_resolver().lookup(name, record_type).await {
    Ok(lookup) => {
      let mut message = Message::new(0, MessageType::Response, OpCode::Query);
      message.add_answers(lookup.answers().iter().cloned());

      match message.to_vec() {
        Ok(bytes) => NodeResolveAnswers::Success(bytes),
        Err(error) => {
          log::warn!("failed to encode DNS answers for {}: {}", query.name, error);
          NodeResolveAnswers::Failure
        }
      }
    }
    Err(error) if error.is_nx_domain() => NodeResolveAnswers::NxDomain,
    Err(error) => {
      log::debug!(
        "local DNS resolve failed for {} type {}: {}",
        query.name,
        query.record_type,
        error
      );
      NodeResolveAnswers::Failure
    }
  }
}
