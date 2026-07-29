use std::sync::LazyLock;

use hickory_resolver::{
  TokioResolver,
  config::{ResolverConfig, ResolverOpts},
  net::{DnsError, NetError, runtime::TokioRuntimeProvider},
  proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
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

      encode_success(message, &query.name)
    }
    Err(error) => resolve_error_answers(&error, &query.name, query.record_type),
  }
}

fn resolve_error_answers(error: &NetError, name: &str, record_type: u16) -> NodeResolveAnswers {
  match error {
    NetError::Dns(DnsError::NoRecordsFound(no_records)) => match no_records.response_code {
      ResponseCode::NoError => {
        // Hickory represents a valid NOERROR/NODATA response as NoRecordsFound.
        // Preserve that DNS meaning instead of turning common empty HTTPS/A/AAAA
        // answers into SERVFAIL.
        encode_success(Message::new(0, MessageType::Response, OpCode::Query), name)
      }
      ResponseCode::NXDomain => NodeResolveAnswers::NxDomain,
      _ => {
        log_resolve_failure(error, name, record_type);
        NodeResolveAnswers::Failure
      }
    },
    _ => {
      log_resolve_failure(error, name, record_type);
      NodeResolveAnswers::Failure
    }
  }
}

fn encode_success(message: Message, name: &str) -> NodeResolveAnswers {
  match message.to_vec() {
    Ok(bytes) => NodeResolveAnswers::Success(bytes),
    Err(error) => {
      log::warn!("failed to encode DNS answers for {name}: {error}");
      NodeResolveAnswers::Failure
    }
  }
}

fn log_resolve_failure(error: &NetError, name: &str, record_type: u16) {
  log::debug!("local DNS resolve failed for {name} type {record_type}: {error}");
}

#[cfg(test)]
mod tests {
  use hickory_resolver::{
    net::{DnsError, NetError, NoRecords},
    proto::{
      op::{Message, Query, ResponseCode},
      rr::{Name, RecordType},
    },
  };

  use super::resolve_error_answers;
  use crate::node::NodeResolveAnswers;

  fn no_records_error(response_code: ResponseCode) -> NetError {
    NoRecords::new(
      Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::HTTPS),
      response_code,
    )
    .into()
  }

  #[test]
  fn noerror_without_records_stays_successful_nodata() {
    let answers = resolve_error_answers(
      &no_records_error(ResponseCode::NoError),
      "example.com.",
      u16::from(RecordType::HTTPS),
    );
    let NodeResolveAnswers::Success(bytes) = answers else {
      panic!("NOERROR/NODATA was not preserved as a successful response");
    };
    let message = Message::from_vec(&bytes).unwrap();

    assert_eq!(message.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
  }

  #[test]
  fn nxdomain_stays_nxdomain() {
    assert!(matches!(
      resolve_error_answers(
        &no_records_error(ResponseCode::NXDomain),
        "example.com.",
        u16::from(RecordType::A),
      ),
      NodeResolveAnswers::NxDomain
    ));
  }

  #[test]
  fn other_dns_failures_stay_failures() {
    let error = NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail));
    assert!(matches!(
      resolve_error_answers(&error, "example.com.", u16::from(RecordType::A)),
      NodeResolveAnswers::Failure
    ));
  }
}
