use std::{
  collections::{HashMap, HashSet},
  fs, io,
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::{Duration, Instant, SystemTime},
};

use anyhow::Context as _;
use lits::duration;
use moka::sync::Cache;
use prost::{Enumeration, Message};
use regex::RegexSet;
use tokio::task::JoinSet;

use crate::primitives::{OutExit, SocketDestination};

use super::rule::GeositeDomainMatcher;

const GEOSITE_URL: &str =
  "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat";

const GEOSITE_FILE_NAME: &str = "dlc.dat";
const UPDATE_INTERVAL: Duration = duration!("24h");
const RETRY_INTERVAL: Duration = duration!("30s");
const DOWNLOAD_TIMEOUT: Duration = duration!("30s");
const CONNECT_TIMEOUT: Duration = duration!("10s");

type RouteCache = Cache<SocketDestination, Vec<OutExit>>;

pub struct Geosite {
  reader: Arc<Mutex<Option<GeositeDatabase>>>,
  path: PathBuf,
  next_update_time: Instant,
  route_cache: RouteCache,
  join_set: Mutex<JoinSet<()>>,
}

impl Geosite {
  pub(super) fn new(dir: impl AsRef<Path>, route_cache: RouteCache) -> Self {
    let path = dir.as_ref().join(GEOSITE_FILE_NAME);

    let modified_time = fs::metadata(&path).map_or_else(
      |error| {
        if error.kind() == io::ErrorKind::NotFound {
          None
        } else {
          panic!("failed to get metadata of Geosite database: {}", error);
        }
      },
      |metadata| Some(metadata.modified().unwrap()),
    );

    let next_update_time = modified_time.map_or_else(Instant::now, |modified_time| {
      Instant::now()
        + UPDATE_INTERVAL.saturating_sub(
          SystemTime::now()
            .duration_since(modified_time)
            .unwrap_or(Duration::ZERO),
        )
    });

    let reader = Arc::new(Mutex::new(modified_time.map(|_| {
      let data = fs::read(&path).expect("failed to read Geosite database.");
      GeositeDatabase::decode(&data).expect("failed to decode Geosite database.")
    })));

    Self {
      reader,
      path,
      next_update_time,
      route_cache,
      join_set: Mutex::new(JoinSet::new()),
    }
  }

  pub(super) fn ensure_updating(&self) {
    let mut join_set = self.join_set.lock().unwrap();

    if !join_set.is_empty() {
      return;
    }

    join_set.spawn(Self::schedule_reader_update(
      self.reader.clone(),
      self.path.clone(),
      self.next_update_time,
      self.route_cache.clone(),
    ));
  }

  pub(super) fn matches(&self, matcher: &GeositeDomainMatcher, domain: &str) -> bool {
    self
      .reader
      .lock()
      .unwrap()
      .as_mut()
      .is_some_and(|reader| reader.matches(matcher, domain))
  }

  async fn schedule_reader_update(
    reader: Arc<Mutex<Option<GeositeDatabase>>>,
    path: PathBuf,
    next_update_time: Instant,
    route_cache: RouteCache,
  ) {
    let client = reqwest::Client::builder()
      .connect_timeout(CONNECT_TIMEOUT)
      .timeout(DOWNLOAD_TIMEOUT)
      .build()
      .unwrap();

    tokio::time::sleep_until(next_update_time.into()).await;

    loop {
      let updated = async {
        log::info!("updating Geosite database...");

        let data = client
          .get(GEOSITE_URL)
          .send()
          .await?
          .error_for_status()?
          .bytes()
          .await?
          .to_vec();
        let database = GeositeDatabase::decode(&data)?;

        tokio::fs::write(&path, &data).await?;

        reader.lock().unwrap().replace(database);
        route_cache.invalidate_all();

        log::info!("Geosite database updated successfully.");

        anyhow::Ok(())
      }
      .await
      .map_or_else(
        |error| {
          log::error!("failed to update Geosite database: {:?}", error);
          false
        },
        |_| true,
      );

      tokio::time::sleep(if updated {
        UPDATE_INTERVAL
      } else {
        RETRY_INTERVAL
      })
      .await;
    }
  }
}

struct GeositeDatabase {
  sites: HashMap<String, Vec<ProtoDomain>>,
  matchers: HashMap<GeositeDomainMatcher, Option<CompiledGeositeMatcher>>,
}

impl GeositeDatabase {
  fn decode(data: &[u8]) -> anyhow::Result<Self> {
    let list = ProtoGeoSiteList::decode(data)?;
    let mut sites = HashMap::with_capacity(list.entry.len());

    for site in list.entry {
      let name = site.country_code.to_ascii_uppercase();

      anyhow::ensure!(
        !name.is_empty(),
        "Geosite database contains an empty list name"
      );
      anyhow::ensure!(
        sites.insert(name.clone(), site.domain).is_none(),
        "Geosite database contains duplicate list {name:?}"
      );
    }

    Ok(Self {
      sites,
      matchers: HashMap::new(),
    })
  }

  fn matches(&mut self, matcher: &GeositeDomainMatcher, domain: &str) -> bool {
    if !self.matchers.contains_key(matcher) {
      let compiled = self
        .compile(matcher)
        .inspect_err(|error| log::error!("{error:#}"))
        .ok();

      self.matchers.insert(matcher.clone(), compiled);
    }

    self
      .matchers
      .get(matcher)
      .and_then(Option::as_ref)
      .is_some_and(|matcher| matcher.matches(domain))
  }

  fn compile(&self, matcher: &GeositeDomainMatcher) -> anyhow::Result<CompiledGeositeMatcher> {
    let entries = self
      .sites
      .get(&matcher.site)
      .with_context(|| format!("Geosite list {:?} does not exist", matcher.site))?;

    CompiledGeositeMatcher::new(entries, &matcher.attributes)
      .with_context(|| format!("failed to compile Geosite list {:?}", matcher.site))
  }
}

struct CompiledGeositeMatcher {
  keywords: Vec<String>,
  regexes: Option<RegexSet>,
  root_domains: HashSet<String>,
  full_domains: HashSet<String>,
}

impl CompiledGeositeMatcher {
  fn new(entries: &[ProtoDomain], attributes: &[String]) -> anyhow::Result<Self> {
    let mut keywords = Vec::new();
    let mut regex_patterns = Vec::new();
    let mut root_domains = HashSet::new();
    let mut full_domains = HashSet::new();

    for entry in entries {
      if !attributes.is_empty()
        && !entry
          .attribute
          .iter()
          .any(|attribute| attributes.iter().any(|selected| selected == &attribute.key))
      {
        continue;
      }

      let value = entry.value.trim_end_matches('.');

      match ProtoDomainType::try_from(entry.r#type)
        .with_context(|| format!("unknown Geosite domain type {}", entry.r#type))?
      {
        ProtoDomainType::Plain => keywords.push(value.to_ascii_lowercase()),
        ProtoDomainType::Regex => regex_patterns.push(value.to_owned()),
        ProtoDomainType::RootDomain => {
          root_domains.insert(value.to_ascii_lowercase());
        }
        ProtoDomainType::Full => {
          full_domains.insert(value.to_ascii_lowercase());
        }
      }
    }

    let regexes = if regex_patterns.is_empty() {
      None
    } else {
      Some(RegexSet::new(regex_patterns)?)
    };

    Ok(Self {
      keywords,
      regexes,
      root_domains,
      full_domains,
    })
  }

  fn matches(&self, domain: &str) -> bool {
    self.full_domains.contains(domain)
      || root_domain_matches(&self.root_domains, domain)
      || self.keywords.iter().any(|keyword| domain.contains(keyword))
      || self
        .regexes
        .as_ref()
        .is_some_and(|regexes| regexes.is_match(domain))
  }
}

fn root_domain_matches(root_domains: &HashSet<String>, domain: &str) -> bool {
  let mut candidate = domain;

  loop {
    if root_domains.contains(candidate) {
      return true;
    }

    let Some((_, parent)) = candidate.split_once('.') else {
      return false;
    };

    candidate = parent;
  }
}

#[derive(Clone, PartialEq, Message)]
struct ProtoGeoSiteList {
  #[prost(message, repeated, tag = "1")]
  entry: Vec<ProtoGeoSite>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoGeoSite {
  #[prost(string, tag = "1")]
  country_code: String,
  #[prost(message, repeated, tag = "2")]
  domain: Vec<ProtoDomain>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoDomain {
  #[prost(enumeration = "ProtoDomainType", tag = "1")]
  r#type: i32,
  #[prost(string, tag = "2")]
  value: String,
  #[prost(message, repeated, tag = "3")]
  attribute: Vec<ProtoDomainAttribute>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoDomainAttribute {
  #[prost(string, tag = "1")]
  key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
enum ProtoDomainType {
  Plain = 0,
  Regex = 1,
  RootDomain = 2,
  Full = 3,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn matches_all_geosite_domain_types_and_attributes() {
    let data = ProtoGeoSiteList {
      entry: vec![ProtoGeoSite {
        country_code: "test".to_owned(),
        domain: vec![
          proto_domain(ProtoDomainType::RootDomain, "root.example"),
          proto_domain(ProtoDomainType::Full, "full.example"),
          proto_domain(ProtoDomainType::Plain, "keyword"),
          proto_domain(ProtoDomainType::Regex, r"^regex[0-9]+\.example$"),
          ProtoDomain {
            attribute: vec![ProtoDomainAttribute {
              key: "cn".to_owned(),
            }],
            ..proto_domain(ProtoDomainType::RootDomain, "china.example")
          },
        ],
      }],
    }
    .encode_to_vec();
    let mut database = GeositeDatabase::decode(&data).unwrap();
    let matcher = GeositeDomainMatcher::parse("geosite:test");

    assert!(database.matches(&matcher, "root.example"));
    assert!(database.matches(&matcher, "www.root.example"));
    assert!(!database.matches(&matcher, "notroot.example"));
    assert!(database.matches(&matcher, "full.example"));
    assert!(!database.matches(&matcher, "www.full.example"));
    assert!(database.matches(&matcher, "has-keyword.example"));
    assert!(database.matches(&matcher, "regex42.example"));

    let matcher = GeositeDomainMatcher::parse("geosite:test@cn");

    assert!(database.matches(&matcher, "www.china.example"));
    assert!(!database.matches(&matcher, "root.example"));
  }

  fn proto_domain(r#type: ProtoDomainType, value: &str) -> ProtoDomain {
    ProtoDomain {
      r#type: r#type as i32,
      value: value.to_owned(),
      attribute: vec![],
    }
  }
}
