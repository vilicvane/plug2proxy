use std::{
  fs, io,
  net::IpAddr,
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::{Duration, Instant, SystemTime},
};

use lits::duration;
use lowkit::{SelfWrapExt, tokio_join_set};
use maxminddb::geoip2::Country;
use tokio::task::JoinSet;

const GEOLITE2_URL: &str =
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb";

const UPDATE_INTERVAL: Duration = duration!("24h");
const RETRY_INTERVAL: Duration = duration!("30s");

pub struct GeoLite2 {
  reader: Arc<Mutex<Option<GeoLite2Reader>>>,
  _join_set: JoinSet<()>,
}

type GeoLite2Reader = maxminddb::Reader<Vec<u8>>;

impl GeoLite2 {
  pub fn new(dir: impl AsRef<Path>) -> Self {
    let path = dir.as_ref().join("geolite2.mmdb");

    let (reader, next_update_time) = match fs::metadata(&path) {
      Ok(metadata) => match maxminddb::Reader::open_readfile(&path) {
        Ok(reader) => {
          let modified_time = metadata.modified().unwrap();
          let next_update_time = Instant::now()
            + (UPDATE_INTERVAL.saturating_sub(
              SystemTime::now()
                .duration_since(modified_time)
                .unwrap_or(Duration::from_secs(0)),
            ));

          (Some(reader), next_update_time)
        }
        Err(error) => {
          log::error!(
            "failed to open GeoLite2 database at {}: {error}; scheduling an immediate update",
            path.display()
          );
          (None, Instant::now())
        }
      },
      Err(error) if error.kind() == io::ErrorKind::NotFound => (None, Instant::now()),
      Err(error) => panic!("failed to get metadata of GeoLite2 database: {error}"),
    };

    let reader = reader.mutex().arc();

    Self {
      reader: reader.clone(),
      _join_set: tokio_join_set!(Self::schedule_reader_update(reader, path, next_update_time)),
    }
  }

  pub fn lookup(&self, ip: IpAddr) -> Option<Vec<String>> {
    let reader = self.reader.lock().unwrap();

    let record: Country = reader
      .as_ref()?
      .lookup(ip)
      .and_then(|record| record.decode())
      .inspect_err(|error| log::error!("failed to lookup IP address: {}", error))
      .ok()?
      .flatten()?;

    region_codes(&record)
  }

  async fn schedule_reader_update(
    reader: Arc<Mutex<Option<GeoLite2Reader>>>,
    path: PathBuf,
    next_update_time: Instant,
  ) {
    tokio::time::sleep_until(next_update_time.into()).await;

    loop {
      let updated = async {
        log::info!("updating GeoLite2 database...");

        let data = reqwest::get(GEOLITE2_URL)
          .await?
          .error_for_status()?
          .bytes()
          .await?
          .to_vec();

        install_database(&reader, &path, data).await?;

        log::info!("GeoLite2 database updated successfully.");

        anyhow::Ok(())
      }
      .await
      .map_or_else(
        |error| {
          log::error!("failed to download GeoLite2 database: {:?}", error);
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

async fn install_database(
  reader: &Arc<Mutex<Option<GeoLite2Reader>>>,
  path: &Path,
  data: Vec<u8>,
) -> anyhow::Result<()> {
  let new_reader = maxminddb::Reader::from_source(data.clone())?;
  let temporary_path = path.with_extension(format!("mmdb.{}.tmp", uuid::Uuid::new_v4()));

  tokio::fs::write(&temporary_path, &data).await?;
  tokio::fs::rename(&temporary_path, path).await?;
  reader.lock().unwrap().replace(new_reader);

  Ok(())
}

fn region_codes(record: &Country<'_>) -> Option<Vec<String>> {
  let mut codes = Vec::new();

  if let Some(iso_code) = record
    .country
    .iso_code
    .or(record.registered_country.iso_code)
  {
    codes.push(iso_code.to_string());
  }

  if let Some(code) = record.continent.code {
    codes.push(code.to_string());
  }

  if codes.is_empty() { None } else { Some(codes) }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, Mutex};

  use maxminddb::geoip2::{Country, country};

  use super::{GeoLite2, install_database, region_codes};
  use crate::test::test_dir;

  #[tokio::test]
  async fn invalid_download_does_not_replace_existing_database() {
    let dir = test_dir().join(format!("geolite_invalid_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("geolite2.mmdb");
    let existing = b"existing database placeholder";
    tokio::fs::write(&path, existing).await.unwrap();

    let reader = Arc::new(Mutex::new(None));
    install_database(&reader, &path, b"not a MaxMind database".to_vec())
      .await
      .unwrap_err();

    assert_eq!(tokio::fs::read(path).await.unwrap(), existing);
    assert!(reader.lock().unwrap().is_none());
  }

  #[tokio::test]
  async fn invalid_existing_database_recovers_without_panicking() {
    let dir = test_dir().join(format!("geolite_existing_{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(dir.join("geolite2.mmdb"), b"not a MaxMind database")
      .await
      .unwrap();

    let database = GeoLite2::new(dir);

    assert!(database.lookup("127.0.0.1".parse().unwrap()).is_none());
  }

  #[test]
  fn region_codes_falls_back_to_registered_country() {
    let record = Country {
      registered_country: country::Country {
        iso_code: Some("US"),
        ..Default::default()
      },
      ..Default::default()
    };

    assert_eq!(region_codes(&record), Some(vec!["US".to_string()]));
  }

  #[test]
  fn region_codes_prefers_country() {
    let record = Country {
      country: country::Country {
        iso_code: Some("CN"),
        ..Default::default()
      },
      registered_country: country::Country {
        iso_code: Some("US"),
        ..Default::default()
      },
      continent: country::Continent {
        code: Some("AS"),
        ..Default::default()
      },
      ..Default::default()
    };

    assert_eq!(
      region_codes(&record),
      Some(vec!["CN".to_string(), "AS".to_string()])
    );
  }
}
