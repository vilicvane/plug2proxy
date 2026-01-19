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

    let modified_time = fs::metadata(&path).map_or_else(
      |error| {
        if error.kind() == io::ErrorKind::NotFound {
          None
        } else {
          panic!("failed to get metadata of GeoLite2 database: {}", error);
        }
      },
      |metadata| Some(metadata.modified().unwrap()),
    );

    let next_update_time = modified_time.map_or_else(Instant::now, |modified_time| {
      Instant::now()
        + (UPDATE_INTERVAL.saturating_sub(
          SystemTime::now()
            .duration_since(modified_time)
            .unwrap_or(Duration::from_secs(0)),
        ))
    });

    let reader = modified_time
      .map(|_| maxminddb::Reader::open_readfile(&path).expect("failed to open GeoLite2 database."))
      .mutex()
      .arc();

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

    let mut codes = Vec::new();

    if let Some(iso_code) = record.country.iso_code {
      codes.push(iso_code.to_string());
    }

    if let Some(code) = record.continent.code {
      codes.push(code.to_string());
    }

    if codes.is_empty() { None } else { Some(codes) }
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

        let data = reqwest::get(GEOLITE2_URL).await?.bytes().await?.to_vec();

        tokio::fs::write(&path, &data).await?;

        reader
          .lock()
          .unwrap()
          .replace(maxminddb::Reader::from_source(data)?);

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
