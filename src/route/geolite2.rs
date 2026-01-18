use std::{
  fs, io,
  net::IpAddr,
  path::PathBuf,
  sync::{Arc, Mutex},
  time::{Duration, Instant, SystemTime},
};

use lowkit::{SelfWrapExt, tokio_join_set};
use maxminddb::geoip2::Country;
use tokio::task::JoinSet;

const RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub struct GeoLite2 {
  reader: Arc<Mutex<Option<GeoLite2Reader>>>,
  _join_set: JoinSet<()>,
}

type GeoLite2Reader = maxminddb::Reader<Vec<u8>>;

impl GeoLite2 {
  pub fn new(cache_path: &PathBuf, url: String, update_interval: Duration) -> Self {
    let modified_time = fs::metadata(cache_path).map_or_else(
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
        + (update_interval.saturating_sub(
          SystemTime::now()
            .duration_since(modified_time)
            .unwrap_or(Duration::from_secs(0)),
        ))
    });

    let reader = modified_time
      .map(|_| {
        maxminddb::Reader::open_readfile(cache_path).expect("failed to open GeoLite2 database.")
      })
      .mutex()
      .arc();

    Self {
      reader: reader.clone(),
      _join_set: tokio_join_set!(Self::schedule_reader_update(
        reader,
        cache_path.clone(),
        url,
        update_interval,
        next_update_time,
      )),
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
    cache_path: PathBuf,
    url: String,
    update_interval: Duration,
    next_update_time: Instant,
  ) {
    tokio::time::sleep_until(next_update_time.into()).await;

    loop {
      let updated = async {
        log::info!("updating GeoLite2 database...");

        log::debug!("downloading GeoLite2 database from: {}", url);

        let data = reqwest::get(&url).await?.bytes().await?.to_vec();

        tokio::fs::write(&cache_path, &data).await?;

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
        update_interval
      } else {
        RETRY_INTERVAL
      })
      .await;
    }
  }
}
