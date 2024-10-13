use std::{
    fs, io,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

const RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub struct GeoLite2 {
    reader: Arc<Mutex<Option<GeoLite2Reader>>>,
    update_handle: tokio::task::JoinHandle<()>,
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

        let reader = modified_time.map(|_| {
            maxminddb::Reader::open_readfile(cache_path).expect("failed to open GeoLite2 database.")
        });

        let reader = Arc::new(Mutex::new(reader));

        let update_handle = tokio::spawn(Self::schedule_reader_update(
            reader.clone(),
            cache_path.clone(),
            url,
            update_interval,
            next_update_time,
        ));

        Self {
            reader,
            update_handle,
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Vec<String>> {
        let reader = self.reader.lock().unwrap();
        let reader = reader.as_ref()?;

        if let Result::<maxminddb::geoip2::Country, _>::Ok(record) = reader.lookup(ip) {
            let mut codes = Vec::new();

            if let Some(country) = record.country {
                if let Some(iso_code) = country.iso_code {
                    codes.push(iso_code.to_owned());
                }
            }

            if let Some(continent) = record.continent {
                if let Some(code) = continent.code {
                    codes.push(code.to_owned());
                }
            }

            Some(codes)
        } else {
            None
        }
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

impl Drop for GeoLite2 {
    fn drop(&mut self) {
        self.update_handle.abort();
    }
}
