use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

pub struct GeoLite2 {
    reader: Arc<tokio::sync::Mutex<Option<GeoLite2Reader>>>,
    update_handle: tokio::task::JoinHandle<()>,
}

type GeoLite2Reader = maxminddb::Reader<Vec<u8>>;

impl GeoLite2 {
    pub async fn new(cache_path: &PathBuf, url: String, update_interval: Duration) -> Self {
        let modified_time = tokio::fs::metadata(&cache_path).await.map_or_else(
            |error| {
                if error.kind() == tokio::io::ErrorKind::NotFound {
                    None
                } else {
                    panic!("failed to get metadata of GeoLite2 database: {}", error);
                }
            },
            |metadata| Some(metadata.modified().unwrap()),
        );

        let next_update_time =
            modified_time.map_or_else(tokio::time::Instant::now, |modified_time| {
                tokio::time::Instant::now()
                    + (update_interval - SystemTime::now().duration_since(modified_time).unwrap())
            });

        let reader = modified_time.map(|_| {
            maxminddb::Reader::open_readfile(cache_path).expect("failed to open GeoLite2 database.")
        });

        let reader = Arc::new(tokio::sync::Mutex::new(reader));

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

    pub async fn lookup(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.lock().await;
        let reader = reader.as_ref()?;

        if let Result::<maxminddb::geoip2::Country, _>::Ok(result) = reader.lookup(ip) {
            result
                .country
                .and_then(|country| country.iso_code.map(|code| code.to_owned()))
        } else {
            None
        }
    }

    async fn schedule_reader_update(
        reader: Arc<tokio::sync::Mutex<Option<GeoLite2Reader>>>,
        cache_path: PathBuf,
        url: String,
        update_interval: Duration,
        next_update_time: tokio::time::Instant,
    ) {
        tokio::time::sleep_until(next_update_time).await;

        loop {
            async {
                log::info!("updating GeoLite2 database...");

                log::debug!("downloading GeoLite2 database from: {}", url);

                let data = reqwest::get(&url).await?.bytes().await?.to_vec();

                tokio::fs::write(&cache_path, &data).await?;

                reader
                    .lock()
                    .await
                    .replace(maxminddb::Reader::from_source(data)?);

                log::info!("GeoLite2 database updated successfully.");

                anyhow::Ok(())
            }
            .await
            .unwrap_or_else(|error| {
                log::error!("failed to download GeoLite2 database: {:?}", error);
            });

            tokio::time::sleep(update_interval).await;
        }
    }
}

impl Drop for GeoLite2 {
    fn drop(&mut self) {
        self.update_handle.abort();
    }
}
