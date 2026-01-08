use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use maxminddb::Reader;

/// GeoLite2 database reader for IP geolocation.
/// Supports reloading the database from disk without restarting.
#[derive(Clone)]
pub struct GeoLite2 {
    path: PathBuf,
    reader: Arc<RwLock<Reader<Vec<u8>>>>,
}

impl GeoLite2 {
    /// Open a GeoLite2 database from file.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, maxminddb::MaxMindDBError> {
        let path = path.into();
        let reader = Reader::open_readfile(&path)?;
        Ok(Self {
            path,
            reader: Arc::new(RwLock::new(reader)),
        })
    }

    /// Reload the database from disk.
    /// This allows picking up updates without restarting the application.
    pub fn reload(&self) -> Result<(), maxminddb::MaxMindDBError> {
        let new_reader = Reader::open_readfile(&self.path)?;
        let mut writer = self.reader.write().unwrap();
        *writer = new_reader;
        tracing::info!("GeoIP database reloaded from: {:?}", self.path);
        Ok(())
    }

    /// Lookup an IP address and return region codes.
    ///
    /// Returns a list of region codes (country ISO code, continent code).
    /// Returns None if the IP is not found in the database.
    pub fn lookup(&self, ip: IpAddr) -> Option<Vec<String>> {
        let reader = self.reader.read().unwrap();
        let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;

        let mut codes = Vec::new();

        // Add country ISO code (e.g., "CN", "US")
        if let Some(country) = record.country {
            if let Some(iso_code) = country.iso_code {
                codes.push(iso_code.to_owned());
            }
        }

        // Add continent code (e.g., "AS", "EU", "NA")
        if let Some(continent) = record.continent {
            if let Some(code) = continent.code {
                codes.push(code.to_owned());
            }
        }

        if codes.is_empty() { None } else { Some(codes) }
    }
}

impl std::fmt::Debug for GeoLite2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoLite2").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::Path;

    #[test]
    fn test_geolite2_lookup() {
        // This test requires the database file to exist
        let db_path = "tmp/configs/deployment/local/geolite2.mmdb";
        if !Path::new(db_path).exists() {
            println!("Skipping test: {} not found", db_path);
            return;
        }

        let geolite2 = GeoLite2::open(db_path).expect("Failed to open GeoLite2 database");

        // Test a well-known IP (Google DNS)
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = geolite2.lookup(ip);
        println!("8.8.8.8 region codes: {:?}", result);
        assert!(result.is_some());

        // Test localhost (should return None or empty)
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = geolite2.lookup(ip);
        println!("127.0.0.1 region codes: {:?}", result);
    }
}
