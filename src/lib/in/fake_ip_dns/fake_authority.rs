use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use hickory_client::{
    op::Query,
    proto::rr::LowerName,
    rr::{
        rdata::{
            svcb::{IpHint, SvcParamKey, SvcParamValue},
            A, AAAA, HTTPS, SVCB,
        },
        RData, RecordType,
    },
};
use hickory_resolver::{lookup::Lookup, TokioAsyncResolver};
use hickory_server::{
    authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
    server::RequestInfo,
    store::forwarder::ForwardLookup,
};
use rusqlite::OptionalExtension;

use crate::utils::time::ms_since_epoch;

const DAY_IN_MS: u64 = 86_400_000;

const FAKE_IP_EXPIRATION_TIME_IN_MS: u64 = DAY_IN_MS * 7;

pub struct FakeAuthority {
    origin: LowerName,
    fake_ip_v4_start: u32,
    fake_ip_v6_start: u128,
    resolver: Arc<TokioAsyncResolver>,
    sqlite_connection: Mutex<rusqlite::Connection>,
}

impl FakeAuthority {
    pub fn new(resolver: Arc<TokioAsyncResolver>, db_path: &PathBuf) -> Self {
        let sqlite_connection = rusqlite::Connection::open(db_path).unwrap();

        sqlite_connection
            .execute(
                r#"
                    CREATE TABLE IF NOT EXISTS records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type STRING NOT NULL,
                        name STRING NOT NULL,
                        real_ip STRING NOT NULL,
                        expires_at INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_type ON records (type);
                    CREATE INDEX IF NOT EXISTS idx_name ON records (name);
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_type_name ON records (type, name);
                    CREATE INDEX IF NOT EXISTS idx_expires_at ON records (expires_at);
                "#,
                [],
            )
            .expect("failed to initialize DNS records table.");

        Self {
            origin: LowerName::from_str(".").unwrap(),
            fake_ip_v4_start: Ipv4Addr::new(198, 18, 0, 0).to_bits(),
            fake_ip_v6_start: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0).to_bits(),
            resolver,
            sqlite_connection: Mutex::new(rusqlite::Connection::open(db_path).unwrap()),
        }
    }

    fn assign_fake_ip(&self, name: &LowerName, real_ip: &IpAddr) -> IpAddr {
        let now = ms_since_epoch();

        let (record_type, real_ip_octets) = match real_ip {
            IpAddr::V4(ipv4) => ("A", ipv4.octets().to_vec()),
            IpAddr::V6(ipv6) => ("AAAA", ipv6.octets().to_vec()),
        };

        let expires_at = now + FAKE_IP_EXPIRATION_TIME_IN_MS;

        let connection = self.sqlite_connection.lock().unwrap();

        {
            // update a matching record.

            let id: Option<i64> = connection
                .query_row(
                    "SELECT id FROM records WHERE type = ? AND name = ?",
                    rusqlite::params![record_type, name.to_string()],
                    |row| row.get("id"),
                )
                .optional()
                .unwrap();

            if let Some(id) = id {
                connection
                    .execute(
                        "UPDATE records SET real_ip = ?, expires_at = ? WHERE id = ?",
                        rusqlite::params![real_ip_octets, expires_at, id],
                    )
                    .unwrap();

                return self.convert_id_to_fake_ip(id, real_ip);
            }
        }

        {
            // replace an expired record.

            let id: Option<i64> = connection
                .query_row(
                    "SELECT id FROM records WHERE expires_at <= ? ORDER BY expires_at ASC",
                    rusqlite::params![now],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();

            if let Some(id) = id {
                connection
                    .execute(
                        "UPDATE records SET type = ?, name = ?, real_ip = ?, expires_at = ? WHERE id = ?",
                        rusqlite::params![record_type, name.to_string(), real_ip_octets, expires_at, id],
                    )
                    .unwrap();

                return self.convert_id_to_fake_ip(id, real_ip);
            }
        }

        {
            // insert a new record.

            connection
                .execute(
                    "INSERT INTO records (type, name, real_ip, expires_at) VALUES (?, ?, ?, ?)",
                    rusqlite::params![record_type, name.to_string(), real_ip_octets, expires_at],
                )
                .unwrap();

            let id = connection.last_insert_rowid();

            self.convert_id_to_fake_ip(id, real_ip)
        }
    }

    fn convert_id_to_fake_ip(&self, id: i64, real_ip: &IpAddr) -> IpAddr {
        match real_ip {
            IpAddr::V4(_) => {
                let bits = self.fake_ip_v4_start + id as u32;
                IpAddr::V4(bits.into())
            }
            IpAddr::V6(_) => {
                let bits = self.fake_ip_v6_start + id as u128;
                IpAddr::V6(bits.into())
            }
        }
    }
}

#[async_trait::async_trait]
impl Authority for FakeAuthority {
    type Lookup = ForwardLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        unimplemented!()
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        let lookup = self.resolver.lookup(name, record_type).await?;

        match record_type {
            RecordType::A | RecordType::AAAA => {
                let upstream_record = lookup
                    .record_iter()
                    .find(|record| record.record_type() == record_type);

                let Some(upstream_record) = upstream_record else {
                    return Ok(ForwardLookup(lookup));
                };

                let real_ip = match upstream_record.data().unwrap() {
                    RData::A(A(ip)) => IpAddr::V4(*ip),
                    RData::AAAA(AAAA(ip)) => IpAddr::V6(*ip),
                    _ => return Ok(ForwardLookup(lookup)),
                };

                let fake_ip = self.assign_fake_ip(name, &real_ip);

                let mut record = upstream_record.clone();

                let data = match fake_ip {
                    IpAddr::V4(ipv4) => RData::A(A::from(ipv4)),
                    IpAddr::V6(ipv6) => RData::AAAA(AAAA::from(ipv6)),
                };

                record.set_ttl(60).set_data(Some(data));

                Ok(ForwardLookup(Lookup::new_with_max_ttl(
                    Query::query(name.into(), record_type),
                    Arc::new([record]),
                )))
            }
            RecordType::HTTPS => {
                let upstream_record = lookup
                    .record_iter()
                    .find(|record| record.record_type() == record_type);

                let Some(upstream_record) = upstream_record else {
                    return Ok(ForwardLookup(lookup));
                };

                let svcb = match upstream_record.data().unwrap() {
                    RData::HTTPS(HTTPS(svcb)) => svcb,
                    _ => return Ok(ForwardLookup(lookup)),
                };

                let mut svcb_params = Vec::new();

                for (key, value) in svcb.svc_params().iter() {
                    let real_ip = match key {
                        SvcParamKey::Ipv4Hint => match value {
                            SvcParamValue::Ipv4Hint(IpHint(items)) => match items.first() {
                                Some(A(ip)) => IpAddr::V4(*ip),
                                _ => return Ok(ForwardLookup(lookup)),
                            },
                            _ => return Ok(ForwardLookup(lookup)),
                        },
                        SvcParamKey::Ipv6Hint => match value {
                            SvcParamValue::Ipv6Hint(IpHint(items)) => match items.first() {
                                Some(AAAA(ip)) => IpAddr::V6(*ip),
                                _ => return Ok(ForwardLookup(lookup)),
                            },
                            _ => return Ok(ForwardLookup(lookup)),
                        },
                        _ => {
                            svcb_params.push((*key, value.clone()));

                            continue;
                        }
                    };

                    let fake_ip = self.assign_fake_ip(name, &real_ip);

                    let value = match fake_ip {
                        IpAddr::V4(ipv4) => SvcParamValue::Ipv4Hint(IpHint(vec![A(ipv4)])),
                        IpAddr::V6(ipv6) => SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(ipv6)])),
                    };

                    svcb_params.push((*key, value));
                }

                let mut record = upstream_record.clone();

                let data = RData::HTTPS(HTTPS(SVCB::new(
                    svcb.svc_priority(),
                    svcb.target_name().clone(),
                    svcb_params,
                )));

                record.set_ttl(60).set_data(Some(data));

                Ok(ForwardLookup(Lookup::new_with_max_ttl(
                    Query::query(name.into(), record_type),
                    Arc::new([record]),
                )))
            }
            _ => Ok(ForwardLookup(lookup)),
        }
    }

    async fn search(
        &self,
        request: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(
            request.query.name(),
            request.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        unimplemented!()
    }
}
