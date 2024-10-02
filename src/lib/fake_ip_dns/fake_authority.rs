use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, Mutex},
};

use hickory_client::{
    op::Query,
    proto::rr::LowerName,
    rr::{
        rdata::{A, AAAA},
        DNSClass, RData, Record, RecordType,
    },
};
use hickory_resolver::{
    config::{NameServerConfig, NameServerConfigGroup, Protocol},
    lookup::Lookup,
    TokioAsyncResolver,
};
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
    resolver: TokioAsyncResolver,
    sqlite_connection: Mutex<rusqlite::Connection>,
}

impl FakeAuthority {
    pub fn new(db_path: &str) -> Self {
        let resolver = {
            let mut config = hickory_resolver::config::ResolverConfig::new();

            // config.add_name_server(NameServerConfig::new(
            //     "223.6.6.6:53".parse().unwrap(),
            //     Protocol::Udp,
            // ));

            // config.add_name_server(NameServerConfig {
            //     socket_addr: "223.6.6.6:853".parse().unwrap(),
            //     protocol: Protocol::Tls,
            //     tls_dns_name: Some("dns.alidns.com".to_owned()),
            //     trust_negative_responses: true,
            //     // tls_config: None,
            //     bind_addr: None,
            // });

            // let mut roots = rustls::RootCertStore::empty();

            // for cert in rustls_native_certs::load_native_certs().unwrap() {
            //     roots.add(cert).unwrap();
            // }

            // let client_config = rustls::ClientConfig::builder()
            //     .with_root_certificates(roots)
            //     .with_no_client_auth();

            // config.set_tls_client_config(Arc::new());

            config.add_name_server(NameServerConfig {
                socket_addr: "8.8.8.8:853".parse().unwrap(),
                protocol: Protocol::Tls,
                tls_dns_name: Some("8.8.8.8".to_owned()),
                trust_negative_responses: true,
                // tls_config: None,
                bind_addr: None,
            });

            hickory_resolver::TokioAsyncResolver::new(
                config,
                hickory_resolver::config::ResolverOpts::default(),
                hickory_resolver::name_server::TokioConnectionProvider::default(),
            )
        };

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

    fn assign_fake_ip(
        &self,
        type_: RecordType,
        name: &LowerName,
        upstream_record: &Record,
    ) -> IpAddr {
        let now = ms_since_epoch();

        let real_ip = match upstream_record.data().unwrap() {
            RData::A(A(ip)) => IpAddr::V4(*ip),
            RData::AAAA(AAAA(ip)) => IpAddr::V6(*ip),
            _ => unreachable!(),
        };

        let real_ip = match real_ip {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };

        let expires_at = now + FAKE_IP_EXPIRATION_TIME_IN_MS;

        let connection = self.sqlite_connection.lock().unwrap();

        {
            // update a matching record.

            let id: Option<i64> = connection
                .query_row(
                    "SELECT id FROM records WHERE type = ? AND name = ?",
                    rusqlite::params![type_.to_string(), name.to_string()],
                    |row| row.get("id"),
                )
                .optional()
                .unwrap();

            if let Some(id) = id {
                connection
                    .execute(
                        "UPDATE records SET real_ip = ?, expires_at = ? WHERE id = ?",
                        rusqlite::params![real_ip, expires_at, id],
                    )
                    .unwrap();

                return self.convert_id_to_fake_ip(id, type_);
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
                        rusqlite::params![type_.to_string(), name.to_string(), real_ip, expires_at, id],
                    )
                    .unwrap();

                return self.convert_id_to_fake_ip(id, type_);
            }
        }

        {
            // insert a new record.

            connection
                .execute(
                    "INSERT INTO records (type, name, real_ip, expires_at) VALUES (?, ?, ?, ?)",
                    rusqlite::params![type_.to_string(), name.to_string(), real_ip, expires_at],
                )
                .unwrap();

            let id = connection.last_insert_rowid();

            self.convert_id_to_fake_ip(id, type_)
        }
    }

    fn convert_id_to_fake_ip(&self, id: i64, type_: RecordType) -> IpAddr {
        match type_ {
            RecordType::A => {
                let bits = self.fake_ip_v4_start + id as u32;
                IpAddr::V4(bits.into())
            }
            RecordType::AAAA => {
                let bits = self.fake_ip_v6_start + id as u128;
                IpAddr::V6(bits.into())
            }
            _ => unreachable!(),
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

                let fake_ip = self.assign_fake_ip(record_type, name, upstream_record);

                let mut record = Record::new();

                let data = match fake_ip {
                    IpAddr::V4(ipv4) => RData::A(A::from(ipv4)),
                    IpAddr::V6(ipv6) => RData::AAAA(AAAA::from(ipv6)),
                };

                record
                    .set_name(name.into())
                    .set_rr_type(record_type)
                    .set_dns_class(DNSClass::IN)
                    .set_ttl(60)
                    .set_data(Some(data));

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
