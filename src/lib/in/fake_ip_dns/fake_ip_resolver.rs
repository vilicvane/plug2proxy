use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Mutex,
};

use rusqlite::OptionalExtension as _;

pub struct FakeIpResolver {
    sqlite_connection: Mutex<rusqlite::Connection>,
    fake_ipv4_net: ipnet::Ipv4Net,
    fake_ipv6_net: ipnet::Ipv6Net,
}

impl FakeIpResolver {
    pub fn new<TPath: AsRef<Path>>(
        db_path: TPath,
        fake_ipv4_net: ipnet::Ipv4Net,
        fake_ipv6_net: ipnet::Ipv6Net,
    ) -> Self {
        let sqlite_connection = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();

        Self {
            sqlite_connection: Mutex::new(sqlite_connection),
            fake_ipv4_net,
            fake_ipv6_net,
        }
    }

    pub fn resolve(&self, ip: &IpAddr) -> Option<(IpAddr, Option<String>)> {
        let fake_ip_type_and_id = match ip {
            IpAddr::V4(ipv4) => {
                if self.fake_ipv4_net.contains(ipv4) {
                    Some((
                        hickory_client::rr::RecordType::A,
                        (ipv4.to_bits() - self.fake_ipv4_net.network().to_bits()) as i64,
                    ))
                } else {
                    None
                }
            }
            IpAddr::V6(ipv6) => {
                if self.fake_ipv6_net.contains(ipv6) {
                    Some((
                        hickory_client::rr::RecordType::AAAA,
                        (ipv6.to_bits() - self.fake_ipv6_net.network().to_bits()) as i64,
                    ))
                } else {
                    None
                }
            }
        };

        if let Some((r#type, id)) = fake_ip_type_and_id {
            let record: Option<(String, Vec<u8>)> = self
                .sqlite_connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT name, real_ip FROM records WHERE type = ? AND id = ?",
                    rusqlite::params![r#type.to_string(), id],
                    |row| Ok((row.get("name")?, row.get("real_ip")?)),
                )
                .optional()
                .unwrap();

            if let Some((name, real_ip)) = record {
                let name = name.trim_end_matches(".").to_owned();

                let real_ip = match r#type {
                    hickory_client::rr::RecordType::A => IpAddr::V4(Ipv4Addr::from_bits(
                        u32::from_be_bytes(real_ip.try_into().unwrap()),
                    )),
                    hickory_client::rr::RecordType::AAAA => IpAddr::V6(Ipv6Addr::from_bits(
                        u128::from_be_bytes(real_ip.try_into().unwrap()),
                    )),
                    _ => unreachable!(),
                };

                log::debug!("fake ip {ip} translated to {real_ip} ({name}).");

                Some((real_ip, Some(name)))
            } else {
                log::warn!("fake ip {ip} not found.");

                None
            }
        } else {
            Some((*ip, None))
        }
    }
}
