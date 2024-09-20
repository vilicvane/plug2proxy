use std::{str::FromStr, sync::Mutex};

use hickory_client::{proto::rr::LowerName, rr::RecordType};
use hickory_resolver::{Resolver, TokioAsyncResolver};
use hickory_server::{
    authority::{
        self, AuthLookup, Authority, LookupError, LookupOptions, MessageRequest, UpdateResult,
        ZoneType,
    },
    server::RequestInfo,
    store::forwarder::ForwardLookup,
};

pub struct FakeAuthority {
    origin: LowerName,
    resolver: TokioAsyncResolver,
    sqlite_connection: Mutex<rusqlite::Connection>,
}

impl FakeAuthority {
    pub fn new(resolver: TokioAsyncResolver) -> Self {
        Self {
            origin: LowerName::from_str(".").unwrap(),
            resolver,
            sqlite_connection: Mutex::new(
                rusqlite::Connection::open_with_flags(
                    "test.db",
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .unwrap(),
            ),
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
        match record_type {
            // RecordType::A => todo!(),
            // RecordType::AAAA => todo!(),
            _ => match self.resolver.lookup(name, record_type).await {
                Ok(lookup) => Ok(ForwardLookup(lookup)).inspect(|x| println!("{:#?}", x.0)),
                Err(error) => Err(LookupError::from(error)),
            },
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
