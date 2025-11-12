use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use aes_gcm::{aead::Aead, AeadCore, KeyInit as _};
use futures::{future::ready, pin_mut, Stream, StreamExt as _};
use itertools::Itertools;
use redis::AsyncCommands;
use sha2::Digest as _;

use crate::{
    route::{config::OutRuleConfig, rule::Label},
    tunnel::TunnelId,
};

use super::{
    match_server::{InMatchServer, MatchIn, MatchOut, OutMatchServerTrait},
    MatchInId, MatchOutId, MatchPair,
};

const MATCH_TIMEOUT_SECONDS: i64 = 5;
const MATCH_IN_DATA_EXPIRATION_IN_SECONDS: i64 = 30;

pub struct RedisInMatchServer {
    id: MatchInId,
    redis: redis::Client,
    cipher: Option<Arc<aes_gcm::Aes256Gcm>>,
    match_name_to_active_out_id_set_map:
        tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<HashSet<MatchOutId>>>>>,
}

impl RedisInMatchServer {
    pub fn new(redis: redis::Client, key: Option<String>) -> Self {
        Self {
            id: MatchInId::new(),
            redis,
            cipher: create_cipher(key),
            match_name_to_active_out_id_set_map: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[allow(dependency_on_unit_never_type_fallback)]
#[async_trait::async_trait]
impl InMatchServer for RedisInMatchServer {
    async fn accept_out<TInData, TOutData>(&self) -> anyhow::Result<MatchOutId>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        let match_name = <(TInData, TOutData)>::get_match_name();
        let out_pattern = <(TInData, TOutData)>::get_redis_out_pattern();

        log::info!("accepting {match_name} OUT...");

        let (mut connection, message_stream) = get_connection_and_subscribe::<MatchOutId>(
            &self.redis,
            out_pattern,
            self.cipher.clone(),
        )
        .await?;

        let active_out_id_set = self
            .match_name_to_active_out_id_set_map
            .lock()
            .await
            .entry(match_name.to_owned())
            .or_default()
            .clone();

        {
            let mut active_out_id_set = active_out_id_set.lock().await;

            let out_id = connection
                .scan_match(out_pattern)
                .await?
                .filter_map(|out_key: String| {
                    ready({
                        <(TInData, TOutData)>::get_out_id_from_redis_out_key(&out_key)
                            .inspect_err(|_| {
                                log::warn!("failed to parse OUT id from key {out_key}.");
                            })
                            .ok()
                            .filter(|&out_id| !active_out_id_set.contains(&out_id))
                    })
                })
                .next()
                .await;

            if let Some(out_id) = out_id {
                log::debug!("accepting OUT {match_name} {out_id} by key value...");

                active_out_id_set.insert(out_id);

                return Ok(out_id);
            }
        }

        pin_mut!(message_stream);

        while let Some(out_id) = message_stream.next().await {
            let out_id = out_id?;

            let mut active_out_id_set = active_out_id_set.lock().await;

            if active_out_id_set.contains(&out_id) {
                continue;
            }

            log::debug!("accepting OUT {match_name} {out_id} by subscription...");

            active_out_id_set.insert(out_id);

            return Ok(out_id);
        }

        anyhow::bail!("subscription to OUT ended.");
    }

    async fn match_out<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
        in_data: TInData,
    ) -> anyhow::Result<Option<MatchOut<TOutData>>>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        let out_key = <(TInData, TOutData)>::get_redis_out_key(&out_id);

        let match_name = <(TInData, TOutData)>::get_match_name();
        let in_announcement_channel_name =
            <(TInData, TOutData)>::get_redis_in_announcement_channel_name(&out_id);

        let match_key = uuid::Uuid::new_v4().to_string();

        let (mut connection, subscription_stream) = get_connection_and_subscribe::<
            MatchOut<TOutData>,
        >(
            &self.redis, &match_key, self.cipher.clone()
        )
        .await?;

        if !connection.exists(out_key).await? {
            self.match_name_to_active_out_id_set_map
                .lock()
                .await
                .get(match_name)
                .unwrap()
                .lock()
                .await
                .remove(&out_id);

            log::info!("{match_name} OUT {out_id} no longer active.");

            return Ok(None);
        }

        let match_task = async {
            pin_mut!(subscription_stream);

            subscription_stream.next().await.unwrap_or_else(|| {
                Err(anyhow::anyhow!(
                    "subscription ended before match to OUT {out_id}."
                ))
            })
        };

        let announce_task = {
            let cipher = self.cipher.clone();

            async move {
                let announcement = InAnnouncement {
                    id: self.id,
                    match_key: match_key.clone(),
                };

                connection
                    .send_packed_command(
                        redis::cmd("SET")
                            .arg(&match_key)
                            .arg(encrypt(
                                &cipher,
                                serde_json::to_string(&in_data)?.as_bytes(),
                            ))
                            .arg("NX")
                            .arg("EX")
                            .arg(MATCH_IN_DATA_EXPIRATION_IN_SECONDS),
                    )
                    .await?;

                let encrypted_announcement =
                    encrypt(&cipher, serde_json::to_string(&announcement)?.as_bytes());

                loop {
                    log::debug!(
                        "announcing {match_name} IN {} with match key {match_key}...",
                        self.id
                    );

                    connection
                        .publish(&in_announcement_channel_name, &encrypted_announcement)
                        .await?;

                    tokio::time::sleep(Duration::from_secs(1)).await;

                    connection
                        .expire(&match_key, MATCH_IN_DATA_EXPIRATION_IN_SECONDS)
                        .await?;
                }

                #[allow(unreachable_code)]
                anyhow::Ok(())
            }
        };

        let match_out = tokio::select! {
            match_out = match_task => match_out?,
            _ = announce_task => anyhow::bail!("failed to match IN."),
        };

        log::info!(
            "matched {match_name} OUT {} as tunnel {}.",
            match_out.id,
            match_out.tunnel_id
        );

        Ok(Some(match_out))
    }
}

pub struct RedisOutMatchServer {
    id: MatchOutId,
    labels: Vec<Label>,
    cipher: Option<Arc<aes_gcm::Aes256Gcm>>,
    redis: redis::Client,
}

impl RedisOutMatchServer {
    pub async fn new(
        redis: redis::Client,
        key: Option<String>,
        labels: Vec<Label>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            id: MatchOutId::new(),
            labels,
            cipher: create_cipher(key),
            redis,
        })
    }
}

#[allow(dependency_on_unit_never_type_fallback)]
#[async_trait::async_trait]
impl OutMatchServerTrait for RedisOutMatchServer {
    async fn match_in<TInData, TOutData>(
        &self,
        out_data: TOutData,
        out_priority: Option<i64>,
        out_routing_rules: &[OutRuleConfig],
        out_routing_priority: i64,
    ) -> anyhow::Result<MatchIn<TInData>>
    where
        TInData: serde::de::DeserializeOwned + Send,
        TOutData: serde::Serialize + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        let channel_name = <(TInData, TOutData)>::get_redis_in_announcement_channel_name(&self.id);
        let out_key = <(TInData, TOutData)>::get_redis_out_key(&self.id);

        let (connection, in_announcement_stream) = get_connection_and_subscribe::<InAnnouncement>(
            &self.redis,
            &channel_name,
            self.cipher.clone(),
        )
        .await?;

        let connection = Arc::new(tokio::sync::Mutex::new(connection));

        let announce_task = {
            let connection = connection.clone();
            let cipher = self.cipher.clone();

            async move {
                {
                    let mut connection = connection.lock().await;

                    // Actually it's not necessary as the OUT id is already in key (and it's
                    // neither used), but we are using the same subscribe utility that does
                    // decryption anyway.
                    let encrypted_out_id =
                        encrypt(&cipher, serde_json::to_string(&self.id)?.as_bytes());

                    connection
                        .send_packed_command(
                            redis::cmd("SET")
                                .arg(&out_key)
                                .arg(&encrypted_out_id)
                                .arg("EX")
                                .arg(MATCH_TIMEOUT_SECONDS),
                        )
                        .await?;

                    connection.publish(&out_key, &encrypted_out_id).await?;
                }

                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    let ret: i32 = connection
                        .lock()
                        .await
                        .expire(&out_key, MATCH_TIMEOUT_SECONDS)
                        .await?;

                    if ret == 0 {
                        anyhow::bail!("OUT {} expired.", self.id);
                    }
                }
            }
        };

        let match_task = async {
            pin_mut!(in_announcement_stream);

            let cipher = self.cipher.clone();

            while let Some(in_announcement) = in_announcement_stream.next().await {
                let InAnnouncement { id, match_key } = in_announcement?;

                let match_lock_key = format!("{match_key}:lock");

                log::debug!("locking IN {match_lock_key}...");

                let mut connection = connection.lock().await;

                let match_key_locking = connection
                    .send_packed_command(
                        redis::cmd("SET")
                            .arg(&match_lock_key)
                            .arg("")
                            .arg("NX")
                            .arg("EX")
                            .arg(MATCH_TIMEOUT_SECONDS),
                    )
                    .await?;

                if !matches!(match_key_locking, redis::Value::Okay) {
                    log::debug!("missed IN {match_lock_key}...");

                    continue;
                }

                let in_data: Vec<u8> = connection.get(&match_key).await?;

                let in_data: TInData = serde_json::from_slice(&decrypt(&cipher, &in_data)?)?;

                let tunnel_id = TunnelId::new();

                log::debug!("matching IN {match_lock_key}...");

                connection
                    .publish(
                        match_key,
                        encrypt(
                            &cipher,
                            serde_json::to_string(&MatchOut {
                                id: self.id,
                                tunnel_id,
                                tunnel_labels: self.labels.clone(),
                                tunnel_priority: out_priority,
                                routing_rules: out_routing_rules.to_vec(),
                                routing_priority: out_routing_priority,
                                data: out_data,
                            })?
                            .as_bytes(),
                        ),
                    )
                    .await?;

                log::info!(
                    "matched IN {} {id} as tunnel {tunnel_id}.",
                    <(TInData, TOutData)>::get_match_name(),
                );

                return Ok(MatchIn {
                    id,
                    tunnel_id,
                    data: in_data,
                });
            }

            anyhow::bail!("IN announcement subscription ended.");
        };

        tokio::select! {
            match_in = match_task => match_in,
            result = announce_task => result,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InAnnouncement {
    id: MatchInId,
    match_key: String,
}

async fn get_connection_and_subscribe<T: serde::de::DeserializeOwned>(
    redis: &redis::Client,
    channel_name: &str,
    cipher: Option<Arc<aes_gcm::Aes256Gcm>>,
) -> anyhow::Result<(
    redis::aio::ConnectionManager,
    impl Stream<Item = anyhow::Result<T>>,
)> {
    let (push_sender, mut push_receiver) = tokio::sync::mpsc::unbounded_channel();

    let mut connection = redis
        .get_connection_manager_with_config(
            redis::aio::ConnectionManagerConfig::default().set_push_sender(push_sender),
        )
        .await?;

    if channel_name.contains("*") {
        connection.psubscribe(channel_name).await?;
    } else {
        connection.subscribe(channel_name).await?;
    }

    let subscription_stream = async_stream::stream! {
        while let Some(push) = push_receiver.recv().await {
            let Some(message) = redis::Msg::from_push_info(push) else {
                continue;
            };

            let value: T = serde_json::from_slice(
                decrypt(&cipher, message.get_payload_bytes())?.as_slice(),
            )?;

            yield Ok(value);
        }
    };

    Ok((connection, subscription_stream))
}

fn create_cipher(key: Option<String>) -> Option<Arc<aes_gcm::Aes256Gcm>> {
    key.map(|key| {
        let key = sha2::Sha256::digest(key.as_bytes());
        let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key);
        Arc::new(aes_gcm::Aes256Gcm::new(key))
    })
}

fn encrypt(cipher: &Option<Arc<aes_gcm::Aes256Gcm>>, data: &[u8]) -> Vec<u8> {
    if let Some(cipher) = cipher {
        let nonce = aes_gcm::Aes256Gcm::generate_nonce(aes_gcm::aead::OsRng);

        let data = cipher.encrypt(&nonce, data).unwrap();

        nonce.iter().copied().chain(data).collect_vec()
    } else {
        data.to_vec()
    }
}

fn decrypt(cipher: &Option<Arc<aes_gcm::Aes256Gcm>>, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if let Some(cipher) = cipher {
        let (nonce, data) = data.split_at(12);

        let nonce = aes_gcm::Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, data)
            .map_err(|error| anyhow::anyhow!("redis match decryption failed, wrong key? {error}"))
    } else {
        Ok(data.to_vec())
    }
}
