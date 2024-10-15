use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use futures::{future::ready, pin_mut, Stream, StreamExt as _};
use redis::AsyncCommands;

use crate::{route::config::OutRuleConfig, tunnel::TunnelId};

use super::{
    match_server::{InMatchServer, MatchIn, MatchOut, OutMatchServerTrait},
    MatchInId, MatchOutId, MatchPair,
};

const MATCH_TIMEOUT_SECONDS: i64 = 5;
const MATCH_IN_DATA_EXPIRATION_IN_SECONDS: i64 = 30;

pub struct RedisInMatchServer {
    redis: redis::Client,
    match_name_to_active_out_id_set_map:
        tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<HashSet<MatchOutId>>>>>,
}

impl RedisInMatchServer {
    pub fn new(redis: redis::Client) -> Self {
        Self {
            redis,
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

        let (mut connection, message_stream) =
            get_connection_and_subscribe::<MatchOutId>(&self.redis, out_pattern).await?;

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
        in_id: MatchInId,
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

        let (mut connection, subscription_stream) =
            get_connection_and_subscribe::<MatchOut<TOutData>>(&self.redis, &match_key).await?;

        if !connection.exists(out_key).await? {
            self.match_name_to_active_out_id_set_map
                .lock()
                .await
                .get(match_name)
                .unwrap()
                .lock()
                .await
                .remove(&out_id);

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

        let announce_task = async move {
            let announcement = InAnnouncement {
                id: in_id,
                match_key: match_key.clone(),
            };

            connection
                .send_packed_command(
                    redis::cmd("SET")
                        .arg(&match_key)
                        .arg(serde_json::to_string(&in_data)?)
                        .arg("NX")
                        .arg("EX")
                        .arg(MATCH_IN_DATA_EXPIRATION_IN_SECONDS),
                )
                .await?;

            loop {
                log::debug!("announcing {match_name} IN {in_id} with match key {match_key}...");

                connection
                    .publish(
                        &in_announcement_channel_name,
                        serde_json::to_string(&announcement)?,
                    )
                    .await?;

                tokio::time::sleep(Duration::from_secs(1)).await;

                connection
                    .expire(&match_key, MATCH_IN_DATA_EXPIRATION_IN_SECONDS)
                    .await?;
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
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
    labels: Vec<String>,
    redis: redis::Client,
}

impl RedisOutMatchServer {
    pub async fn new(redis: redis::Client, labels: Vec<String>) -> anyhow::Result<Self> {
        Ok(Self { labels, redis })
    }
}

#[allow(dependency_on_unit_never_type_fallback)]
#[async_trait::async_trait]
impl OutMatchServerTrait for RedisOutMatchServer {
    async fn match_in<TInData, TOutData>(
        &self,
        out_id: MatchOutId,
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
        let channel_name = <(TInData, TOutData)>::get_redis_in_announcement_channel_name(&out_id);
        let out_key = <(TInData, TOutData)>::get_redis_out_key(&out_id);

        let (connection, in_announcement_stream) =
            get_connection_and_subscribe::<InAnnouncement>(&self.redis, &channel_name).await?;

        let connection = Arc::new(tokio::sync::Mutex::new(connection));

        let announce_task = {
            let connection = connection.clone();

            async move {
                connection
                    .lock()
                    .await
                    .send_packed_command(
                        redis::cmd("SET")
                            .arg(&out_key)
                            .arg(serde_json::to_string(&out_id)?)
                            .arg("EX")
                            .arg(MATCH_TIMEOUT_SECONDS),
                    )
                    .await?;

                let mut first = true;

                loop {
                    {
                        let mut connection = connection.lock().await;

                        if first {
                            first = false;
                        } else {
                            connection.expire(&out_key, MATCH_TIMEOUT_SECONDS).await?;
                        }

                        connection
                            .publish(&out_key, serde_json::to_string(&out_id)?)
                            .await?;
                    }

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };

        let match_task = async {
            pin_mut!(in_announcement_stream);

            while let Some(in_announcement) = in_announcement_stream.next().await {
                let InAnnouncement { id, match_key } = in_announcement?;

                let match_lock_key = format!("{match_key}:lock");

                log::debug!("locking IN {match_lock_key}...");

                let mut connection = connection.lock().await;

                let match_key_locking = connection
                    .send_packed_command(
                        redis::cmd("SET")
                            .arg(&match_lock_key)
                            .arg(serde_json::to_string(&out_data)?)
                            .arg("NX")
                            .arg("EX")
                            .arg(MATCH_TIMEOUT_SECONDS),
                    )
                    .await?;

                if !matches!(match_key_locking, redis::Value::Okay) {
                    log::debug!("missed IN {match_lock_key}...");

                    continue;
                }

                let in_data: String = connection.get(&match_key).await?;

                let in_data: TInData = serde_json::from_str(&in_data)?;

                let tunnel_id = TunnelId::new();

                log::debug!("matching IN {match_lock_key}...");

                connection
                    .publish(
                        match_key,
                        serde_json::to_string(&MatchOut {
                            id: out_id,
                            tunnel_id,
                            tunnel_labels: self.labels.clone(),
                            tunnel_priority: out_priority,
                            routing_rules: out_routing_rules.to_vec(),
                            routing_priority: out_routing_priority,
                            data: out_data,
                        })?,
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
) -> anyhow::Result<(
    redis::aio::MultiplexedConnection,
    impl Stream<Item = anyhow::Result<T>>,
)> {
    let (push_sender, mut push_receiver) = tokio::sync::mpsc::unbounded_channel();

    let mut connection = redis
        .get_multiplexed_async_connection_with_config(
            &redis::AsyncConnectionConfig::default().set_push_sender(push_sender),
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

            let value: T = serde_json::from_slice(message.get_payload_bytes())?;

            yield Ok(value);
        }
    };

    Ok((connection, subscription_stream))
}
