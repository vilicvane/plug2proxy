use std::{collections::HashSet, sync::Arc, time::Duration};

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
}

impl RedisInMatchServer {
    pub fn new(redis: redis::Client) -> Self {
        Self { redis }
    }
}

#[allow(dependency_on_unit_never_type_fallback)]
#[async_trait::async_trait]
impl InMatchServer for RedisInMatchServer {
    async fn match_out<TInData, TOutData>(
        &self,
        in_id: MatchInId,
        in_data: TInData,
    ) -> anyhow::Result<MatchOut<TOutData>>
    where
        TInData: serde::Serialize + Send,
        TOutData: serde::de::DeserializeOwned + Send,
        (TInData, TOutData): MatchPair<TInData, TOutData>,
    {
        let match_name = <(TInData, TOutData)>::get_match_name();
        let channel_name = <(TInData, TOutData)>::get_redis_in_announcement_channel_name();

        let (push_sender, mut push_receiver) = tokio::sync::mpsc::unbounded_channel();

        let mut connection = self
            .redis
            .get_multiplexed_async_connection_with_config(
                &redis::AsyncConnectionConfig::default().set_push_sender(push_sender),
            )
            .await?;

        let match_key = uuid::Uuid::new_v4().to_string();

        connection.subscribe(&match_key).await?;

        let match_task = async {
            while let Some(push) = push_receiver.recv().await {
                let Some(message) = redis::Msg::from_push_info(push) else {
                    continue;
                };

                let match_out: MatchOut<TOutData> =
                    serde_json::from_slice(message.get_payload_bytes())?;

                return Ok(match_out);
            }

            anyhow::bail!("failed to match a server.");
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
                    .publish(&channel_name, serde_json::to_string(&announcement)?)
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

        Ok(match_out)
    }
}

pub struct RedisOutMatchServer {
    labels: Vec<String>,
    matched_in_id_set: Arc<tokio::sync::Mutex<HashSet<MatchInId>>>,
    redis: redis::Client,
}

impl RedisOutMatchServer {
    pub async fn new(redis: redis::Client, labels: Vec<String>) -> anyhow::Result<Self> {
        Ok(Self {
            labels,
            matched_in_id_set: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            redis,
        })
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
        let (push_sender, mut push_receiver) = tokio::sync::mpsc::unbounded_channel();

        let mut connection = self
            .redis
            .get_multiplexed_async_connection_with_config(
                &redis::AsyncConnectionConfig::default().set_push_sender(push_sender),
            )
            .await?;

        let channel_name = <(TInData, TOutData)>::get_redis_in_announcement_channel_name();

        connection.subscribe(&channel_name).await?;

        loop {
            let push = push_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("IN announcement subscription ended."))?;

            let Some(message) = redis::Msg::from_push_info(push) else {
                continue;
            };

            let Ok(InAnnouncement { id, match_key }) =
                serde_json::from_slice(message.get_payload_bytes())
            else {
                continue;
            };

            if self.matched_in_id_set.lock().await.contains(&id) {
                continue;
            }

            let match_lock_key = format!("{match_key}:lock");

            log::debug!("locking IN {match_lock_key}...");

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

            break Ok(MatchIn {
                id,
                tunnel_id,
                data: in_data,
            });
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InAnnouncement {
    id: MatchInId,
    match_key: String,
}
