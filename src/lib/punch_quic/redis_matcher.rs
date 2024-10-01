use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use redis::AsyncCommands;

use super::matcher::{ClientSideMatcher, ServerSideMatcher};

pub struct RedisClientSideMatcher {
    redis: redis::Client,
}

impl RedisClientSideMatcher {
    pub fn new(redis: redis::Client) -> Self {
        Self { redis }
    }
}

#[async_trait::async_trait]
impl ClientSideMatcher for RedisClientSideMatcher {
    async fn match_server(
        &self,
        client_id: uuid::Uuid,
        client_address: SocketAddr,
    ) -> anyhow::Result<SocketAddr> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        let config = redis::aio::ConnectionManagerConfig::new().set_push_sender(sender);

        let mut conn = self
            .redis
            .get_connection_manager_with_config(config)
            .await?;

        conn.subscribe(match_channel_name(client_id, client_address))
            .await?;

        let match_task = async {
            while let Some(push) = receiver.recv().await {
                let Some(message) = redis::Msg::from_push_info(push) else {
                    continue;
                };

                let address: String = message.get_payload()?;
                let address: SocketAddr = address.parse()?;

                return Ok(address);
            }

            anyhow::bail!("failed to match a server.");
        };

        let announce_task = {
            async move {
                loop {
                    conn.publish(
                        CLIENT_ANNOUNCEMENT_CHANNEL_NAME,
                        serde_json::to_string(&ClientAnnouncement {
                            id: client_id.clone(),
                            address: client_address,
                        })?,
                    )
                    .await?;

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                #[allow(unreachable_code)]
                anyhow::Ok(())
            }
        };

        let address = tokio::select! {
            address = match_task => address?,
            _ = announce_task => anyhow::bail!("failed to match a server."),
        };

        println!("matched: {:?}", address);

        Ok(address)
    }
}

pub struct RedisServerSideMatcher {
    client_id_set: Arc<tokio::sync::Mutex<HashSet<uuid::Uuid>>>,
    redis_conn: redis::aio::ConnectionManager,
    client_announcement_receiver:
        Arc<tokio::sync::Mutex<tokio::sync::broadcast::Receiver<ClientAnnouncement>>>,
}

impl RedisServerSideMatcher {
    pub async fn new(redis: redis::Client) -> anyhow::Result<Self> {
        let (redis_conn, client_announcement_receiver) = {
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let config = redis::aio::ConnectionManagerConfig::new().set_push_sender(sender);

            let mut conn = redis.get_connection_manager_with_config(config).await?;

            conn.subscribe(CLIENT_ANNOUNCEMENT_CHANNEL_NAME).await?;

            let (client_announcement_sender, client_announcement_receiver) =
                tokio::sync::broadcast::channel(1);

            tokio::spawn(async move {
                loop {
                    let push = receiver
                        .recv()
                        .await
                        .expect("unexpected end of server side matcher subscription.");

                    let Some(message) = redis::Msg::from_push_info(push) else {
                        continue;
                    };

                    if message.get_channel_name() != CLIENT_ANNOUNCEMENT_CHANNEL_NAME {
                        continue;
                    }

                    if let Result::<ClientAnnouncement, _>::Ok(client_announcement) =
                        serde_json::from_slice(message.get_payload_bytes())
                    {
                        let _ = client_announcement_sender.send(client_announcement);
                    }
                }
            });

            (conn, client_announcement_receiver)
        };

        Ok(Self {
            client_id_set: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            redis_conn,
            client_announcement_receiver: Arc::new(tokio::sync::Mutex::new(
                client_announcement_receiver,
            )),
        })
    }
}

#[async_trait::async_trait]
impl ServerSideMatcher for RedisServerSideMatcher {
    async fn match_client(
        &self,
        _server_id: uuid::Uuid,
        server_address: SocketAddr,
    ) -> anyhow::Result<(uuid::Uuid, SocketAddr)> {
        loop {
            let client_announcement = self
                .client_announcement_receiver
                .lock()
                .await
                .recv()
                .await?;

            if self
                .client_id_set
                .lock()
                .await
                .contains(&client_announcement.id)
            {
                continue;
            }

            let client_key = match_key(client_announcement.id, client_announcement.address);

            println!("key: {:?}", client_key);

            let mut redis_conn = self.redis_conn.clone();

            let match_key_set = redis_conn
                .send_packed_command(
                    redis::cmd("SET")
                        .arg(client_key)
                        .arg(server_address.to_string())
                        .arg("NX")
                        .arg("EX")
                        .arg(MATCH_TIMEOUT_SECONDS),
                )
                .await?;

            if !matches!(match_key_set, redis::Value::Okay) {
                continue;
            }

            redis_conn
                .publish(
                    match_channel_name(client_announcement.id, client_announcement.address),
                    server_address.to_string(),
                )
                .await?;

            println!("matched: {:?}", client_announcement.address);

            return Ok((client_announcement.id, client_announcement.address));
        }

        anyhow::bail!("failed to match a client.");
    }

    async fn register_client(&self, client_id: uuid::Uuid) -> anyhow::Result<()> {
        self.client_id_set.lock().await.insert(client_id);

        Ok(())
    }

    async fn unregister_client(&self, client_id: &uuid::Uuid) -> anyhow::Result<()> {
        self.client_id_set.lock().await.remove(&client_id);

        Ok(())
    }
}

const CLIENT_ANNOUNCEMENT_CHANNEL_NAME: &str = "client_announcement";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ClientAnnouncement {
    id: uuid::Uuid,
    address: SocketAddr,
}

const MATCH_TIMEOUT_SECONDS: u64 = 30;

fn match_key(id: uuid::Uuid, address: SocketAddr) -> String {
    format!("{}/{}", id, address)
}

fn match_channel_name(id: uuid::Uuid, address: SocketAddr) -> String {
    format!("match/{}", match_key(id, address))
}
