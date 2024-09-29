use std::env;

use redis::{AsyncCommands as _, PubSubCommands as _};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let redis_url = env::var("REDIS_URL")?;

    let redis = redis::Client::open(format!("{redis_url}?protocol=resp3"))?;

    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

    let config = redis::AsyncConnectionConfig::new().set_push_sender(sender);

    let mut redis_conn = redis
        .get_multiplexed_async_connection_with_config(&config)
        .await?;

    tokio::spawn(async move {
        while let Some(info) = receiver.recv().await {
            println!("received: {:?}", info);
        }
    });

    redis_conn.subscribe("test").await?;

    Ok(())
}
