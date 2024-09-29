use super::config::Config;

pub async fn up(
    Config {
        stun_server,
        exchange_server,
    }: Config,
) -> anyhow::Result<()> {
    Ok(())
}
