#[tokio::main]
async fn main() -> anyhow::Result<()> {
  env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

  log::info!("hello, plug2proxy!");

  Ok(())
}
