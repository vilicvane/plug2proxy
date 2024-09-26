async fn test_sqlite() -> anyhow::Result<()> {
    let sqlite = rusqlite::Connection::open_with_flags(
        "test.db",
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;

    sqlite.execute(
        r#"
      CREATE TABLE IF NOT EXISTS records (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name STRING NOT NULL,
          real_ip STRING NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_name ON records (name);
      "#,
        [],
    )?;

    Ok(())
}
