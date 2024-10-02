async fn test_sqlite() -> anyhow::Result<()> {
    let sqlite = rusqlite::Connection::open_with_flags(
        "test.db",
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;

    sqlite.execute(
        r#"
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type STRING NOT NULL,
            name STRING UNIQUE NOT NULL,
            real_ip BLOB NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_type ON records (type);
        CREATE INDEX IF NOT EXISTS idx_name ON records (name);
        CREATE INDEX IF NOT EXISTS idx_expires_at ON records (expires_at);
        "#,
        [],
    )?;

    Ok(())
}
