use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Open the database. A file database gets WAL and a bounded pool; an in-memory
/// database is pinned to one connection so every query sees the same schema.
pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<SqlitePool> {
    let memory = url.contains(":memory:");
    if !memory {
        create_parent_directory(url)?;
    }

    let mut options = SqliteConnectOptions::from_str(url)
        .with_context(|| format!("invalid AIRPORT_DATABASE_URL `{url}`"))?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .journal_mode(if memory {
            SqliteJournalMode::Memory
        } else {
            SqliteJournalMode::Wal
        });

    options = options.synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

    let pool = SqlitePoolOptions::new()
        .max_connections(if memory { 1 } else { max_connections })
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options)
        .await
        .context("could not open the Airport database")?;

    Ok(pool)
}

fn create_parent_directory(url: &str) -> anyhow::Result<()> {
    let path = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(url);
    let path = path.split('?').next().unwrap_or(path);
    if path.is_empty() || path == ":memory:" {
        return Ok(());
    }
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
    }
    Ok(())
}

/// Current schema revision, recorded in SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 1;

/// Schema for a fresh install. Statements are idempotent so startup can run this
/// every time. The version marker refuses to let an older binary open a database
/// written by a newer one, which would otherwise corrupt data in confusing ways.
pub async fn migrate(pool: &SqlitePool) -> anyhow::Result<()> {
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .context("could not read the Airport schema version")?;
    if version > SCHEMA_VERSION {
        anyhow::bail!(
            "database schema version {version} is newer than this build supports \
             ({SCHEMA_VERSION}); upgrade Airport before starting it"
        );
    }
    sqlx::raw_sql(SCHEMA)
        .execute(pool)
        .await
        .context("could not apply the Airport schema")?;
    if version < SCHEMA_VERSION {
        sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .execute(pool)
            .await
            .context("could not record the Airport schema version")?;
    }
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name  TEXT,
    created_at    INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    revoked_at  INTEGER,
    replaced_by TEXT
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS devices (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    platform          TEXT,
    public_key        TEXT,
    credential_hash   TEXT NOT NULL,
    credential_prefix TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    last_seen_at      INTEGER,
    revoked_at        INTEGER
);
CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS devices_credential ON devices(credential_prefix);

CREATE TABLE IF NOT EXISTS pairing_codes (
    code_hash   TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pairing_codes_user ON pairing_codes(user_id);

CREATE TABLE IF NOT EXISTS tickets (
    id          TEXT PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   TEXT,
    kind        TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tickets_expiry ON tickets(expires_at);

CREATE TABLE IF NOT EXISTS grants (
    id             TEXT PRIMARY KEY,
    device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    owner_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label          TEXT,
    allowed_events TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    revoked_at     INTEGER
);
CREATE INDEX IF NOT EXISTS grants_device ON grants(device_id);
CREATE INDEX IF NOT EXISTS grants_grantee ON grants(grantee_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS grants_active
    ON grants(device_id, grantee_user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS device_counters (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    last_seq  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id                   TEXT PRIMARY KEY,
    target_device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    seq                  INTEGER NOT NULL,
    sender_key           TEXT NOT NULL,
    sender_user_id       TEXT NOT NULL,
    sender_device_id     TEXT,
    sender_connection_id TEXT,
    sender_public_key    TEXT,
    msg_id               TEXT NOT NULL,
    event                TEXT NOT NULL,
    content_type         TEXT NOT NULL,
    payload              TEXT NOT NULL,
    enc                  TEXT,
    reply_to             TEXT,
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER,
    delivered_at         INTEGER,
    acked_at             INTEGER,
    UNIQUE(target_device_id, seq),
    UNIQUE(sender_key, msg_id)
);
CREATE INDEX IF NOT EXISTS messages_pending
    ON messages(target_device_id, seq) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_retention ON messages(created_at);
"#;
