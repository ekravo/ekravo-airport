use sqlx::SqlitePool;

use crate::error::is_unique_violation;
use crate::util::now_secs;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub created_at: i64,
    pub disabled: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshRow {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub replaced_by: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub platform: Option<String>,
    pub public_key: Option<String>,
    pub credential_hash: String,
    pub credential_prefix: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PairingRow {
    pub user_id: String,
    pub device_name: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TicketRow {
    pub id: String,
    pub user_id: String,
    pub device_id: Option<String>,
    pub kind: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GrantRow {
    pub id: String,
    pub device_id: String,
    pub owner_user_id: String,
    pub grantee_user_id: String,
    pub label: Option<String>,
    pub allowed_events: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageRow {
    pub id: String,
    pub target_device_id: String,
    pub seq: i64,
    pub sender_key: String,
    pub sender_user_id: String,
    pub sender_device_id: Option<String>,
    pub sender_connection_id: Option<String>,
    pub sender_public_key: Option<String>,
    pub msg_id: String,
    pub event: String,
    pub content_type: String,
    pub payload: String,
    pub enc: Option<String>,
    pub reply_to: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub delivered_at: Option<i64>,
    pub acked_at: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("mailbox full")]
    MailboxFull,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

// --- Users ------------------------------------------------------------------

pub async fn create_user(
    pool: &SqlitePool,
    id: &str,
    email: &str,
    password_hash: &str,
    display_name: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(email)
    .bind(password_hash)
    .bind(display_name)
    .bind(now_secs())
    .execute(pool)
    .await
    .map(|_| ())
}

pub enum CreateUserOutcome {
    Created,
    RegistrationClosed,
}

/// Create an account while enforcing the closed-registration rule and the
/// first-account exception atomically.
///
/// The route's early check makes the common case cheap, but checking the user
/// count and inserting in separate statements lets several simultaneous
/// requests all observe an empty users table and all create an account on a
/// closed instance. `BEGIN IMMEDIATE` serializes the check with the insert.
pub async fn create_user_guarded(
    pool: &SqlitePool,
    id: &str,
    email: &str,
    password_hash: &str,
    display_name: Option<&str>,
    allow_registration: bool,
) -> Result<CreateUserOutcome, sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    if !allow_registration {
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        if users > 0 {
            tx.rollback().await?;
            return Ok(CreateUserOutcome::RegistrationClosed);
        }
    }

    if let Err(error) = sqlx::query(
        "INSERT INTO users (id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(email)
    .bind(password_hash)
    .bind(display_name)
    .bind(now_secs())
    .execute(&mut *tx)
    .await
    {
        tx.rollback().await?;
        return Err(error);
    }
    tx.commit().await?;
    Ok(CreateUserOutcome::Created)
}

pub async fn user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(pool)
        .await
}

pub async fn user_by_id(pool: &SqlitePool, id: &str) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn user_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
}

// --- Refresh tokens ---------------------------------------------------------

pub async fn insert_refresh_token(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    token_hash: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now_secs())
    .execute(pool)
    .await
    .map(|_| ())
}

pub async fn refresh_by_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<RefreshRow>, sqlx::Error> {
    sqlx::query_as::<_, RefreshRow>("SELECT * FROM refresh_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_optional(pool)
        .await
}

pub async fn revoke_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind(now_secs())
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Atomically revoke the old refresh token and insert its replacement.
///
/// `None` means another request already consumed the old row, which is treated
/// as token theft by the caller. Doing both statements in one transaction rules
/// out the window where two refreshes could both succeed.
pub async fn rotate_refresh_token(
    pool: &SqlitePool,
    old_id: &str,
    new_id: &str,
    user_id: &str,
    token_hash: &str,
    expires_at: i64,
) -> Result<Option<()>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now = now_secs();
    let updated = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = ?, replaced_by = ?
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(new_id)
    .bind(old_id)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(None);
    }
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(new_id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(()))
}

pub async fn revoke_all_refresh_tokens(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(now_secs())
        .bind(user_id)
        .execute(pool)
        .await
        .map(|_| ())
}

// --- Pairing ----------------------------------------------------------------

pub async fn create_pairing_code(
    pool: &SqlitePool,
    code_hash: &str,
    user_id: &str,
    device_name: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pairing_codes (code_hash, user_id, device_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(code_hash)
    .bind(user_id)
    .bind(device_name)
    .bind(expires_at)
    .bind(now_secs())
    .execute(pool)
    .await
    .map(|_| ())
}

/// Single-use consumption. The `consumed_at IS NULL` predicate makes two
/// simultaneous exchanges race safely: exactly one updates a row.
pub async fn consume_pairing_code(
    pool: &SqlitePool,
    code_hash: &str,
) -> Result<Option<PairingRow>, sqlx::Error> {
    sqlx::query_as::<_, PairingRow>(
        "UPDATE pairing_codes SET consumed_at = ?
         WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?
         RETURNING user_id, device_name",
    )
    .bind(now_secs())
    .bind(code_hash)
    .bind(now_secs())
    .fetch_optional(pool)
    .await
}

// --- Devices ----------------------------------------------------------------

pub async fn create_device(pool: &SqlitePool, device: &DeviceRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices
         (id, user_id, name, platform, public_key, credential_hash, credential_prefix, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&device.id)
    .bind(&device.user_id)
    .bind(&device.name)
    .bind(&device.platform)
    .bind(&device.public_key)
    .bind(&device.credential_hash)
    .bind(&device.credential_prefix)
    .bind(device.created_at)
    .execute(pool)
    .await
    .map(|_| ())
}

pub enum CreateDeviceOutcome {
    Created,
    LimitReached,
}

/// Create a device while enforcing the active-device cap in the same write
/// transaction. Concurrent pairing-code exchanges must not each observe room
/// and then exceed the cap.
pub async fn create_device_guarded(
    pool: &SqlitePool,
    device: &DeviceRow,
    max_active: i64,
) -> Result<CreateDeviceOutcome, sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = ? AND revoked_at IS NULL")
            .bind(&device.user_id)
            .fetch_one(&mut *tx)
            .await?;
    if active >= max_active {
        tx.rollback().await?;
        return Ok(CreateDeviceOutcome::LimitReached);
    }

    if let Err(error) = sqlx::query(
        "INSERT INTO devices
         (id, user_id, name, platform, public_key, credential_hash, credential_prefix, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&device.id)
    .bind(&device.user_id)
    .bind(&device.name)
    .bind(&device.platform)
    .bind(&device.public_key)
    .bind(&device.credential_hash)
    .bind(&device.credential_prefix)
    .bind(device.created_at)
    .execute(&mut *tx)
    .await
    {
        tx.rollback().await?;
        return Err(error);
    }
    tx.commit().await?;
    Ok(CreateDeviceOutcome::Created)
}

pub async fn device_by_id(pool: &SqlitePool, id: &str) -> Result<Option<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn devices_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(
        "SELECT * FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn active_device_count(pool: &SqlitePool, user_id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM devices WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

pub async fn device_by_credential_prefix(
    pool: &SqlitePool,
    prefix: &str,
) -> Result<Option<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(
        "SELECT * FROM devices WHERE credential_prefix = ? AND revoked_at IS NULL",
    )
    .bind(prefix)
    .fetch_optional(pool)
    .await
}

pub async fn revoke_device(
    pool: &SqlitePool,
    user_id: &str,
    device_id: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now = now_secs();
    let result = sqlx::query(
        "UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(device_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    // A share of a revoked device must not survive in the grantee's list or
    // keep authorizing replies.
    sqlx::query("UPDATE grants SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn rotate_device_credential(
    pool: &SqlitePool,
    user_id: &str,
    device_id: &str,
    credential_hash: &str,
    credential_prefix: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE devices SET credential_hash = ?, credential_prefix = ?
         WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(credential_hash)
    .bind(credential_prefix)
    .bind(device_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn touch_device(pool: &SqlitePool, device_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET last_seen_at = ? WHERE id = ?")
        .bind(now_secs())
        .bind(device_id)
        .execute(pool)
        .await
        .map(|_| ())
}

// --- Tickets ----------------------------------------------------------------

pub async fn create_ticket(
    pool: &SqlitePool,
    id: &str,
    ticket_hash: &str,
    user_id: &str,
    device_id: Option<&str>,
    kind: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tickets (id, ticket_hash, user_id, device_id, kind, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(ticket_hash)
    .bind(user_id)
    .bind(device_id)
    .bind(kind)
    .bind(expires_at)
    .bind(now_secs())
    .execute(pool)
    .await
    .map(|_| ())
}

pub async fn consume_ticket(
    pool: &SqlitePool,
    ticket_hash: &str,
) -> Result<Option<TicketRow>, sqlx::Error> {
    sqlx::query_as::<_, TicketRow>(
        "UPDATE tickets SET consumed_at = ?
         WHERE ticket_hash = ? AND consumed_at IS NULL AND expires_at > ?
         RETURNING id, user_id, device_id, kind, expires_at",
    )
    .bind(now_secs())
    .bind(ticket_hash)
    .bind(now_secs())
    .fetch_optional(pool)
    .await
}

// --- Grants -----------------------------------------------------------------

pub async fn create_grant(pool: &SqlitePool, grant: &GrantRow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grants
         (id, device_id, owner_user_id, grantee_user_id, label, allowed_events, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&grant.id)
    .bind(&grant.device_id)
    .bind(&grant.owner_user_id)
    .bind(&grant.grantee_user_id)
    .bind(&grant.label)
    .bind(&grant.allowed_events)
    .bind(grant.created_at)
    .execute(pool)
    .await
    .map(|_| ())
}

pub async fn grants_owned_by(
    pool: &SqlitePool,
    owner_user_id: &str,
) -> Result<Vec<GrantRow>, sqlx::Error> {
    sqlx::query_as::<_, GrantRow>(
        "SELECT * FROM grants WHERE owner_user_id = ? AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(owner_user_id)
    .fetch_all(pool)
    .await
}

pub async fn grants_for_grantee(
    pool: &SqlitePool,
    grantee_user_id: &str,
) -> Result<Vec<GrantRow>, sqlx::Error> {
    sqlx::query_as::<_, GrantRow>(
        "SELECT * FROM grants WHERE grantee_user_id = ? AND revoked_at IS NULL ORDER BY created_at",
    )
    .bind(grantee_user_id)
    .fetch_all(pool)
    .await
}

pub async fn grant_by_id(pool: &SqlitePool, id: &str) -> Result<Option<GrantRow>, sqlx::Error> {
    sqlx::query_as::<_, GrantRow>("SELECT * FROM grants WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn active_grant(
    pool: &SqlitePool,
    device_id: &str,
    grantee_user_id: &str,
) -> Result<Option<GrantRow>, sqlx::Error> {
    sqlx::query_as::<_, GrantRow>(
        "SELECT * FROM grants
         WHERE device_id = ? AND grantee_user_id = ? AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(grantee_user_id)
    .fetch_optional(pool)
    .await
}

pub async fn revoke_grant(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now_secs())
            .bind(id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

// --- Messages ---------------------------------------------------------------

pub struct NewMessage<'a> {
    pub id: &'a str,
    pub target_device_id: &'a str,
    pub sender_key: &'a str,
    pub sender_user_id: &'a str,
    pub sender_device_id: Option<&'a str>,
    pub sender_connection_id: Option<&'a str>,
    pub sender_public_key: Option<&'a str>,
    pub msg_id: &'a str,
    pub event: &'a str,
    pub content_type: &'a str,
    pub payload: &'a str,
    pub enc: Option<&'a str>,
    pub reply_to: Option<&'a str>,
    pub expires_at: Option<i64>,
    pub queue_limit: i64,
}

pub enum InsertOutcome {
    Inserted(MessageRow),
    Duplicate(MessageRow),
}

/// Store a message exactly once per `(sender, msgId)`.
///
/// The transaction both reserves a per-device sequence number and enforces the
/// mailbox cap. SQLite serializes writers, so `device_counters` cannot hand the
/// same sequence to two messages.
///
/// `BEGIN IMMEDIATE` is deliberate. A deferred transaction reads the duplicate
/// and mailbox-depth checks before writing; in WAL mode, if another connection
/// commits in that window, the later write fails with `SQLITE_BUSY_SNAPSHOT`
/// and the message is lost. Taking the write lock first makes the read part of
/// the same serialized write operation, so concurrent inserts and acks wait
/// instead of failing.
pub async fn insert_message(
    pool: &SqlitePool,
    new: NewMessage<'_>,
) -> Result<InsertOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    if let Some(existing) = sqlx::query_as::<_, MessageRow>(
        "SELECT * FROM messages WHERE sender_key = ? AND msg_id = ?",
    )
    .bind(new.sender_key)
    .bind(new.msg_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.rollback().await?;
        return Ok(InsertOutcome::Duplicate(existing));
    }

    let now = now_secs();
    let depth: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages
         WHERE target_device_id = ? AND acked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(new.target_device_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if depth >= new.queue_limit {
        tx.rollback().await?;
        return Err(StoreError::MailboxFull);
    }

    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO device_counters (device_id, last_seq) VALUES (?, 1)
         ON CONFLICT(device_id) DO UPDATE SET last_seq = device_counters.last_seq + 1
         RETURNING last_seq",
    )
    .bind(new.target_device_id)
    .fetch_one(&mut *tx)
    .await?;

    if let Err(error) = sqlx::query(
        "INSERT INTO messages
         (id, target_device_id, seq, sender_key, sender_user_id, sender_device_id,
          sender_connection_id, sender_public_key, msg_id, event, content_type, payload,
          enc, reply_to, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(new.id)
    .bind(new.target_device_id)
    .bind(seq)
    .bind(new.sender_key)
    .bind(new.sender_user_id)
    .bind(new.sender_device_id)
    .bind(new.sender_connection_id)
    .bind(new.sender_public_key)
    .bind(new.msg_id)
    .bind(new.event)
    .bind(new.content_type)
    .bind(new.payload)
    .bind(new.enc)
    .bind(new.reply_to)
    .bind(now)
    .bind(new.expires_at)
    .execute(&mut *tx)
    .await
    {
        // Two concurrent submissions from the same sender can both pass the
        // SELECT above. The unique index decides which one wins; the loser
        // returns the winner's row instead of a 500.
        let duplicate = is_unique_violation(&error);
        tx.rollback().await?;
        if duplicate {
            if let Some(existing) = sqlx::query_as::<_, MessageRow>(
                "SELECT * FROM messages WHERE sender_key = ? AND msg_id = ?",
            )
            .bind(new.sender_key)
            .bind(new.msg_id)
            .fetch_optional(pool)
            .await?
            {
                return Ok(InsertOutcome::Duplicate(existing));
            }
        }
        return Err(error.into());
    }

    tx.commit().await?;

    Ok(InsertOutcome::Inserted(MessageRow {
        id: new.id.to_string(),
        target_device_id: new.target_device_id.to_string(),
        seq,
        sender_key: new.sender_key.to_string(),
        sender_user_id: new.sender_user_id.to_string(),
        sender_device_id: new.sender_device_id.map(str::to_string),
        sender_connection_id: new.sender_connection_id.map(str::to_string),
        sender_public_key: new.sender_public_key.map(str::to_string),
        msg_id: new.msg_id.to_string(),
        event: new.event.to_string(),
        content_type: new.content_type.to_string(),
        payload: new.payload.to_string(),
        enc: new.enc.map(str::to_string),
        reply_to: new.reply_to.map(str::to_string),
        created_at: now,
        expires_at: new.expires_at,
        delivered_at: None,
        acked_at: None,
    }))
}

pub async fn mark_delivered(pool: &SqlitePool, message_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE messages SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL")
        .bind(now_secs())
        .bind(message_id)
        .execute(pool)
        .await
        .map(|_| ())
}

pub async fn pending_messages(
    pool: &SqlitePool,
    device_id: &str,
    limit: i64,
) -> Result<Vec<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        "SELECT * FROM messages
         WHERE target_device_id = ? AND acked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY seq LIMIT ?",
    )
    .bind(device_id)
    .bind(now_secs())
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Acknowledge the exact mailbox entry the device was given. `seq` is unique
/// per target device, so two senders may reuse the same `msgId` without one
/// acknowledgement clearing the other's message.
pub async fn ack_message_by_seq(
    pool: &SqlitePool,
    device_id: &str,
    seq: i64,
) -> Result<Option<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        "UPDATE messages SET acked_at = ?
         WHERE target_device_id = ? AND seq = ? AND acked_at IS NULL
         RETURNING *",
    )
    .bind(now_secs())
    .bind(device_id)
    .bind(seq)
    .fetch_optional(pool)
    .await
}

/// Fallback for peers that do not send `seq`: acknowledge only the newest
/// unacknowledged row with this id, never every row that happens to share it.
pub async fn ack_message_by_msg_id(
    pool: &SqlitePool,
    device_id: &str,
    msg_id: &str,
) -> Result<Option<MessageRow>, sqlx::Error> {
    sqlx::query_as::<_, MessageRow>(
        "UPDATE messages SET acked_at = ?
         WHERE id = (
             SELECT id FROM messages
             WHERE target_device_id = ? AND msg_id = ? AND acked_at IS NULL
             ORDER BY seq DESC LIMIT 1
         )
         RETURNING *",
    )
    .bind(now_secs())
    .bind(device_id)
    .bind(msg_id)
    .fetch_optional(pool)
    .await
}

/// Drop old rows that no longer serve delivery, idempotency, or revocation.
pub async fn cleanup(pool: &SqlitePool, retention_secs: i64) -> Result<(), sqlx::Error> {
    let cutoff = now_secs() - retention_secs;
    sqlx::query("DELETE FROM messages WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM pairing_codes WHERE expires_at < ?")
        .bind(now_secs() - 3600)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM tickets WHERE expires_at < ?")
        .bind(now_secs() - 3600)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(())
}
