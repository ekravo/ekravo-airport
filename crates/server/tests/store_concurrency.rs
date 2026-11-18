//! Regression coverage for the mailbox write path under a file-backed WAL.
//!
//! The in-memory integration suite pins SQLite to one connection, which hides
//! the read-then-write race that a deferred transaction has in WAL mode. This
//! test uses several connections and contends mailbox inserts with device acks;
//! before `BEGIN IMMEDIATE`, SQLite could return `SQLITE_BUSY_SNAPSHOT` and the
//! relay would drop the message.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use airport_server::db;
use airport_server::store::{
    self, CreateDeviceOutcome, CreateUserOutcome, DeviceRow, InsertOutcome, NewMessage,
};

struct TempDatabase {
    directory: PathBuf,
    url: String,
}

impl TempDatabase {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("airport-store-{}-{unique}", std::process::id()));
        fs::create_dir_all(&directory).expect("temp directory");
        let path = directory.join("airport.db");
        let url = format!("sqlite://{}", path.to_string_lossy().replace('\\', "/"));
        Self { directory, url }
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn closed_registration_admits_exactly_one_account_under_race() {
    let pool = db::connect("sqlite::memory:", 1).await.expect("database");
    db::migrate(&pool).await.expect("schema");

    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let mut tasks = Vec::new();
    for index in 0..8 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store::create_user_guarded(
                &pool,
                &format!("usr_race_{index}"),
                &format!("race-{index}@example.com"),
                "hash",
                None,
                false,
            )
            .await
            .expect("guarded create")
        }));
    }
    barrier.wait().await;

    let mut created = 0;
    let mut closed = 0;
    for task in tasks {
        match task.await.expect("registration task") {
            CreateUserOutcome::Created => created += 1,
            CreateUserOutcome::RegistrationClosed => closed += 1,
        }
    }
    assert_eq!(created, 1, "only the first account may be created");
    assert_eq!(closed, 7, "every later concurrent registration is refused");

    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("user count");
    assert_eq!(users, 1);
}

#[tokio::test]
async fn device_pairing_cap_holds_under_concurrent_exchanges() {
    let pool = db::connect("sqlite::memory:", 1).await.expect("database");
    db::migrate(&pool).await.expect("schema");
    store::create_user(&pool, "usr_cap", "cap@example.com", "hash", None)
        .await
        .expect("user");

    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let mut tasks = Vec::new();
    for index in 0..8 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let id = format!("dev_race_{index}");
            store::create_device_guarded(
                &pool,
                &DeviceRow {
                    id: id.clone(),
                    user_id: "usr_cap".to_string(),
                    name: format!("Device {index}"),
                    platform: None,
                    public_key: None,
                    credential_hash: format!("hash-{index}"),
                    credential_prefix: format!("prefix-{index}"),
                    created_at: 1,
                    last_seen_at: None,
                    revoked_at: None,
                },
                1,
            )
            .await
            .expect("guarded device create")
        }));
    }
    barrier.wait().await;

    let mut created = 0;
    let mut refused = 0;
    for task in tasks {
        match task.await.expect("device task") {
            CreateDeviceOutcome::Created => created += 1,
            CreateDeviceOutcome::LimitReached => refused += 1,
        }
    }
    assert_eq!(created, 1, "the active-device cap must not be exceeded");
    assert_eq!(refused, 7);

    let devices: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = ? AND revoked_at IS NULL")
            .bind("usr_cap")
            .fetch_one(&pool)
            .await
            .expect("device count");
    assert_eq!(devices, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inserts_and_acks_do_not_lose_messages_to_busy_snapshot() {
    let database = TempDatabase::new();
    let pool = db::connect(&database.url, 8).await.expect("database");
    db::migrate(&pool).await.expect("schema");

    store::create_user(&pool, "usr_concurrency", "c@example.com", "hash", None)
        .await
        .expect("user");
    store::create_device(
        &pool,
        &DeviceRow {
            id: "dev_concurrency".to_string(),
            user_id: "usr_concurrency".to_string(),
            name: "Concurrent device".to_string(),
            platform: Some("test".to_string()),
            public_key: None,
            credential_hash: "hash".to_string(),
            credential_prefix: "prefix".to_string(),
            created_at: 1,
            last_seen_at: None,
            revoked_at: None,
        },
    )
    .await
    .expect("device");

    let (done_tx, done_rx) = tokio::sync::watch::channel(false);
    let barrier = Arc::new(tokio::sync::Barrier::new(5));
    let mut tasks = Vec::new();

    let ack_pool = pool.clone();
    let ack_barrier = Arc::clone(&barrier);
    let ack_task = tokio::spawn(async move {
        ack_barrier.wait().await;
        loop {
            if *done_rx.borrow() {
                break;
            }
            let pending = store::pending_messages(&ack_pool, "dev_concurrency", 1)
                .await
                .expect("pending messages");
            if let Some(row) = pending.into_iter().next() {
                store::ack_message_by_seq(&ack_pool, "dev_concurrency", row.seq)
                    .await
                    .expect("ack");
            }
            tokio::task::yield_now().await;
        }
    });

    for worker in 0..4 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for index in 0..50 {
                let id = format!("msg-row-{worker}-{index}");
                let msg_id = format!("msg-{worker}-{index}");
                let outcome = store::insert_message(
                    &pool,
                    NewMessage {
                        id: &id,
                        target_device_id: "dev_concurrency",
                        sender_key: "user:usr_concurrency",
                        sender_user_id: "usr_concurrency",
                        sender_device_id: None,
                        sender_connection_id: None,
                        sender_public_key: None,
                        msg_id: &msg_id,
                        event: "chat.send",
                        content_type: "text",
                        payload: "payload",
                        enc: None,
                        reply_to: None,
                        expires_at: None,
                        queue_limit: 10_000,
                    },
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("insert {msg_id} failed: {error}");
                });
                assert!(
                    matches!(outcome, InsertOutcome::Inserted(_)),
                    "{msg_id} was unexpectedly treated as a duplicate"
                );
            }
        }));
    }

    for task in tasks {
        task.await.expect("insert worker");
    }
    done_tx.send(true).expect("stop ack worker");
    ack_task.await.expect("ack worker");

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&pool)
        .await
        .expect("message count");
    assert_eq!(total, 200, "every concurrent insert is stored exactly once");

    let sequences: Vec<i64> = sqlx::query_scalar("SELECT seq FROM messages ORDER BY seq")
        .fetch_all(&pool)
        .await
        .expect("sequences");
    assert_eq!(sequences.len(), 200);
    assert_eq!(
        sequences,
        (1..=200).collect::<Vec<_>>(),
        "per-device sequence allocation has no gaps or duplicates"
    );

    // Close the pool before the temp-directory guard runs. On Windows an open
    // SQLite handle prevents the test from removing its own database.
    pool.close().await;
}
