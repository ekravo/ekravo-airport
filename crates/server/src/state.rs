use std::sync::Arc;
use std::time::Instant;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::ratelimit::HttpRateLimiter;
use crate::registry::Registry;

/// State shared by every request and socket.
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: SqlitePool,
    pub registry: Arc<Registry>,
    pub http_limits: HttpRateLimiter,
    pub started_at: Instant,
}

impl AppState {
    pub fn new(config: Config, pool: SqlitePool) -> Self {
        Self {
            config: Arc::new(config),
            pool,
            registry: Arc::new(Registry::new()),
            http_limits: HttpRateLimiter::new(),
            started_at: Instant::now(),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
