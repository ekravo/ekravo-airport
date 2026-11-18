use std::time::Instant;

use dashmap::DashMap;

use crate::util::now_secs;

/// Token bucket for one WebSocket connection.
///
/// Refills continuously at `rate` messages per second up to `burst`. A peer
/// that exceeds the budget gets a `rate_limited` error frame; the connection is
/// not closed, so a legitimate burst does not cost the session.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate: u32, burst: u32) -> Self {
        let rate = rate.max(1) as f64;
        let burst = burst.max(1) as f64;
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Fixed one-minute windows keyed by client IP and endpoint class. This is a
/// blunt instrument for unauthenticated endpoints (login, registration,
/// pairing); authenticated traffic is governed by the per-connection bucket.
pub struct HttpRateLimiter {
    windows: DashMap<String, (i64, u32)>,
}

impl HttpRateLimiter {
    pub fn new() -> Self {
        Self {
            windows: DashMap::new(),
        }
    }

    pub fn check(&self, key: &str, limit: u32) -> bool {
        let minute = now_secs() / 60;
        let allowed = {
            let mut entry = self.windows.entry(key.to_string()).or_insert((minute, 0));
            if entry.0 != minute {
                *entry = (minute, 0);
            }
            entry.1 = entry.1.saturating_add(1);
            entry.1 <= limit
        };
        if self.windows.len() > 20_000 {
            self.windows.retain(|_, (window, _)| *window == minute);
        }
        allowed
    }
}

impl Default for HttpRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let mut bucket = TokenBucket::new(1, 2);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(bucket.try_acquire());
    }

    #[test]
    fn http_limiter_counts_within_the_window() {
        let limiter = HttpRateLimiter::new();
        assert!(limiter.check("ip:test", 2));
        assert!(limiter.check("ip:test", 2));
        assert!(!limiter.check("ip:test", 2));
        assert!(limiter.check("ip:other", 2));
    }
}
