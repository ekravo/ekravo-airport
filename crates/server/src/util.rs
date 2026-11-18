use std::time::{SystemTime, UNIX_EPOCH};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Unix seconds. Airport stores all timestamps as integers so SQL comparisons
/// and expiry checks are unambiguous.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// RFC 3339 UTC for API responses. Invalid values cannot occur for the range
/// Airport produces, but the fallback keeps the API total.
pub fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        // `time` writes UTC as +00:00; the API has always used Z.
        .map(|formatted| formatted.replace("+00:00", "Z"))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

/// Prefixed, unguessable identifier: `usr_…`, `dev_…`, `conn_…`.
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

/// Prefix used by the SDKs and tests for a new message id.
pub fn new_msg_id() -> String {
    format!("msg_{}", Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::iso;

    #[test]
    fn iso_is_second_precision_utc() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
