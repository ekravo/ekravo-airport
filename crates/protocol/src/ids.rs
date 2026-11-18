//! Identifier validation shared by the server and SDKs.
//!
//! Ids are intentionally restricted to an unambiguous ASCII subset: they appear
//! in logs, URLs, and storage keys, and a permissive charset invites confusion
//! and injection bugs.

const MAX_ID_LEN: usize = 128;
const MAX_EVENT_LEN: usize = 128;

/// True for non-empty ids made of ASCII alphanumerics and `-_.:`.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Application message event names, e.g. `chat.send` or `fs.stat`.
///
/// The same charset as ids; the server never interprets the name but does
/// enforce its shape so grants can match on it safely.
pub fn valid_event(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVENT_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'*'))
}

/// Device/user/connection ids minted by Airport all fit [`valid_id`].
pub fn valid_device_id(value: &str) -> bool {
    value.starts_with("dev_") && valid_id(value)
}

/// Whether a grant pattern allows an event.
///
/// Patterns are exact names, a trailing `*` prefix (`fs.*`), or the universal
/// `*`. A device owner still sees every event; patterns only constrain grantees.
pub fn event_allowed(patterns: &[String], event: &str) -> bool {
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        match pattern.strip_suffix('*') {
            Some(prefix) => event.starts_with(prefix),
            None => pattern == event,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_reject_empty_and_path_characters() {
        assert!(valid_id("msg_01HZX"));
        assert!(valid_id("dev_abc-123"));
        assert!(!valid_id(""));
        assert!(!valid_id("../etc/passwd"));
        assert!(!valid_id("has space"));
        assert!(!valid_id(&"a".repeat(129)));
    }

    #[test]
    fn event_patterns_support_exact_prefix_and_wildcard() {
        let patterns = vec!["chat.send".to_string(), "fs.*".to_string()];
        assert!(event_allowed(&patterns, "chat.send"));
        assert!(!event_allowed(&patterns, "chat.other"));
        assert!(event_allowed(&patterns, "fs.stat"));
        assert!(!event_allowed(&patterns, "shell.exec"));
        assert!(event_allowed(&["*".to_string()], "anything"));
    }
}
