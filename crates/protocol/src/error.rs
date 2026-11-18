use serde::{Deserialize, Serialize};

/// A parse or validation failure. These never contain peer-controlled payload
/// text, so they are safe to log and to return to the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version {0}; this server speaks version 1")]
    UnsupportedVersion(u32),
    #[error("unknown frame type")]
    UnknownFrameType,
    #[error("frame exceeds the {limit}-byte limit")]
    FrameTooLarge { limit: usize },
    #[error("invalid frame: {0}")]
    Invalid(String),
    #[error("payload exceeds the {limit}-byte limit")]
    PayloadTooLarge { limit: usize },
    #[error("invalid encryption header: {0}")]
    InvalidEncryption(String),
    #[error("could not encode frame: {0}")]
    Encode(String),
}

/// Stable, machine-readable codes carried in `error` frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Missing, expired, or malformed credentials.
    Unauthorized,
    /// Authenticated, but not allowed to reach this endpoint.
    Forbidden,
    /// The frame did not match the protocol schema.
    InvalidFrame,
    /// The peer speaks a protocol version this server does not support.
    UnsupportedVersion,
    /// The payload or frame exceeded the configured limit.
    PayloadTooLarge,
    /// The connection exceeded its message budget.
    RateLimited,
    /// The target device is offline and could not accept more mail, or the
    /// target connection no longer exists.
    RecipientUnavailable,
    /// The device's offline mailbox is full.
    MailboxFull,
    /// The requested resource does not exist.
    NotFound,
    /// The request conflicts with current state (duplicate account, etc.).
    Conflict,
    /// A group of messages arrived faster than the connection may send.
    SlowDown,
    /// The server failed to process the frame.
    Internal,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::InvalidFrame => "invalid_frame",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::RecipientUnavailable => "recipient_unavailable",
            ErrorCode::MailboxFull => "mailbox_full",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::SlowDown => "slow_down",
            ErrorCode::Internal => "internal",
        };
        f.write_str(text)
    }
}
