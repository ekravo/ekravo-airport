use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use airport_protocol::DEFAULT_HEARTBEAT_MS;
use axum::http::uri::Authority;

/// How logs are emitted. JSON is the default in containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// In-process TLS, for deployments that do not terminate TLS at a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

impl ConfigError {
    fn invalid(name: &'static str, message: impl Into<String>) -> Self {
        ConfigError::Invalid {
            name,
            message: message.into(),
        }
    }
}

/// Every runtime knob comes from the environment. See `.env.example` for the
/// documented list and defaults.
#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Public origin used to build absolute WebSocket URLs in API responses.
    pub public_url: Option<String>,
    pub database_url: String,
    pub jwt_secret: String,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
    pub pairing_ttl_secs: i64,
    pub ticket_ttl_secs: i64,
    pub max_payload_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_queue_depth: usize,
    pub offline_queue_limit: i64,
    pub message_ttl_secs: i64,
    pub retention_secs: i64,
    pub heartbeat_interval_secs: u64,
    pub messages_per_second: u32,
    pub message_burst: u32,
    pub auth_attempts_per_minute: u32,
    pub allow_registration: bool,
    pub trusted_origins: Vec<String>,
    pub log_format: LogFormat,
    pub max_connections_per_user: usize,
    pub max_devices_per_user: i64,
    pub replay_batch: i64,
    pub require_e2ee: bool,
    pub tls: Option<TlsConfig>,
    pub trust_proxy: bool,
}

/// Never print the signing key, even if a future caller logs the whole config.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("public_url", &self.public_url)
            .field("database_url", &self.database_url)
            .field("jwt_secret", &"<redacted>")
            .field("tls", &self.tls)
            .field("trusted_origins", &self.trusted_origins)
            .field("allow_registration", &self.allow_registration)
            .field("require_e2ee", &self.require_e2ee)
            .field("trust_proxy", &self.trust_proxy)
            .field("log_format", &self.log_format)
            .finish_non_exhaustive()
    }
}

fn var(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match var(name) {
        Some(raw) => raw
            .parse::<T>()
            .map_err(|error| ConfigError::invalid(name, error.to_string())),
        None => Ok(default),
    }
}

fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match var(name).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "TRUE" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "FALSE" | "no" | "off") => Ok(false),
        Some(other) => Err(ConfigError::invalid(
            name,
            format!("expected true or false, got `{other}`"),
        )),
    }
}

/// Validate an HTTP origin: scheme, non-empty host, and no path, query,
/// fragment, userinfo, wildcard, or whitespace. Both CORS and absolute ticket
/// URLs depend on this shape; accepting a path here would silently produce a
/// malformed WebSocket URL later.
fn validate_origin(name: &'static str, origin: &str) -> Result<(), ConfigError> {
    if !(origin.starts_with("https://") || origin.starts_with("http://")) {
        return Err(ConfigError::invalid(
            name,
            format!("origin `{origin}` must start with http:// or https://"),
        ));
    }
    if origin
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '*' | '\\'))
    {
        return Err(ConfigError::invalid(
            name,
            format!("origin `{origin}` is not a literal origin"),
        ));
    }
    let rest = origin.split_once("://").map(|(_, rest)| rest).unwrap_or("");
    let authority = Authority::from_str(rest).ok();
    let port = if rest.starts_with('[') {
        rest.rsplit_once("]:")
    } else {
        rest.rsplit_once(':')
    };
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
        || rest.starts_with(':')
        || rest.ends_with(':')
        || authority
            .as_ref()
            .is_none_or(|authority| authority.host().is_empty())
        || port.is_some_and(|(_, port)| port.parse::<u16>().is_err())
    {
        return Err(ConfigError::invalid(
            name,
            format!("origin `{origin}` must be a host with an optional port, not a URL with a path or credentials"),
        ));
    }
    Ok(())
}

fn parse_origins(name: &'static str, default: Vec<String>) -> Result<Vec<String>, ConfigError> {
    let Some(raw) = var(name) else {
        return Ok(default);
    };
    let mut origins = Vec::new();
    for entry in raw.split(',') {
        let origin = entry.trim().trim_end_matches('/');
        if origin.is_empty() {
            continue;
        }
        validate_origin(name, origin)?;
        // Schemes and hosts are case-insensitive and browsers send lowercase.
        origins.push(origin.to_ascii_lowercase());
    }
    Ok(origins)
}

impl Config {
    /// Read and validate configuration from the process environment.
    ///
    /// The environment file itself is loaded by `main` (`.env` by default, or
    /// `AIRPORT_ENV_FILE`), so this function only sees ordinary variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr: SocketAddr = var("AIRPORT_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8787".to_string())
            .parse()
            .map_err(|error| ConfigError::invalid("AIRPORT_BIND_ADDR", format!("{error}")))?;

        let jwt_secret =
            var("AIRPORT_JWT_SECRET").ok_or(ConfigError::Missing("AIRPORT_JWT_SECRET"))?;
        if jwt_secret.len() < 32 {
            return Err(ConfigError::invalid(
                "AIRPORT_JWT_SECRET",
                "must be at least 32 characters; generate one with `openssl rand -base64 48`",
            ));
        }

        let database_url =
            var("AIRPORT_DATABASE_URL").unwrap_or_else(|| "sqlite://data/airport.db".to_string());

        let max_payload_bytes: usize = parse("AIRPORT_MAX_PAYLOAD_BYTES", 256 * 1024)?;
        if !(1024..=8 * 1024 * 1024).contains(&max_payload_bytes) {
            return Err(ConfigError::invalid(
                "AIRPORT_MAX_PAYLOAD_BYTES",
                "must be between 1024 and 8388608",
            ));
        }
        let max_frame_bytes: usize = parse("AIRPORT_MAX_FRAME_BYTES", 1024 * 1024)?;
        if max_frame_bytes < max_payload_bytes || max_frame_bytes > 8 * 1024 * 1024 {
            return Err(ConfigError::invalid(
                "AIRPORT_MAX_FRAME_BYTES",
                "must be at least AIRPORT_MAX_PAYLOAD_BYTES and at most 8388608",
            ));
        }

        let tls_cert = var("AIRPORT_TLS_CERT");
        let tls_key = var("AIRPORT_TLS_KEY");
        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsConfig {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::invalid(
                    "AIRPORT_TLS_CERT",
                    "set both AIRPORT_TLS_CERT and AIRPORT_TLS_KEY, or neither",
                ))
            }
        };

        let public_url =
            var("AIRPORT_PUBLIC_URL").map(|value| value.trim_end_matches('/').to_string());
        if let Some(url) = &public_url {
            validate_origin("AIRPORT_PUBLIC_URL", url)?;
        }

        let log_format = match var("AIRPORT_LOG_FORMAT").as_deref() {
            None | Some("json") => LogFormat::Json,
            Some("text" | "pretty") => LogFormat::Text,
            Some(other) => {
                return Err(ConfigError::invalid(
                    "AIRPORT_LOG_FORMAT",
                    format!("expected json or text, got `{other}`"),
                ))
            }
        };

        let heartbeat_secs: u64 = parse(
            "AIRPORT_HEARTBEAT_INTERVAL_SECS",
            DEFAULT_HEARTBEAT_MS / 1000,
        )?;
        if !(5..=120).contains(&heartbeat_secs) {
            return Err(ConfigError::invalid(
                "AIRPORT_HEARTBEAT_INTERVAL_SECS",
                "must be between 5 and 120",
            ));
        }

        let message_ttl_secs: i64 = parse("AIRPORT_MESSAGE_TTL_SECS", 24 * 60 * 60)?;
        if message_ttl_secs < 60 {
            return Err(ConfigError::invalid(
                "AIRPORT_MESSAGE_TTL_SECS",
                "must be at least 60 seconds",
            ));
        }

        let config = Self {
            bind_addr,
            public_url,
            database_url,
            jwt_secret,
            access_token_ttl_secs: parse("AIRPORT_ACCESS_TOKEN_TTL_SECS", 900)?,
            refresh_token_ttl_secs: parse("AIRPORT_REFRESH_TOKEN_TTL_SECS", 30 * 24 * 60 * 60)?,
            pairing_ttl_secs: parse("AIRPORT_PAIRING_TTL_SECS", 600)?,
            ticket_ttl_secs: parse("AIRPORT_TICKET_TTL_SECS", 90)?,
            max_payload_bytes,
            max_frame_bytes,
            max_queue_depth: parse("AIRPORT_MAX_QUEUE_DEPTH", 256)?,
            offline_queue_limit: parse("AIRPORT_OFFLINE_QUEUE_LIMIT", 500)?,
            message_ttl_secs,
            retention_secs: parse("AIRPORT_RETENTION_SECS", 7 * 24 * 60 * 60)?,
            heartbeat_interval_secs: heartbeat_secs,
            messages_per_second: parse("AIRPORT_MESSAGES_PER_SECOND", 20)?,
            message_burst: parse("AIRPORT_MESSAGE_BURST", 40)?,
            auth_attempts_per_minute: parse("AIRPORT_AUTH_ATTEMPTS_PER_MINUTE", 10)?,
            allow_registration: parse_bool("AIRPORT_ALLOW_REGISTRATION", true)?,
            trusted_origins: parse_origins("AIRPORT_TRUSTED_ORIGINS", Vec::new())?,
            log_format,
            max_connections_per_user: parse("AIRPORT_MAX_CONNECTIONS_PER_USER", 20)?,
            max_devices_per_user: parse("AIRPORT_MAX_DEVICES_PER_USER", 25)?,
            replay_batch: parse("AIRPORT_REPLAY_BATCH", 100)?,
            require_e2ee: parse_bool("AIRPORT_REQUIRE_E2EE", false)?,
            tls,
            trust_proxy: parse_bool("AIRPORT_TRUST_PROXY", false)?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Reject values that parse but cannot work. A zero queue depth, a ticket
    /// that expires instantly, or a retention window shorter than the message
    /// TTL would all produce a running but broken instance, so startup fails
    /// instead of discovering it under load.
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(url) = &self.public_url {
            validate_origin("AIRPORT_PUBLIC_URL", url)?;
        }

        fn range(name: &'static str, value: i64, min: i64, max: i64) -> Result<(), ConfigError> {
            if (min..=max).contains(&value) {
                Ok(())
            } else {
                Err(ConfigError::invalid(
                    name,
                    format!("must be between {min} and {max}"),
                ))
            }
        }

        range(
            "AIRPORT_ACCESS_TOKEN_TTL_SECS",
            self.access_token_ttl_secs,
            60,
            86_400,
        )?;
        range(
            "AIRPORT_REFRESH_TOKEN_TTL_SECS",
            self.refresh_token_ttl_secs,
            self.access_token_ttl_secs,
            31_536_000,
        )?;
        range("AIRPORT_PAIRING_TTL_SECS", self.pairing_ttl_secs, 60, 3600)?;
        range("AIRPORT_TICKET_TTL_SECS", self.ticket_ttl_secs, 15, 600)?;
        range(
            "AIRPORT_MAX_QUEUE_DEPTH",
            self.max_queue_depth as i64,
            16,
            4096,
        )?;
        range(
            "AIRPORT_OFFLINE_QUEUE_LIMIT",
            self.offline_queue_limit,
            1,
            100_000,
        )?;
        range(
            "AIRPORT_MESSAGE_TTL_SECS",
            self.message_ttl_secs,
            60,
            2_592_000,
        )?;
        range(
            "AIRPORT_RETENTION_SECS",
            self.retention_secs,
            self.message_ttl_secs,
            31_536_000,
        )?;
        range(
            "AIRPORT_MESSAGES_PER_SECOND",
            self.messages_per_second as i64,
            1,
            10_000,
        )?;
        range(
            "AIRPORT_MESSAGE_BURST",
            self.message_burst as i64,
            1,
            1_000_000,
        )?;
        range(
            "AIRPORT_AUTH_ATTEMPTS_PER_MINUTE",
            self.auth_attempts_per_minute as i64,
            1,
            10_000,
        )?;
        range(
            "AIRPORT_MAX_CONNECTIONS_PER_USER",
            self.max_connections_per_user as i64,
            1,
            10_000,
        )?;
        range(
            "AIRPORT_MAX_DEVICES_PER_USER",
            self.max_devices_per_user,
            1,
            10_000,
        )?;
        range("AIRPORT_REPLAY_BATCH", self.replay_batch, 1, 1_000_000)?;
        Ok(())
    }

    /// Deterministic development configuration used by tests and examples.
    /// It is never read from the environment and must not be used in production
    /// because the JWT secret is public.
    pub fn dev_defaults() -> Self {
        let config = Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            public_url: None,
            database_url: "sqlite::memory:".into(),
            jwt_secret: "airport-development-secret-not-for-production-use".into(),
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 30 * 24 * 60 * 60,
            pairing_ttl_secs: 600,
            ticket_ttl_secs: 90,
            max_payload_bytes: 256 * 1024,
            max_frame_bytes: 1024 * 1024,
            max_queue_depth: 256,
            offline_queue_limit: 100,
            message_ttl_secs: 24 * 60 * 60,
            retention_secs: 7 * 24 * 60 * 60,
            heartbeat_interval_secs: 25,
            messages_per_second: 50,
            message_burst: 100,
            auth_attempts_per_minute: 1000,
            allow_registration: true,
            trusted_origins: Vec::new(),
            log_format: LogFormat::Text,
            max_connections_per_user: 20,
            max_devices_per_user: 25,
            replay_batch: 100,
            require_e2ee: false,
            tls: None,
            trust_proxy: false,
        };
        debug_assert!(
            config.validate().is_ok(),
            "development defaults must satisfy the production rules"
        );
        config
    }

    pub fn heartbeat_ms(&self) -> u64 {
        self.heartbeat_interval_secs * 1000
    }

    /// Absolute `ws(s)://…/v1/connect` URL for API responses, when a public URL
    /// is configured.
    pub fn websocket_url(&self, ticket: &str) -> Option<String> {
        self.public_url.as_ref().map(|base| {
            let scheme = if base.starts_with("https://") {
                "wss://"
            } else {
                "ws://"
            };
            let host = base
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            format!("{scheme}{host}/v1/connect?ticket={ticket}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_defaults_are_valid() {
        assert!(Config::dev_defaults().validate().is_ok());
    }

    #[test]
    fn rejects_values_that_parse_but_cannot_work() {
        let mut config = Config::dev_defaults();
        config.max_queue_depth = 0;
        assert!(config.validate().is_err());

        let mut config = Config::dev_defaults();
        config.ticket_ttl_secs = 0;
        assert!(config.validate().is_err());

        let mut config = Config::dev_defaults();
        config.retention_secs = config.message_ttl_secs - 1;
        assert!(config.validate().is_err());

        let mut config = Config::dev_defaults();
        config.refresh_token_ttl_secs = config.access_token_ttl_secs - 1;
        assert!(config.validate().is_err());

        let mut config = Config::dev_defaults();
        config.messages_per_second = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn debug_output_never_contains_the_signing_key() {
        let config = Config::dev_defaults();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(&config.jwt_secret));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn public_url_must_be_an_origin_without_a_path_or_credentials() {
        let mut config = Config::dev_defaults();

        config.public_url = Some("https://airport.example.com".into());
        assert!(config.validate().is_ok());

        config.public_url = Some("https://airport.example.com/base".into());
        assert!(config.validate().is_err());

        config.public_url = Some("https://user:password@airport.example.com".into());
        assert!(config.validate().is_err());

        config.public_url = Some("ftp://airport.example.com".into());
        assert!(config.validate().is_err());

        config.public_url = Some("https://:8787".into());
        assert!(config.validate().is_err());

        config.public_url = Some("https://airport.example.com:".into());
        assert!(config.validate().is_err());
    }
}
