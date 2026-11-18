use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::util::now_secs;

/// Stable issuer claim. It distinguishes Airport access tokens from any other
/// JWT signed with the same secret.
pub const TOKEN_ISSUER: &str = "ekravo-airport";
/// Prefix on every device credential, used for cheap discrimination.
pub const DEVICE_CREDENTIAL_PREFIX: &str = "airport_dev_";
/// Prefix on human-entered pairing codes.
pub const PAIRING_CODE_PREFIX: &str = "airport_pair_";

/// Argon2id hash of a password. This is intentionally slow; it runs only on
/// registration and login, never per request.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| {
            tracing::error!(error = %error, "password hashing failed");
            ApiError::internal("could not secure the password")
        })
}

/// Constant-time verification handled by argon2.
pub fn verify_password(password: &str, stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// URL-safe random secret with `bytes` bytes of entropy.
pub fn new_secret(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

pub fn new_device_credential() -> String {
    format!("{DEVICE_CREDENTIAL_PREFIX}{}", new_secret(32))
}

pub fn new_pairing_code() -> String {
    format!("{PAIRING_CODE_PREFIX}{}", new_secret(24))
}

pub fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Indexed lookup key for an opaque secret. The full hash is still compared.
pub fn secret_prefix(hash: &str) -> String {
    hash.chars().take(16).collect()
}

/// Claims carried by a short-lived access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub iss: String,
    pub typ: String,
}

/// Mint an access token. Returns the token and its lifetime in seconds.
pub fn issue_access_token(
    secret: &str,
    user_id: &str,
    ttl_secs: i64,
) -> Result<(String, i64), ApiError> {
    let issued_at = now_secs();
    let claims = AccessClaims {
        sub: user_id.to_string(),
        exp: issued_at + ttl_secs,
        iat: issued_at,
        jti: new_secret(12),
        iss: TOKEN_ISSUER.to_string(),
        typ: "access".to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|error| {
        tracing::error!(error = %error, "token signing failed");
        ApiError::internal("could not issue a token")
    })?;
    Ok((token, ttl_secs))
}

/// Verify signature, issuer, expiry, and token type.
pub fn decode_access_token(secret: &str, token: &str) -> Result<AccessClaims, ApiError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_required_spec_claims(&["exp", "sub", "iss"]);
    validation.leeway = 5;
    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::unauthorized("access token is invalid or expired"))?;
    if data.claims.typ != "access" {
        return Err(ApiError::unauthorized("access token is invalid or expired"));
    }
    Ok(data.claims)
}

/// Bearer value from an `Authorization` header, without the scheme.
pub fn bearer_token(header: Option<&str>) -> Option<&str> {
    header
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_round_trip_and_reject_wrong_input() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn access_tokens_are_verified_and_typed() {
        let secret = "0123456789abcdef0123456789abcdef";
        let (token, ttl) = issue_access_token(secret, "usr_1", 60).unwrap();
        assert_eq!(ttl, 60);
        let claims = decode_access_token(secret, &token).unwrap();
        assert_eq!(claims.sub, "usr_1");
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert!(decode_access_token("another-secret-another-secret-1234", &token).is_err());
    }

    #[test]
    fn secrets_are_prefixed_and_hashed_for_lookup() {
        let credential = new_device_credential();
        assert!(credential.starts_with(DEVICE_CREDENTIAL_PREFIX));
        let hash = sha256_hex(&credential);
        assert_eq!(hash.len(), 64);
        assert_eq!(secret_prefix(&hash).len(), 16);
    }
}
