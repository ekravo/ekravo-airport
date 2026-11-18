//! Optional end-to-end encryption.
//!
//! Airport relays ciphertext verbatim. The scheme is:
//!
//! 1. X25519 between the sender's fresh ephemeral private key and the
//!    recipient's long-term public key.
//! 2. HKDF-SHA256 with the salt `airport-e2ee-v1` and the info string
//!    [`E2EE_ALG`], producing a 32-byte key.
//! 3. AES-256-GCM with a random 12-byte nonce and the associated data
//!    `airport-e2ee-v1|<msgId>|<event>`.
//!
//! Binding the message id and event name as AAD stops a relayed ciphertext from
//! being silently re-labelled or replayed under a different id.
//!
//! Long-term keys identify endpoints; per-message ephemeral keys provide
//! forward secrecy for message contents. Airport only ever sees the ephemeral
//! public key and the nonce, both of which are public.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::error::ProtocolError;
use crate::message::Encryption;

/// Algorithm identifier carried in every `enc` header.
pub const E2EE_ALG: &str = "x25519-hkdf-sha256-aes-256-gcm";

/// AES-GCM nonce length.
pub const NONCE_BYTES: usize = 12;

/// X25519 public key length.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Prefix used for the key-derivation salt and for associated data.
pub const E2EE_CONTEXT: &str = "airport-e2ee-v1";

/// Decode and validate a base64 X25519 public key.
pub fn validate_public_key(value: &str) -> Result<Vec<u8>, ProtocolError> {
    let bytes = B64
        .decode(value)
        .map_err(|_| ProtocolError::Invalid("public key is not valid base64".into()))?;
    if bytes.len() != PUBLIC_KEY_BYTES {
        return Err(ProtocolError::Invalid(format!(
            "public key must be {PUBLIC_KEY_BYTES} bytes"
        )));
    }
    // A low-order/zero key yields an all-zero shared secret. Rust and the SDK
    // both reject it; checking the obvious all-zero case here catches the
    // mistake early without pretending to replace the library's check.
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::Invalid("public key is not usable".into()));
    }
    Ok(bytes)
}

/// Validate an encryption header and base64 payload shape.
pub fn validate_encryption(enc: &Encryption, payload: &str) -> Result<(), ProtocolError> {
    if enc.alg != E2EE_ALG {
        return Err(ProtocolError::InvalidEncryption(format!(
            "unsupported algorithm `{}`",
            enc.alg
        )));
    }
    validate_public_key(&enc.epk)
        .map_err(|_| ProtocolError::InvalidEncryption("epk is not a valid public key".into()))?;
    let nonce = B64
        .decode(&enc.nonce)
        .map_err(|_| ProtocolError::InvalidEncryption("nonce is not valid base64".into()))?;
    if nonce.len() != NONCE_BYTES {
        return Err(ProtocolError::InvalidEncryption(format!(
            "nonce must be {NONCE_BYTES} bytes"
        )));
    }
    let ciphertext = B64
        .decode(payload)
        .map_err(|_| ProtocolError::InvalidEncryption("payload is not valid base64".into()))?;
    // AES-GCM appends a 16-byte tag; anything shorter cannot be a ciphertext.
    if ciphertext.len() < 16 {
        return Err(ProtocolError::InvalidEncryption(
            "ciphertext is shorter than an authentication tag".into(),
        ));
    }
    Ok(())
}

/// Associated data for a message. Both ends must build this identically.
pub fn associated_data(msg_id: &str, event: &str) -> Vec<u8> {
    format!("{E2EE_CONTEXT}|{msg_id}|{event}").into_bytes()
}

/// HKDF salt, exposed for SDK parity.
pub fn kdf_salt() -> &'static [u8] {
    E2EE_CONTEXT.as_bytes()
}

/// HKDF info, exposed for SDK parity.
pub fn kdf_info() -> &'static [u8] {
    E2EE_ALG.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_keys_and_nonces() {
        assert!(validate_public_key("not base64").is_err());
        assert!(validate_public_key(&B64.encode([0u8; 32])).is_err());
        assert!(validate_public_key(&B64.encode([7u8; 31])).is_err());
        assert!(validate_public_key(&B64.encode([7u8; 32])).is_ok());
    }

    #[test]
    fn rejects_wrong_algorithm_and_short_ciphertext() {
        let mut enc = Encryption {
            alg: "rot13".into(),
            epk: B64.encode([9u8; 32]),
            nonce: B64.encode([1u8; NONCE_BYTES]),
            plain_type: None,
        };
        assert!(validate_encryption(&enc, &B64.encode([0u8; 32])).is_err());
        enc.alg = E2EE_ALG.into();
        assert!(validate_encryption(&enc, &B64.encode([0u8; 8])).is_err());
        assert!(validate_encryption(&enc, &B64.encode([0u8; 32])).is_ok());
    }

    #[test]
    fn associated_data_binds_id_and_event() {
        assert_eq!(
            associated_data("m1", "chat.send"),
            b"airport-e2ee-v1|m1|chat.send".to_vec()
        );
    }
}
