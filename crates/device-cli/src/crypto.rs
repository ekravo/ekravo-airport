//! End-to-end encryption matching `@ekravo/airport-sdk`.
//!
//! X25519 → HKDF-SHA256 → AES-256-GCM, with `airport-e2ee-v1|<msgId>|<event>`
//! as associated data. Airport only ever sees the ephemeral public key, the
//! nonce, and ciphertext.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use airport_protocol::{Encryption, E2EE_ALG, E2EE_CONTEXT, NONCE_BYTES, PUBLIC_KEY_BYTES};

/// The device's long-term X25519 identity.
pub struct DeviceKeys {
    secret: StaticSecret,
    public_b64: String,
}

impl DeviceKeys {
    /// Generate a new identity from the OS random source.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public_b64: B64.encode(public.as_bytes()),
        }
    }

    pub fn from_secret_b64(value: &str) -> Result<Self> {
        let bytes = B64
            .decode(value)
            .context("private key is not valid base64")?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("private key must be 32 bytes"))?;
        let secret = StaticSecret::from(array);
        let public = PublicKey::from(&secret);
        Ok(Self {
            secret,
            public_b64: B64.encode(public.as_bytes()),
        })
    }

    pub fn secret_b64(&self) -> String {
        B64.encode(self.secret.to_bytes())
    }

    pub fn public_b64(&self) -> &str {
        &self.public_b64
    }
}

pub struct Sealed {
    pub payload_b64: String,
    pub epk: String,
    pub nonce: String,
}

fn derive(shared: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(E2EE_CONTEXT.as_bytes()), shared);
    let mut key = [0u8; 32];
    hkdf.expand(E2EE_ALG.as_bytes(), &mut key)
        .map_err(|_| anyhow!("key derivation failed"))?;
    Ok(key)
}

fn associated_data(msg_id: &str, event: &str) -> Vec<u8> {
    format!("{E2EE_CONTEXT}|{msg_id}|{event}").into_bytes()
}

fn parse_public(value: &str) -> Result<PublicKey> {
    let bytes = B64
        .decode(value)
        .context("public key is not valid base64")?;
    let array: [u8; PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    if array.iter().all(|byte| *byte == 0) {
        bail!("public key is not usable");
    }
    Ok(PublicKey::from(array))
}

/// Encrypt to a recipient's long-term public key using a fresh ephemeral key.
pub fn seal(
    recipient_public_b64: &str,
    plaintext: &[u8],
    msg_id: &str,
    event: &str,
) -> Result<Sealed> {
    let mut ephemeral = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral);
    let mut nonce = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    seal_with(
        recipient_public_b64,
        plaintext,
        msg_id,
        event,
        &ephemeral,
        &nonce,
    )
}

/// Deterministic core, used by [`seal`] and by the interoperability test that
/// pins the exact bytes the TypeScript SDK produces.
#[allow(clippy::too_many_arguments)]
fn seal_with(
    recipient_public_b64: &str,
    plaintext: &[u8],
    msg_id: &str,
    event: &str,
    ephemeral_bytes: &[u8; 32],
    nonce_bytes: &[u8; NONCE_BYTES],
) -> Result<Sealed> {
    let ephemeral = StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let recipient = parse_public(recipient_public_b64)?;

    let shared = ephemeral.diffie_hellman(&recipient);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        bail!("the recipient public key produced an unusable shared secret");
    }
    let key = derive(shared.as_bytes())?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &associated_data(msg_id, event),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;

    Ok(Sealed {
        payload_b64: B64.encode(ciphertext),
        epk: B64.encode(ephemeral_public.as_bytes()),
        nonce: B64.encode(nonce_bytes),
    })
}

/// Decrypt with the device's long-term secret and the sender's ephemeral key.
pub fn open(
    keys: &DeviceKeys,
    enc: &Encryption,
    payload_b64: &str,
    msg_id: &str,
    event: &str,
) -> Result<Vec<u8>> {
    if enc.alg != E2EE_ALG {
        bail!("unsupported encryption algorithm `{}`", enc.alg);
    }
    let sender = parse_public(&enc.epk)?;
    let nonce_bytes = B64
        .decode(&enc.nonce)
        .context("nonce is not valid base64")?;
    if nonce_bytes.len() != NONCE_BYTES {
        bail!("nonce must be {NONCE_BYTES} bytes");
    }
    let ciphertext = B64
        .decode(payload_b64)
        .context("payload is not valid base64")?;

    let shared = keys.secret.diffie_hellman(&sender);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        bail!("the sender public key produced an unusable shared secret");
    }
    let key = derive(shared.as_bytes())?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: &associated_data(msg_id, event),
            },
        )
        .map_err(|_| anyhow!("the message could not be authenticated"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_identities_can_exchange_both_directions() {
        let alice = DeviceKeys::generate();
        let bob = DeviceKeys::generate();

        let sealed = seal(bob.public_b64(), b"hello bob", "m1", "chat.send").unwrap();
        let enc = Encryption {
            alg: E2EE_ALG.into(),
            epk: sealed.epk.clone(),
            nonce: sealed.nonce.clone(),
            plain_type: None,
        };
        let opened = open(&bob, &enc, &sealed.payload_b64, "m1", "chat.send").unwrap();
        assert_eq!(opened, b"hello bob");

        let reply = seal(alice.public_b64(), b"hi alice", "m2", "chat.reply").unwrap();
        let enc = Encryption {
            alg: E2EE_ALG.into(),
            epk: reply.epk,
            nonce: reply.nonce,
            plain_type: None,
        };
        assert_eq!(
            open(&alice, &enc, &reply.payload_b64, "m2", "chat.reply").unwrap(),
            b"hi alice"
        );
    }

    #[test]
    fn tampering_with_ids_or_ciphertext_fails() {
        let bob = DeviceKeys::generate();
        let sealed = seal(bob.public_b64(), b"secret", "m1", "chat.send").unwrap();
        let enc = Encryption {
            alg: E2EE_ALG.into(),
            epk: sealed.epk.clone(),
            nonce: sealed.nonce.clone(),
            plain_type: None,
        };
        assert!(open(&bob, &enc, &sealed.payload_b64, "m2", "chat.send").is_err());
        assert!(open(&bob, &enc, &sealed.payload_b64, "m1", "other.event").is_err());

        let mut bytes = B64.decode(&sealed.payload_b64).unwrap();
        bytes[0] ^= 1;
        assert!(open(&bob, &enc, &B64.encode(bytes), "m1", "chat.send").is_err());
    }

    #[test]
    fn keys_round_trip_through_base64() {
        let keys = DeviceKeys::generate();
        let restored = DeviceKeys::from_secret_b64(&keys.secret_b64()).unwrap();
        assert_eq!(restored.public_b64(), keys.public_b64());
    }

    // Fixed inputs shared with packages/sdk/test/crypto.test.mjs. Both
    // implementations must derive this exact ciphertext, which is what makes
    // "the Rust client and the TypeScript SDK interoperate" a tested claim.
    const INTEROP_SECRET_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    const INTEROP_PUBLIC_B64: &str = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";
    const INTEROP_EPK_B64: &str = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=";
    const INTEROP_NONCE_B64: &str = "ZWZnaGlqa2xtbm9w";
    const INTEROP_CIPHERTEXT_B64: &str = "6Nvfk/FLf4DVHokr0VjdOrehkMjBuStfx82UcTuo0OYhWj7TcjQ=";

    #[test]
    fn matches_the_typescript_interoperability_vector() {
        let keys = DeviceKeys::from_secret_b64(INTEROP_SECRET_B64).unwrap();
        assert_eq!(keys.public_b64(), INTEROP_PUBLIC_B64);

        let ephemeral: [u8; 32] = std::array::from_fn(|index| index as u8 + 33);
        let nonce: [u8; NONCE_BYTES] = std::array::from_fn(|index| index as u8 + 101);
        let sealed = seal_with(
            keys.public_b64(),
            b"Airport interop vector",
            "msg_interop_1",
            "chat.send",
            &ephemeral,
            &nonce,
        )
        .unwrap();

        assert_eq!(sealed.epk, INTEROP_EPK_B64);
        assert_eq!(sealed.nonce, INTEROP_NONCE_B64);
        assert_eq!(sealed.payload_b64, INTEROP_CIPHERTEXT_B64);

        let enc = Encryption {
            alg: E2EE_ALG.into(),
            epk: sealed.epk,
            nonce: sealed.nonce,
            plain_type: None,
        };
        assert_eq!(
            open(
                &keys,
                &enc,
                &sealed.payload_b64,
                "msg_interop_1",
                "chat.send"
            )
            .unwrap(),
            b"Airport interop vector"
        );
    }
}
