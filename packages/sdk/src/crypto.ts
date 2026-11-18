/**
 * End-to-end encryption shared with the Rust device client.
 *
 * X25519(ephemeral, recipient) → HKDF-SHA256 → AES-256-GCM. The associated data
 * `airport-e2ee-v1|<msgId>|<event>` stops a relayed ciphertext from being
 * replayed or re-labelled. Airport never sees the plaintext or either private
 * key.
 */

import { gcm } from "@noble/ciphers/aes";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";

import type { EncryptionHeader } from "./types.js";

export const E2EE_ALG = "x25519-hkdf-sha256-aes-256-gcm";
const CONTEXT = "airport-e2ee-v1";
const NONCE_BYTES = 12;
const KEY_BYTES = 32;

/** A long-term identity for one participant. Keep the secret key in memory. */
export interface Identity {
  secretKey: Uint8Array;
  publicKey: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index] as number);
  }
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function generateIdentity(): Identity {
  return identityFromSecretKey(x25519.utils.randomPrivateKey());
}

export function identityFromSecretKey(secretKey: Uint8Array): Identity {
  if (secretKey.length !== KEY_BYTES) {
    throw new Error("an X25519 secret key must be 32 bytes");
  }
  // Copy so callers cannot mutate the key after the fact.
  const copy = new Uint8Array(secretKey);
  return {
    secretKey: copy,
    publicKey: toBase64(x25519.getPublicKey(copy)),
  };
}

/** Restore an identity from the base64 secret produced by `exportSecret`. */
export function identityFromSecret(secret: string): Identity {
  return identityFromSecretKey(fromBase64(secret));
}

export function exportSecret(identity: Identity): string {
  return toBase64(identity.secretKey);
}

function associatedData(msgId: string, event: string): Uint8Array {
  return encoder.encode(`${CONTEXT}|${msgId}|${event}`);
}

function deriveKey(shared: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    shared,
    encoder.encode(CONTEXT),
    encoder.encode(E2EE_ALG),
    KEY_BYTES,
  );
}

function assertUsableSharedSecret(shared: Uint8Array): void {
  if (shared.every((byte) => byte === 0)) {
    throw new Error("the peer public key produced an unusable shared secret");
  }
}

export interface SealedMessage {
  payload: string;
  enc: EncryptionHeader;
}

/**
 * Encrypt bytes to a recipient's long-term public key.
 *
 * A fresh ephemeral key per message limits the damage of a leaked identity key
 * to messages an attacker can actively intercept afterwards.
 */
export function seal(
  recipientPublicKey: string,
  plaintext: Uint8Array,
  msgId: string,
  event: string,
): SealedMessage {
  const recipient = fromBase64(recipientPublicKey);
  if (recipient.length !== KEY_BYTES) {
    throw new Error("the recipient public key must be 32 bytes");
  }
  const ephemeralSecret = x25519.utils.randomPrivateKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
  const shared = x25519.getSharedSecret(ephemeralSecret, recipient);
  assertUsableSharedSecret(shared);

  const key = deriveKey(shared);
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertext = gcm(key, nonce, associatedData(msgId, event)).encrypt(plaintext);

  return {
    payload: toBase64(ciphertext),
    enc: {
      alg: E2EE_ALG,
      epk: toBase64(ephemeralPublic),
      nonce: toBase64(nonce),
    },
  };
}

/** Decrypt a message addressed to this identity. Throws on any tampering. */
export function open(
  identity: Identity,
  enc: EncryptionHeader,
  payload: string,
  msgId: string,
  event: string,
): Uint8Array {
  if (enc.alg !== E2EE_ALG) {
    throw new Error(`unsupported encryption algorithm \`${enc.alg}\``);
  }
  const sender = fromBase64(enc.epk);
  if (sender.length !== KEY_BYTES) {
    throw new Error("the sender ephemeral key must be 32 bytes");
  }
  const nonce = fromBase64(enc.nonce);
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`the nonce must be ${NONCE_BYTES} bytes`);
  }
  const shared = x25519.getSharedSecret(identity.secretKey, sender);
  assertUsableSharedSecret(shared);

  const key = deriveKey(shared);
  return gcm(key, nonce, associatedData(msgId, event)).decrypt(fromBase64(payload));
}

/** Decode plaintext bytes that the application sent as text or JSON. */
export function bytesToText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}
