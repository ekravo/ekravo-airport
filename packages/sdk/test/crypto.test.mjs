import test from "node:test";
import assert from "node:assert/strict";

import { gcm } from "@noble/ciphers/aes";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import {
  E2EE_ALG,
  bytesToText,
  exportSecret,
  fromBase64,
  generateIdentity,
  identityFromSecret,
  open,
  seal,
  toBase64,
} from "../dist/index.js";

test("identities survive export and restore", () => {
  const identity = generateIdentity();
  const restored = identityFromSecret(exportSecret(identity));
  assert.equal(restored.publicKey, identity.publicKey);
  assert.deepEqual(restored.secretKey, identity.secretKey);
});

test("two identities exchange encrypted messages both ways", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();

  const toBob = seal(bob.publicKey, new TextEncoder().encode("hello bob"), "m1", "chat.send");
  assert.equal(toBob.enc.alg, E2EE_ALG);
  const plaintext = open(bob, toBob.enc, toBob.payload, "m1", "chat.send");
  assert.equal(new TextDecoder().decode(plaintext), "hello bob");

  const toAlice = seal(alice.publicKey, new TextEncoder().encode("hi alice"), "m2", "chat.reply");
  assert.equal(
    new TextDecoder().decode(open(alice, toAlice.enc, toAlice.payload, "m2", "chat.reply")),
    "hi alice",
  );
});

test("a ciphertext is bound to its message id and event", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const sealed = seal(bob.publicKey, new TextEncoder().encode("secret"), "m1", "chat.send");

  assert.throws(() => open(bob, sealed.enc, sealed.payload, "m2", "chat.send"));
  assert.throws(() => open(bob, sealed.enc, sealed.payload, "m1", "other.event"));
  assert.throws(() => open(alice, sealed.enc, sealed.payload, "m1", "chat.send"));
});

// Fixed inputs shared with crates/device-cli/src/crypto.rs. The Rust test
// asserts it derives this exact ciphertext, so the two implementations are
// pinned to one another rather than only tested against themselves.
const VECTOR = {
  secret: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
  publicKey: "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=",
  epk: "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=",
  nonce: "ZWZnaGlqa2xtbm9w",
  ciphertext: "6Nvfk/FLf4DVHokr0VjdOrehkMjBuStfx82UcTuo0OYhWj7TcjQ=",
};

test("matches the shared Rust interoperability vector", () => {
  const encoder = new TextEncoder();
  const recipient = x25519.getPublicKey(fromBase64(VECTOR.secret));
  assert.equal(toBase64(recipient), VECTOR.publicKey);

  const ephemeral = Uint8Array.from({ length: 32 }, (_, index) => index + 33);
  const shared = x25519.getSharedSecret(ephemeral, recipient);
  const key = hkdf(
    sha256,
    shared,
    encoder.encode("airport-e2ee-v1"),
    encoder.encode(E2EE_ALG),
    32,
  );
  const ciphertext = gcm(
    key,
    fromBase64(VECTOR.nonce),
    encoder.encode("airport-e2ee-v1|msg_interop_1|chat.send"),
  ).encrypt(encoder.encode("Airport interop vector"));
  assert.equal(toBase64(ciphertext), VECTOR.ciphertext);

  const identity = identityFromSecret(VECTOR.secret);
  const plaintext = open(
    identity,
    { alg: E2EE_ALG, epk: VECTOR.epk, nonce: VECTOR.nonce },
    VECTOR.ciphertext,
    "msg_interop_1",
    "chat.send",
  );
  assert.equal(bytesToText(plaintext), "Airport interop vector");
  assert.equal(toBase64(x25519.getPublicKey(fromBase64(VECTOR.secret))), identity.publicKey);
});

test("tampered ciphertext and headers are rejected", () => {
  const bob = generateIdentity();
  const sealed = seal(bob.publicKey, new TextEncoder().encode("secret"), "m1", "chat.send");

  const bytes = Buffer.from(sealed.payload, "base64");
  bytes[0] ^= 1;
  assert.throws(() => open(bob, sealed.enc, bytes.toString("base64"), "m1", "chat.send"));

  assert.throws(() =>
    open(
      bob,
      { ...sealed.enc, alg: "none" },
      sealed.payload,
      "m1",
      "chat.send",
    ),
  );
});
