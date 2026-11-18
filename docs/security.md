# Security

## Threat model

Airport assumes:

- The network is hostile. Transport may be inspected or altered; use TLS.
- A device and the server are separate trust domains. The device holds secrets
  the server must not learn.
- Any peer may be malicious: a browser tab, another account, or a stolen device
  credential.
- The operator is trusted to configure the server and protect its host. Airport
  does not defend against a compromised host that can read process memory or the
  database.

Airport is **not** a VPN, a reverse proxy, or a remote-shell service. It relays
application-defined messages. It never opens a shell, reads files, or executes a
command on a device.

## What Airport protects

| Risk | Control |
| --- | --- |
| Credential theft from a URL or proxy log | WebSockets use single-use 90 s tickets; device credentials stay in headers |
| Password database leak | Argon2id with per-password salt |
| Stolen refresh token replayed | Refresh tokens rotate; reuse revokes the whole family |
| Cross-account device access | Owner check, then an explicit, revocable, event-scoped grant |
| Identity spoofing in a frame | Sender identity and connection id are injected by the server |
| Replay of a message | `(sender, msgId)` uniqueness; tickets and pairing codes are single-use |
| Resource exhaustion | Frame/payload ceilings, bounded socket queues, mailbox caps, token buckets, per-IP windows |
| Payload inspection by the relay | Optional E2EE; the server only sees ciphertext and public metadata |
| Silent logging of content | No payload, token, password, or email is logged; ids and sizes only |
| Revoked device continuing | Live socket is told `revoked`, then closed; credential stops authenticating |

## Credentials

- **Passwords** are hashed with Argon2id (`argon2` defaults) and never logged.
  Login performs the same expensive work for unknown accounts, so timing does not
  reveal whether an address exists.
- **Access tokens** are HS256 JWTs with `iss=ekravo-airport`, `typ=access`, a
  unique `jti`, and a 15-minute lifetime. The secret must be at least 32
  characters; rotating it invalidates every access token immediately.
- **Refresh tokens** are 32 random bytes, stored only as SHA-256 hashes. Every
  refresh rotates the token in a single transaction: revoking the old row and
  inserting its replacement cannot be split by two simultaneous requests.
  Presenting an already-rotated token is treated as theft: every refresh token
  for that account is revoked.
- **Device credentials** are `airport_dev_` plus 32 random bytes, stored as a
  SHA-256 hash with a 16-character indexed prefix. The prefix narrows the lookup;
  the full hash is compared in constant time.
- **Pairing codes** are `airport_pair_` plus 24 random bytes, stored hashed,
  single-use, ten minutes, IP rate-limited.
- **Connection tickets** are 32 random bytes, stored hashed, single-use, 90
  seconds. They appear in a URL by necessity; their lifetime and single use are
  what make that acceptable.

### Client-side storage

The reference device client writes its identity and credential to
`<config>/ekravo-airport/device.json` with mode 0600 and an atomic rename. A
production desktop application should store the credential in the OS credential
store (Keychain, libsecret, DPAPI/Credential Manager) and keep only non-secret
metadata in the config file. See [integration](integration.md).

## Transport

- Use `https://` and `wss://` in production. Either terminate TLS at Airport
  (`AIRPORT_TLS_CERT` / `AIRPORT_TLS_KEY`) or at a reverse proxy you control.
- When Airport terminates TLS itself it sends HSTS. Behind a proxy, set HSTS at
  the proxy.
- `AIRPORT_TRUSTED_ORIGINS` is enforced on both the HTTP API (CORS) and the
  WebSocket upgrade. A browser `Origin` that is not listed is refused before its
  ticket is consumed; non-browser clients send no `Origin` and are unaffected.
- `AIRPORT_TRUST_PROXY=true` makes rate limiting honor `X-Forwarded-For`. Enable
  it only when every request passes through a proxy you control; otherwise a
  caller can choose its own bucket.
- The reference device verifies platform roots by default. With `--ca-cert` /
  `AIRPORT_CA_CERT`, its HTTP client adds that CA and its WebSocket trust store
  contains exactly the configured CA; verification is never disabled. The
  TypeScript SDK uses the `fetch`/`WebSocket` runtime's trust store (for Node,
  `NODE_EXTRA_CA_CERTS`).

## Authorization

Every routed message is checked against:

1. The authenticated sender, established by ticket or credential.
2. The target device's owner (`device.user_id`).
3. If the sender is not the owner, an **active grant** from the owner to the
   sender's account, and the event must match one of the grant's patterns.

A device replying to a connection must either own that connection's account or
hold a grant for that account. A client may broadcast only to its own account.
Airport rewrites `from` from server-side state, so a frame cannot claim another
identity.

Patterns (`*`, exact, `prefix*`) constrain grantees only. The owner can always
reach their own devices. Revoking a grant takes effect on the next message; no
cache has to expire.

## Resource limits

Defaults; all configurable.

| Limit | Default |
| --- | --- |
| WebSocket frame | 1 MiB |
| Message payload | 256 KiB |
| Socket outbound queue | 256 frames |
| Messages per second per socket | 20, burst 40 |
| Auth attempts per IP per minute | 10 |
| Pairing-code, ticket, and grant requests per account per minute | 10 |
| HTTP API request deadline | 30 seconds |
| WebSocket write deadline | 10 seconds |
| Offline mailbox per device | 500 messages |
| Message TTL | 24 hours |
| Idempotency/retention | 7 days |
| Devices per account | 25 |
| Connections per account | 20 |

Exceeding a per-connection rate returns `rate_limited` rather than closing the
socket. Exceeding a payload limit is rejected during validation, before the
payload is processed. The per-account connection cap is reserved atomically when
the socket is established and released when it ends, so a burst of minted
tickets cannot exceed it or leak a slot.

## End-to-end encryption

E2EE is optional per message. When used, Airport forwards opaque bytes.

### Construction

For a sender with an ephemeral X25519 key `e` and a recipient with long-term
public key `R`:

```
shared = X25519(e_private, R)
key    = HKDF-SHA256(
           ikm  = shared,
           salt = "airport-e2ee-v1",
           info = "x25519-hkdf-sha256-aes-256-gcm",
           len  = 32)
nonce  = 12 random bytes
aad    = "airport-e2ee-v1|" + msgId + "|" + event
ct     = AES-256-GCM(key, nonce, aad, plaintext)
```

The frame carries `alg`, `epk` (the ephemeral public key), `nonce`, and base64
ciphertext as `payload` with `contentType: "binary"`. The Rust client and
TypeScript SDK implement exactly this, and both test suites pin the same fixed
vector: identical inputs must yield byte-identical ciphertext and each side must
decrypt the other's output.

AAD binds ciphertext to its message id and event name, so a relay cannot
re-label or replay a ciphertext under a different id without detection.

### Properties

- Airport cannot read the payload.
- A new ephemeral key per message means compromise of an *ephemeral* secret does
  not expose other messages.
- Compromise of a long-term private key exposes messages encrypted to that key,
  past and future. This is static-recipient encryption, not a full Double Ratchet;
  it provides no post-compromise healing. Do not describe it as more than it is.
- Metadata is still visible to Airport: who talks to whom, when, message sizes,
  event names, and message ids. If that is sensitive, operate your own Airport.
- The server validates the header shape (algorithm, 32-byte key, 12-byte nonce,
  minimum ciphertext length). It cannot validate authenticity.
- Plaintext mode exists for compatibility and debugging. Set
  `AIRPORT_REQUIRE_E2EE=true` to refuse unencrypted application messages. This
  affects every client, including devices that only speak plaintext.

## Metadata and enumeration

Registration returns `409` for an existing address, and grant creation returns
`404` for an address without an account. Both are rate-limited, but the signal
remains: an authenticated caller can discover whether an address is registered.
This is inherent to signing in by email and to sharing by email. If that matters
for your deployment, close registration, distribute invitations out of band, and
avoid the sharing flow.

Airport also sees message metadata even with E2EE: sender and recipient ids,
timestamps, sizes, event names, and message ids. Operating your own instance is
the only way to keep that from a third-party relay.

## Logging and privacy

- Structured logs contain connection ids, user ids, device ids, error codes, and
  counts. They never contain payloads, passwords, tokens, pairing codes,
  credentials, or email addresses. The HTTP trace span logs the request path,
  never the full URI, so a single-use ticket in `/v1/connect?ticket=…` cannot be
  written by debug logging. `Config`'s `Debug` implementation redacts the
  signing key, so a future diagnostic log cannot leak it by printing the config.
- HTTP error bodies are generic for internal failures; database errors are logged
  server-side only. API requests have a 30-second deadline and WebSocket writes
  have a 10-second deadline, so a slow peer cannot hold a task forever.
- The database necessarily stores message payloads for offline devices, because
  delivery requires it. With E2EE those payloads are ciphertext. Retention is
  bounded by `AIRPORT_RETENTION_SECS`.
- Pairing codes and tickets are deleted an hour after expiry; acknowledged
  messages after the retention window.

## Designing a safe device

Airport enforces **authorization**, not **intent**. A device that exposes
`exec.run` to every grantee is a remote shell, and no relay can make that safe.

Rules for device implementations:

- Expose a small, named event API (`document.open`, `media.play`, `chat.send`).
  Never expose a generic shell, `eval`, or unrestricted filesystem read/write.
- Validate every field of an event again on the device. The relay's schema check
  says nothing about your payload.
- Treat encrypted and plaintext messages with the same suspicion.
- Require explicit, per-device user consent before handling a new event type.
- Keep authorization decisions on the device for destructive actions; a grant
  pattern is a coarse filter, not a capability system.
- Never let a grantee enumerate other devices or other accounts.

## Operator checklist

- [ ] `AIRPORT_JWT_SECRET` is at least 32 random bytes, stored outside the repo.
- [ ] TLS is enabled, or a trusted proxy terminates it.
- [ ] `AIRPORT_TRUSTED_ORIGINS` lists only your real web origins.
- [ ] `AIRPORT_ALLOW_REGISTRATION` matches your policy (first account always
      works; close registration afterwards).
- [ ] `AIRPORT_TRUST_PROXY` is true only behind a controlled proxy.
- [ ] The database file and `.env` are readable only by the service account.
- [ ] Backups exist and a restore has been tested.
- [ ] `/healthz` and `/readyz` are monitored.
- [ ] Logs are shipped somewhere with retention, and access is restricted.
- [ ] Revoking a device is part of your incident runbook.

## Dependency hygiene

CI runs two advisory gates against the committed lockfiles:

```bash
cargo audit --deny warnings
(cd packages/sdk && npm audit --audit-level=high)
```

`cargo audit` scans the full Rust graph, including dev-dependencies; `npm audit`
scans the SDK's installed graph. A new vulnerability or unmaintained crate fails
the job. Do not add a silent ignore: fix the dependency, or document the reason
and the follow-up here and in the audit configuration.

### Pinned SQLite binding

`sqlx-sqlite` 0.8.6 pins `libsqlite3-sys 0.30.1`, which bundles SQLite 3.46 and
is affected by [RUSTSEC-2026-0459] (CVE-2026-119375): a crafted database and
`-wal` file pair can make a process that opens them return uninitialized
page-cache memory. The attack is local and requires the victim to open
attacker-written files, but it is a real information-disclosure bug.

The upstream fix is `libsqlite3-sys 0.39.0` (SQLite 3.54.0). The sqlx release
that allows it, 0.9.1, requires Rust 1.94, above this project's supported 1.89
MSRV. `vendor/sqlx-sqlite` is the upstream 0.8.6 source with only the binding
version changed to 0.39.1 (SQLite 3.54.1, Rust 1.88). The workspace
`[patch.crates-io]` selects it, and `cargo audit --deny warnings` is clean on
the resulting lockfile. This removes the vulnerable code rather than relying on
Airport's usual file permissions.

Remove the patch when a released sqlx uses `libsqlite3-sys >= 0.39` and still
builds on Rust 1.89. The exact diff and removal steps are in
[`vendor/sqlx-sqlite/PATCH.md`](../vendor/sqlx-sqlite/PATCH.md).

[RUSTSEC-2026-0459]: https://rustsec.org/advisories/RUSTSEC-2026-0459

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Please do not open a public issue for a
suspected vulnerability.
