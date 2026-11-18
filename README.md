# Ekravo Airport

**An independent, self-hostable relay that connects websites to software running
on your own computer.**

Devices dial **out** to Airport over one persistent WebSocket. Nothing listens on
the device, no port is forwarded, and no address is published. An authorized
website, browser extension, or app sends a message to the relay; Airport checks
who is allowed to reach which device and delivers it. Replies travel back on the
same socket.

Airport is MIT licensed, runs on a single Rust binary with SQLite, and **never
requires an Ekravo account**. It is designed to power communication across the
Ekravo ecosystem, but it is useful on its own.

```
 browser / website ──HTTPS──▶ ┌──────────────────┐ ◀──WSS── desktop app
                              │  Ekravo Airport  │
                              │  auth · routing  │
                              │  mailboxes · TLS │
                              └──────────────────┘
```

## What is in this repository

| Component | Path | Purpose |
| --- | --- | --- |
| Protocol | `crates/protocol` | Versioned JSON frames, validation, error codes, E2EE constants |
| Server | `crates/server` | Axum/Tokio HTTP API and WebSocket relay, SQLite persistence |
| Device client | `crates/device-cli` | Reference Rust client: pair, connect, ack, reply |
| TypeScript SDK | `packages/sdk` | Browser + Node client with end-to-end encryption |
| Deployment | `Dockerfile`, `docker-compose.yml`, `deploy/` | Container and systemd units |
| Documentation | `docs/` | Architecture, protocol, API, security, self-hosting, integration |

## Features

**Communication**

- Persistent bidirectional WebSockets with heartbeats and automatic reconnect.
- Messages addressed to a device, a specific connection, or every connection of
  a user.
- Durable mailboxes: messages for an offline device are stored, replayed on
  reconnect, and acknowledged. At-least-once delivery with `msgId` deduplication.
- Presence events when a device connects or disconnects.

**Devices**

- One-time pairing codes exchanged for a per-device credential.
- Multiple devices per account, credential rotation, immediate revocation.
- Revoking a device closes its live socket and invalidates its credential.

**Security**

- Argon2id passwords, short-lived JWT access tokens, rotating refresh tokens with
  reuse detection.
- Single-use, 90-second connection tickets instead of secrets in WebSocket URLs.
- Strict frame validation, payload and frame ceilings, per-connection token
  buckets, per-IP limits on unauthenticated endpoints.
- Optional end-to-end encryption (X25519 + HKDF-SHA256 + AES-256-GCM) so Airport
  relays ciphertext it cannot read.
- Structured, privacy-conscious logs: ids and sizes, never payloads or secrets.
- **No shell, filesystem, or arbitrary RPC surface.** Devices decide what an
  event means; Airport only moves bytes.

## Quick start

Requirements: Rust 1.89+ (or Docker). Node 20+ only if you want the TypeScript SDK.

```bash
git clone https://github.com/ekravo/ekravo-airport.git
cd airport
cp .env.example .env

# Put a real secret in .env:
#   openssl rand -base64 48
$EDITOR .env

cargo run -p airport-server
```

The server binds `0.0.0.0:8787` by default, so it is reachable at
`http://127.0.0.1:8787`. For a local-only instance, set
`AIRPORT_BIND_ADDR=127.0.0.1:8787` in `.env`; otherwise put a firewall and a TLS
proxy in front of any public interface.

```bash
curl -s http://127.0.0.1:8787/healthz
curl -s http://127.0.0.1:8787/readyz
```

Create the first account (the first account works even when registration is
closed, so a fresh instance is never locked out):

```bash
curl -s http://127.0.0.1:8787/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct horse battery","displayName":"You"}'
```

Pair the reference device and run it:

```bash
TOKEN=…            # accessToken from the response above
CODE=$(curl -s http://127.0.0.1:8787/api/v1/devices/pairing \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Laptop"}' | jq -r .code)

cargo run -p airport-device -- pair --code "$CODE" --name "Laptop"
cargo run -p airport-device -- run
```

Send it a message with the TypeScript SDK:

```bash
(cd packages/sdk && npm install && npm run build)

AIRPORT_EMAIL=you@example.com \
AIRPORT_PASSWORD='correct horse battery' \
node examples/node-echo.mjs
```

The device answers `echo` with `echo.reply`, echoed to the connection that asked.

## Docker

```bash
cp .env.example .env      # set AIRPORT_JWT_SECRET
docker compose -p airport up -d --build
docker inspect --format '{{.State.Health.Status}}' airport-airport-1
curl -s http://127.0.0.1:8787/healthz
```

Or without Compose:

```bash
docker build -t ekravo-airport:0.1.0 .
docker run -d --name airport \
  --restart unless-stopped \
  -p 127.0.0.1:8787:8787 \
  -v airport-data:/var/lib/airport \
  --env-file .env \
  ekravo-airport:0.1.0
```

The container runs as an unprivileged user and persists SQLite in the
`airport-data` volume; `docker-compose.yml` additionally drops all capabilities
and makes the root filesystem read-only. Compose publishes the port on
`127.0.0.1` only — put a TLS proxy in front, or change the mapping to
`"8787:8787"` once you have decided the plaintext port is safe to expose.
Paired devices and queued messages survive `docker restart`.

### Docker with TLS

Airport can terminate TLS in the container. Generate a throwaway CA and a
`localhost`/`127.0.0.1` certificate, then build the chain:

```bash
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout tls/ca-key.pem -out tls/ca.pem \
  -subj "/CN=Airport Container Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -new -newkey rsa:2048 -nodes \
  -keyout tls/server-key.pem -out tls/server.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage=serverAuth"
openssl x509 -req -in tls/server.csr -CA tls/ca.pem -CAkey tls/ca-key.pem \
  -CAcreateserial -out tls/server.pem -days 2 -sha256 -copy_extensions copy
cat tls/server.pem tls/ca.pem > tls/server-fullchain.pem
chmod 0644 tls/ca.pem tls/server-fullchain.pem tls/server-key.pem
```

Create `tls/airport.env` with the secret, TLS paths, database URL, public
`https://localhost:8443` origin, and trusted origins, then run:

```bash
docker build -t ekravo-airport:0.1.0 .
docker run -d --name airport-tls \
  --restart unless-stopped \
  -p 127.0.0.1:8443:8787 \
  -v airport-tls-data:/var/lib/airport \
  --mount type=bind,source="$PWD/tls",target=/certs,readonly \
  --mount type=bind,source="$PWD/tls/airport.env",target=/etc/airport/airport.env,readonly \
  -e AIRPORT_ENV_FILE=/etc/airport/airport.env \
  -e AIRPORT_HEALTHCHECK_URL=https://127.0.0.1:8787/healthz \
  -e AIRPORT_HEALTHCHECK_CA=/certs/ca.pem \
  ekravo-airport:0.1.0
```

```bash
docker inspect --format '{{.State.Health.Status}}' airport-tls
curl --cacert tls/ca.pem https://localhost:8443/healthz
docker stop airport-tls && docker start airport-tls
```

Or start the same TLS stack with Compose, which mounts the certs and env file
and configures the inherited HTTPS healthcheck:

```bash
docker compose -f docker-compose.tls.yml -p airport-tls up -d --build
docker inspect --format '{{.State.Health.Status}}' airport-tls-airport-1
```

Plaintext on the TLS port is refused, and devices pair with
`airport-device pair --server https://localhost:8443 --ca-cert tls/ca.pem`.
The full flow, including the env file contents, the Compose TLS stack, and
Windows/Git Bash path notes, is in
[self-hosting](docs/self-hosting.md#docker-with-in-process-tls).

## How routing authorization works

- A device can always be reached by its **owner**.
- Another account can reach it only through a **grant** created by the owner.
  Grants are revocable and can be limited to event patterns such as `chat.*`.
- A device may reply on the connection that sent a request, or to another
  connection belonging to its owner or to a grantee.
- A client may broadcast only to its own account's connections.
- Airport injects the sender identity; a peer cannot claim to be someone else.

## Configuration

All settings are environment variables documented in
[`.env.example`](.env.example). The file is read from the working directory
(`.env`), or from `AIRPORT_ENV_FILE`. Real environment variables win.

- Local and Docker: `<repository>/.env`
- systemd: `/etc/ekravo-airport/airport.env`
- Platform-as-a-service: set the variables in the provider's secret store

`AIRPORT_JWT_SECRET` is required and must be at least 32 characters. Nothing else
is mandatory; every other value has a deliberate default.

## Documentation

- [Architecture](docs/architecture.md) — components, data flow, persistence, limits
- [Protocol](docs/protocol.md) — every frame, acknowledgements, delivery semantics
- [HTTP API](docs/api.md) — endpoints, request and response shapes
- [Security](docs/security.md) — threat model, credentials, E2EE, what Airport cannot do
- [Self-hosting](docs/self-hosting.md) — Docker, systemd, TLS, backups, upgrades
- [Integration](docs/integration.md) — how Ekravo Desktop and Ekravo Website can adopt Airport

## End-to-end encryption

Airport can route messages it cannot read. A message may carry:

```json
{
  "contentType": "binary",
  "payload": "base64 ciphertext",
  "enc": {
    "alg": "x25519-hkdf-sha256-aes-256-gcm",
    "epk": "base64 ephemeral public key",
    "nonce": "base64 12-byte nonce"
  }
}
```

The server validates the header's shape and size and forwards it unchanged. The
Rust client and the TypeScript SDK derive the same key; a fixed test vector in
both suites (`crates/device-cli/src/crypto.rs` and
`packages/sdk/test/crypto.test.mjs`) asserts that they produce byte-for-byte
identical ciphertext. See [docs/security.md](docs/security.md#end-to-end-encryption)
for the exact construction and its limits.

## Development

```bash
cargo test --workspace --locked          # protocol, server, device client
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check

(cd packages/sdk && npm ci && npm test)

# Full proof: builds release binaries + SDK, runs plaintext and TLS/WSS
node scripts/e2e.mjs
```

The end-to-end proof requires Node 22+ (it uses `node:sqlite` for a read-only
state check), npm, OpenSSL, and Rust 1.89+. It generates an ephemeral CA,
starts two real paired `airport-device` processes in separate configs, and
covers two accounts, raw WebSocket and SDK text/binary payloads, sender-sealed
E2EE, granted and forbidden events, offline queue/replay, repeated
send/kill/queue/reconnect races, restart on a preserved database with a device
process staying up, and mid-session revocation. Every wait is on an observable
condition (presence, receipts, `/devices` state, `/healthz`, process exit, or a
read-only SQLite acknowledgement check); there are no fixed settle delays.

Set `E2E_MODES=plaintext` or `E2E_MODES=tls` for one transport,
`E2E_CYCLES=N` to change the number of race windows, and `E2E_KEEP=1` to keep
the temporary work directory. The command removes its work directory otherwise.

CI also runs the suite on the declared minimum toolchain (Rust 1.89) with
`--locked`, so the MSRV and the committed lockfile are both tested rather than
assumed. A separate job runs `cargo audit --deny warnings` and
`npm audit --audit-level=high`; the one pinned SQLite binding and its removal
condition are documented in [docs/security.md](docs/security.md#pinned-sqlite-binding).
The E2E proof is a CI job as well, using the same Node 22 pin as the SDK and
audit jobs.

The Rust integration suite starts a real server on an ephemeral port and drives
it with real WebSocket clients: pairing, relay, acks, offline replay, duplicate
suppression, grants, revocation, ticket reuse, payload limits, and rate limits.
A separate file-backed concurrency test contends mailbox inserts with device
acknowledgements so a WAL write race cannot silently return to the relay path.

## Status and scope

Version 0.1.0 is a complete single-node relay:

- The in-memory connection registry is authoritative for **live** sockets, while
  SQLite owns identities, devices, grants, and mailboxes. A restart disconnects
  sockets; devices reconnect and receive unacknowledged messages.
- Horizontal scaling is not implemented. Running multiple instances requires a
  shared registry and sticky routing for device sockets; see
  [Architecture → Scaling](docs/architecture.md#scaling).
- Airport is transport, not an application protocol. A device must not expose a
  general shell or unbounded filesystem API; see
  [Security → Designing a safe device](docs/security.md#designing-a-safe-device).

## Contributing and support

Contribution rules and the full check list are in [CONTRIBUTING.md](CONTRIBUTING.md).
Bug reports and feature requests belong in
[GitHub Issues](https://github.com/ekravo/ekravo-airport/issues); suspected
vulnerabilities must follow [SECURITY.md](SECURITY.md) instead of a public issue.
Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT. See [LICENSE](LICENSE). The TypeScript SDK is MIT-licensed as well
([packages/sdk/LICENSE](packages/sdk/LICENSE)).
