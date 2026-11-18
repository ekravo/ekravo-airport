# Architecture

## Goals

1. A device never accepts inbound connections. It dials out, so NAT, CGNAT, and
   corporate firewalls are not a problem and no address is published.
2. Airport decides **who may reach which endpoint**, but does not need to
   understand application messages. It can be run by someone who is not Ekravo.
3. A message to an offline device is not lost. Reconnect is the normal case, not
   an exception.
4. The security-sensitive surface stays small and legible: one HTTP API, one
   WebSocket endpoint, one SQLite schema.

## Components

```
                     ┌──────────────────────────────────────────┐
  website / SDK ────▶│  HTTP API            /api/v1/*           │
                     │  auth · pairing · devices · grants ·     │
                     │  tickets                                 │
                     ├──────────────────────────────────────────┤
  desktop app  ─────▶│  WebSocket relay     /v1/connect         │
                     │  authenticate ticket · registry · route  │
                     │  mailbox · presence · heartbeat          │
                     ├──────────────────────────────────────────┤
                     │  SQLite              users, devices,     │
                     │  grants, mailboxes, tickets, refresh     │
                     └──────────────────────────────────────────┘
```

### `crates/protocol`

Pure types with no I/O:

- `FrameHeader` and version checks.
- Inbound frames: `hello`, `msg`, `ack`, `ping`.
- Outbound frames: `welcome`, `msg`, `ack`, `delivered`, `presence`, `error`,
  `pong`, `revoked`, `replaced`.
- Validation: ids, event names, payload ceilings, encryption header shape.
- `ErrorCode`, the stable set of machine-readable failures.

The server and the device client both depend on it, so a frame cannot drift
between them without a compile error.

### `crates/server`

| Module | Responsibility |
| --- | --- |
| `config` | Read and validate the environment; refuse unsafe combinations |
| `db` | Open SQLite with WAL/foreign keys; apply the idempotent schema |
| `store` | Every query, including the mailbox transaction |
| `auth` | Argon2id, opaque secrets, JWT signing and verification |
| `extract` | `AuthUser` (JWT) and `Actor` (JWT or device credential) |
| `registry` | Live socket index: one socket per device, fan-out, takeover |
| `ratelimit` | Per-connection token bucket, per-IP minute windows |
| `routes` | HTTP endpoints and the WebSocket handler |
| `routes::ws` | The relay: routing, acknowledgements, replay, presence |

`main` wires those together, chooses TLS, and starts a retention task.

### `crates/device-cli`

The reference device. It pairs with the server, stores a local identity and
credential, requests tickets, connects, acknowledges, and answers messages with
`echo.reply`. It is deliberately not a general remote-execution agent.

### `packages/sdk`

The browser/Node client. It performs the same HTTP flow, opens a WebSocket with a
ticket, reconnects, deduplicates, and exposes request/response helpers. Its
cryptography matches the Rust implementation byte for byte.

## Identity and credentials

| Secret | Entropy | Storage | Lifetime |
| --- | --- | --- | --- |
| Password | user-chosen | Argon2id hash | until changed |
| Access token | HS256 JWT | client memory | 15 minutes (default) |
| Refresh token | 32 random bytes | SHA-256 hash in SQLite | 30 days, rotated on use |
| Pairing code | 24 random bytes | SHA-256 hash in SQLite | 10 minutes, single use |
| Connection ticket | 32 random bytes | SHA-256 hash in SQLite | 90 seconds, single use |
| Device credential | 32 random bytes | SHA-256 hash + prefix index | until rotated/revoked |

A connection ticket exists because browsers cannot set headers on a WebSocket
handshake. The long-lived device credential is never placed in a URL. The device
client stores it in a 0600 config file; a production desktop client should keep it
in the OS credential store (see `docs/integration.md`).

## Message flow

### Website → device

1. The SDK calls `POST /api/v1/tickets` with its access token and receives a
   single-use ticket.
2. It opens `wss://…/v1/connect?ticket=…`. The server consumes the ticket,
   registers the connection, and sends `welcome`.
3. The client sends `msg` with `to: { kind: "device", id }`, an `event`, and a
   payload.
4. Airport checks ownership or an active grant, including the event pattern.
5. The message is written to `messages` inside a transaction that also reserves a
   per-device sequence number and enforces the mailbox cap.
6. If the device is online, the frame is queued on its socket and the row is
   marked `delivered_at`. Otherwise it stays queued.
7. The sender receives an `ack` receipt: `queued`, `delivered`, or `duplicate`.
8. The device processes the message and sends `ack`. The row is marked `acked_at`
   and the original sender receives `delivered` if still connected.

### Device → website

Devices reply to the `from.connectionId` included in the delivered frame. That is
a live connection, so the message is best-effort: if the browser is gone, the
device gets `recipient_unavailable` and can decide what to do.

A device can also send to another device (same owner or a grant), or broadcast to
its owner's client connections with `to: { kind: "user", id }`.

## Delivery semantics

- **Devices: at-least-once.** A stored message is replayed until the device
  acknowledges it or it expires. Devices and SDKs deduplicate by the tuple
  `(sender user, sender device, msgId)`, matching `(sender, msgId)` idempotency
  on the server. Deduplicating by `msgId` alone would drop a second sender's
  message.
- **Connections and users: at-most-once.** These targets are live sockets; a
  failed send returns an error rather than queueing.
- **Idempotency.** `(sender, msgId)` is unique. Re-sending the same id returns a
  `duplicate` receipt and does not deliver again. Senders are identified by their
  authenticated account or device; a peer cannot forge another sender's key.
- **Acknowledgement scope.** Devices ack a mailbox row by its per-device `seq`.
  That matters because two senders may reuse a `msgId`; acknowledging by id alone
  would clear both rows and lose one message.
- **Backlog draining.** A reconnect sends one `replay_batch`; each ack releases
  the next pending row. A 500-message mailbox therefore drains on one connection
  instead of waiting for a reconnect per batch.

## Persistence

```
users ──< devices ──< device_counters
  │           │
  │           └──< messages  (mailbox + idempotency)
  ├──< refresh_tokens
  ├──< pairing_codes
  └──< grants >── users (grantee)
tickets (short-lived, independent)
```

- Timestamps are Unix seconds, stored as integers.
- `messages` has a partial index on unacknowledged rows per device, so replay is
  a range scan by `seq`.
- The mailbox transaction is serialized by SQLite. Two senders cannot obtain the
  same sequence, and the duplicate check and insert are atomic.
- A retention task deletes messages older than `AIRPORT_RETENTION_SECS`, plus
  expired pairing codes, tickets, and refresh tokens. Deleting old acked messages
  also bounds how long a `msgId` is remembered.
- `PRAGMA user_version` records the schema revision. A binary refuses to open a
  database written by a newer revision, rather than silently misreading it.

## Reconnect and takeover

- A device has exactly one live socket. A second connection for the same device
  receives a `replaced` frame and the older socket is closed. Its `unregister`
  cannot remove the newer device index.
- Per-account connection slots are reserved atomically before the socket is
  registered and released by a drop guard, so the cap holds under a burst of
  ticket requests and is not leaked by early returns.
- A reconnect replays every unacknowledged, unexpired message in `seq` order,
  up to `AIRPORT_REPLAY_BATCH`.
- Presence `online` is broadcast when the device socket registers; `offline` only
  when no newer socket owns the device.
- Heartbeats are WebSocket pings every `AIRPORT_HEARTBEAT_INTERVAL_SECS`; three
  silent intervals close the socket.

## Scaling

The current release is a **single-node** relay:

- Live sockets are in process memory; SQLite is local.
- Running two instances behind a load balancer would split the registry, and a
  message could be routed to an instance that does not own the device socket.

A multi-node deployment needs a shared connection directory (for example Redis or
NATS) and a routing hop between instances, or sticky assignment of each device to
an instance. The protocol does not change: the ticket and mailbox model already
separates identity from transport. This is intentionally left out of 0.1.0 rather
than half-implemented.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Device socket drops | Device reconnects with backoff; unacked mail replays |
| Client socket drops | Client reconnects with a new ticket; in-flight requests reject |
| Server restarts | All sockets close; devices reconnect and receive unacked mail |
| Database unavailable | `/readyz` fails; API returns 500; sockets that are already open can still exchange live messages until they touch the database |
| Mailbox full | Sender gets `mailbox_full`; nothing is silently dropped |
| Device revoked | Live socket receives `revoked`, then closes; credential stops authenticating |
| Credential rotated | Same as revocation; the device must use the new credential |
| Duplicate submission | `duplicate` receipt with the original sequence, no second delivery |
