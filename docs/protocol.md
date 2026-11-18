# Protocol v1

Airport speaks **one JSON object per WebSocket text frame**. Every frame carries:

```json
{ "v": 1, "type": "…" }
```

- `v` is the protocol version. The server rejects any other value with a fatal
  `unsupported_version` frame and closes. There is no negotiation.
- `type` selects the frame. Unknown types are rejected, not ignored.

Binary frames are not supported. Base64 is used where bytes are needed.

Endpoint: `GET /v1/connect?ticket=<single-use ticket>`. The HTTP upgrade must
succeed within the ticket's 90-second lifetime.

Limits (defaults, configurable):

| Limit | Default | Enforced by |
| --- | --- | --- |
| Frame size | 1 MiB (configured); 8 MiB protocol ceiling | WebSocket layer and codec |
| Payload | 256 KiB | Protocol validation |
| Queue depth per socket | 256 frames | Server registry |
| Connections per account | 20 | Registry slot reservation at handshake |
| Inbound frames per second | 20 (burst 40); acks exempt | Token bucket |
| Offline mailbox | 500 messages, 24 h TTL | Store transaction |

## Client → server frames

### `hello`

Optional. `welcome` already establishes the session. `hello` advertises the
peer's long-term X25519 public key so the other side can encrypt replies.

```json
{
  "v": 1,
  "type": "hello",
  "clientVersion": "airport-sdk/0.1.0",
  "platform": "macos-arm64",
  "publicKey": "base64 32-byte X25519 public key"
}
```

`publicKey` is optional. Devices also register one at pairing; the server uses
the registered key unless the device sends `hello` with a new one.

### `msg`

```json
{
  "v": 1,
  "type": "msg",
  "msgId": "msg_5f0c…",
  "to": { "kind": "device", "id": "dev_…" },
  "event": "chat.send",
  "payload": "{\"text\":\"hello\"}",
  "contentType": "json",
  "replyTo": "msg_…",
  "ttlMs": 60000
}
```

An encrypted message sets `contentType` to `binary` (the payload is
ciphertext) and declares what the decrypted bytes mean in `enc.plainType`:

```json
{
  "v": 1,
  "type": "msg",
  "msgId": "msg_5f0c…",
  "to": { "kind": "device", "id": "dev_…" },
  "event": "chat.send",
  "payload": "base64 ciphertext",
  "contentType": "binary",
  "enc": {
    "alg": "x25519-hkdf-sha256-aes-256-gcm",
    "epk": "base64 ephemeral public key",
    "nonce": "base64 12-byte nonce",
    "plainType": "json"
  }
}
```

| Field | Required | Rules |
| --- | --- | --- |
| `msgId` | yes | 1–128 chars of `[A-Za-z0-9._:-]`; idempotency key per sender |
| `to.kind` | yes | `device`, `connection`, or `user` |
| `to.id` | yes | Same charset; device ids start with `dev_` |
| `event` | yes | Same charset, no `*` |
| `payload` | yes | Up to the payload limit |
| `contentType` | no | `json` (default), `text`, `binary` |
| `enc` | no | Encryption header; requires `contentType: binary` |
| `replyTo` | no | A previous `msgId` |
| `ttlMs` | no | 1–604 800 000; capped by the server's message TTL |

`contentType: json` requires `payload` to be valid JSON. `binary` requires valid
base64. When `enc` is present the payload is base64 ciphertext and the server
never interprets it.

### `ack`

Confirms receipt. A device must ack stored messages or they replay.

```json
{ "v": 1, "type": "ack", "msgId": "msg_5f0c…", "seq": 42 }
```

`seq` identifies one mailbox row exactly and should be copied from the delivered
frame. Two different senders may legitimately choose the same `msgId`, so an
acknowledgement without `seq` is applied only to the newest unacknowledged row
with that id. Include `seq` whenever the server supplied it.

### `ping`

```json
{ "v": 1, "type": "ping" }
```

Answered with `pong`. WebSocket-level pings are also used by the server; browsers
answer those automatically.

## Server → peer frames

### `welcome`

First frame after a successful upgrade.

```json
{
  "v": 1,
  "type": "welcome",
  "protocolVersion": 1,
  "connectionId": "conn_…",
  "userId": "usr_…",
  "deviceId": "dev_…",
  "role": "device",
  "serverTime": 1770000000,
  "limits": {
    "maxPayloadBytes": 262144,
    "maxQueueDepth": 256,
    "messagesPerSecond": 20,
    "heartbeatMs": 25000
  }
}
```

`deviceId` is present only for device connections. `connectionId` is the address
other peers use for `to.kind: "connection"`.

### `msg`

A delivered message.

```json
{
  "v": 1,
  "type": "msg",
  "deliveryId": "msg_…",
  "msgId": "msg_5f0c…",
  "seq": 42,
  "from": {
    "userId": "usr_…",
    "deviceId": "dev_…",
    "deviceName": "Laptop",
    "connectionId": "conn_…",
    "publicKey": "base64…"
  },
  "event": "chat.send",
  "payload": "…",
  "contentType": "json",
  "replyTo": "msg_…",
  "createdAt": 1770000000,
  "expiresAt": 1770086400
}
```

`from` is authoritative: Airport sets `userId`, `deviceId`, and `connectionId`
from the authenticated socket. `seq` is present for stored device mail and
replayed mail, absent for live-only messages.

### `ack`

Immediate receipt for a submitted `msg`, sent to its sender.

```json
{
  "v": 1,
  "type": "ack",
  "deliveryId": "msg_…",
  "msgId": "msg_5f0c…",
  "status": "delivered",
  "queued": false,
  "seq": 42,
  "at": 1770000000
}
```

| `status` | Meaning |
| --- | --- |
| `queued` | Stored for an offline device (or its socket queue is full) |
| `delivered` | Written to the device's live socket |
| `duplicate` | This sender already stored this `msgId`; nothing was sent again |

### `delivered`

Sent to the original sender when the recipient acknowledges a stored message.

```json
{ "v": 1, "type": "delivered", "deliveryId": "msg_…", "msgId": "msg_5f0c…", "at": 1770000060 }
```

### `presence`

Broadcast to the device owner's client connections when a device connects or
disconnects.

```json
{ "v": 1, "type": "presence", "deviceId": "dev_…", "status": "online", "at": 1770000000 }
```

Presence is sent only to the device owner's client connections. A grantee sees
the current `online` field from `GET /api/v1/devices/shared` and should treat it
as a snapshot, not a subscription.

### `error`

A recoverable or fatal problem. Errors caused by a specific message carry its
`msgId`.

```json
{
  "v": 1,
  "type": "error",
  "code": "forbidden",
  "message": "you do not have access to this device",
  "msgId": "msg_5f0c…",
  "fatal": false
}
```

| Code | Retry? | Meaning |
| --- | --- | --- |
| `unauthorized` | no | Ticket or token rejected before the socket opened |
| `forbidden` | no | Authenticated but not allowed (owner, grant, or event) |
| `invalid_frame` | no | Malformed JSON or schema violation |
| `unsupported_version` | no | Protocol version mismatch; fatal |
| `payload_too_large` | no | Reduce the payload |
| `rate_limited` | yes, later | Slow down; acks are never throttled |
| `recipient_unavailable` | maybe | The connection or device is not reachable |
| `mailbox_full` | yes, later | The device's offline queue is at its cap |
| `not_found` | no | Unknown resource |
| `conflict` | no | Duplicate account or grant |
| `internal` | maybe | Server failure; retry with backoff |

### `pong`

```json
{ "v": 1, "type": "pong", "at": 1770000000 }
```

### `revoked`

The device was revoked or its credential rotated. The server closes the socket
and the device must not reconnect with the old credential.

```json
{ "v": 1, "type": "revoked", "reason": "device was revoked" }
```

### `replaced`

Another socket took over this device. The older process must stop rather than
fight for the identity.

```json
{ "v": 1, "type": "replaced" }
```

## Authorization rules

| Sender | Target | Rule |
| --- | --- | --- |
| Owner client | own device | allowed |
| Other account | device | active grant, and the event must match an allowed pattern |
| Any client | connection | same account |
| Device | connection | own account, or a grantee of this device |
| Client | user | only its own user id |
| Device | user | only its owner's user id |
| Any | itself | allowed (useful for tests) |

Grant patterns are `*`, an exact event (`chat.send`), or a prefix ending in `*`
(`fs.*`). The device owner is never constrained by patterns.

## Delivery guarantees

- **Device targets** are stored before delivery. The server sends up to
  `replay_batch` unacknowledged, unexpired rows on reconnect in sequence order,
  then sends the next row as each acknowledgement arrives. A large backlog
  therefore drains without waiting for another reconnect. Expect duplicates
  after a network blip: deduplicate by `(from.userId, from.deviceId, msgId)`,
  which matches the server's per-sender idempotency key. Two senders may reuse
  an id, and they are distinct messages.
- **Acknowledging** a mailbox row requires its `seq`. Without it the server acks
  only the newest row with the supplied `msgId`, because two senders are allowed
  to reuse an id.
- **Connection and user targets** are live fan-out. If no socket is reachable,
  the sender gets `recipient_unavailable`; nothing is queued.
- **Idempotency:** `(authenticated sender, msgId)` is unique. Reusing an id
  returns `duplicate` with the original `seq`.
- **Expiry:** messages older than the TTL are not replayed. Acknowledged
  messages are retained for the configured retention window for idempotency, then
  pruned.

## End-to-end encryption

See [Security → End-to-end encryption](security.md#end-to-end-encryption). The
server validates `alg`, `epk` (32 bytes), `nonce` (12 bytes), and that the
ciphertext is long enough to contain a 16-byte tag. It forwards everything else
unchanged.
