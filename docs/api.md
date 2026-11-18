# HTTP API

Base path: `/api/v1`. All bodies are JSON. Every failure — including a malformed
body, an unknown route, and a wrong method — uses:

```json
{ "error": { "code": "forbidden", "message": "you do not have access to this device" } }
```

API responses carry `Cache-Control: no-store`, because they can contain tokens
or account details. A `429` also carries `Retry-After: 60`. A request that does
not finish within 30 seconds is cancelled with `408 request_timeout`; a body
larger than `AIRPORT_MAX_FRAME_BYTES` is refused with `413 payload_too_large`.
Both use the same error envelope.

Authentication is `Authorization: Bearer <access token>` unless noted. Device
credentials use the same header and are accepted only where stated. Timestamps in
responses are RFC 3339 UTC strings; internal storage uses Unix seconds.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/healthz` | none | Liveness |
| GET | `/readyz` | none | Database readiness |
| GET | `/version` | none | Server and protocol version |
| POST | `/auth/register` | none | Create an account |
| POST | `/auth/login` | none | Sign in |
| POST | `/auth/refresh` | none | Rotate a refresh token |
| POST | `/auth/logout` | none | Revoke a refresh token |
| GET | `/me` | user | Current account and device count |
| POST | `/devices/pairing` | user | Create a one-time pairing code |
| POST | `/devices/pair` | code | Exchange a code for a device credential |
| GET | `/devices` | user | List owned devices |
| GET | `/devices/shared` | user | Devices shared with this account |
| DELETE | `/devices/{id}` | user | Revoke a device |
| POST | `/devices/{id}/rotate` | user | Replace a device credential |
| GET | `/grants` | user | Grants owned and received |
| POST | `/grants` | user | Share a device with another account |
| DELETE | `/grants/{id}` | owner/grantee | Revoke a grant |
| POST | `/tickets` | user or device | Mint a WebSocket ticket |
| GET | `/v1/connect?ticket=…` | ticket | WebSocket upgrade (outside `/api`) |

## Health

`GET /healthz` → `200`

```json
{ "status": "ok", "version": "0.1.0", "uptimeSeconds": 42, "connections": 3 }
```

`GET /readyz` → `200` when SQLite answers, `503` otherwise.

```json
{ "status": "ready", "checks": { "database": "ok" } }
```

`GET /version` → `200`

```json
{ "name": "ekravo-airport", "version": "0.1.0", "protocolVersion": 1 }
```

Readiness is deliberately separate from liveness: a failing database should drain
traffic, not restart the process.

## Accounts

### `POST /auth/register`

```json
{ "email": "you@example.com", "password": "at least 10 characters", "displayName": "You" }
```

`201`:

```json
{
  "user": { "id": "usr_…", "email": "you@example.com", "displayName": "You", "createdAt": "2026-01-01T00:00:00Z" },
  "accessToken": "eyJ…",
  "refreshToken": "…",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

- `400` invalid email/password.
- `403` registration closed (the first account is always allowed).
- `409` email already registered.
- `429` too many attempts from this IP.

### `POST /auth/login`

Same request minus `displayName`; same response. `401` for a wrong password or
unknown account, with identical work performed for both. `403` when the account
is disabled, and `429` after too many attempts from one IP.

### `POST /auth/refresh`

```json
{ "refreshToken": "…" }
```

Returns a new access token and a **new** refresh token. The old token is revoked.
Reusing an already-rotated token revokes the whole family and returns `401`.

### `POST /auth/logout`

```json
{ "refreshToken": "…" }
```

`204`, idempotent.

### `GET /me`

```json
{ "user": { "id": "usr_…", "email": "…", "displayName": "…", "createdAt": "…" }, "devices": 2 }
```

## Devices

### `POST /devices/pairing`

```json
{ "name": "Laptop", "platform": "macos-arm64" }
```

`201`:

```json
{ "code": "airport_pair_…", "expiresAt": "2026-01-01T00:10:00Z" }
```

The code is single-use, valid for ten minutes, and only its hash is stored. `403`
when the device cap is reached, `429` when this account requests codes too
quickly.

### `POST /devices/pair`

No bearer token; the pairing code is the authorization.

```json
{
  "code": "airport_pair_…",
  "name": "Laptop",
  "platform": "macos-arm64",
  "publicKey": "base64 32-byte X25519 public key"
}
```

`201`:

```json
{
  "device": {
    "id": "dev_…", "name": "Laptop", "platform": "macos-arm64",
    "publicKey": "…", "online": false, "createdAt": "…", "lastSeenAt": null
  },
  "credential": "airport_dev_…"
}
```

The credential is shown **once**. `400` for an invalid, used, or expired code;
`403` when the account has reached its device cap; `429` for repeated attempts
from one IP.

### `GET /devices`

```json
{ "devices": [ { "id": "dev_…", "name": "Laptop", "platform": "…", "publicKey": "…", "online": true, "createdAt": "…", "lastSeenAt": "…" } ] }
```

`online` reflects the live registry at request time.

### `GET /devices/shared`

Devices another account has shared with this one, including the grant id and the
allowed event patterns:

```json
{ "devices": [ { "id": "dev_…", "name": "Workstation", "online": true, "ownerName": "Alex", "grantId": "grant_…", "allowedEvents": ["chat.*"] } ] }
```

### `DELETE /devices/{id}`

`204`. Closes the live socket (the device first receives `revoked`), invalidates
the credential, revokes every share of the device, and removes it from future
listings and from grantees' shared-device lists. `404` if it does not belong to
this account.

### `POST /devices/{id}/rotate`

Replaces the credential and disconnects the device so it must re-authenticate.

```json
{ "device": { "id": "dev_…", "…": "…" }, "credential": "airport_dev_…" }
```

## Grants

### `POST /grants`

```json
{
  "deviceId": "dev_…",
  "granteeEmail": "friend@example.com",
  "label": "chat only",
  "allowedEvents": ["chat.*"]
}
```

`201`:

```json
{
  "id": "grant_…", "deviceId": "dev_…", "deviceName": "Workstation",
  "granteeEmail": "friend@example.com", "label": "chat only",
  "allowedEvents": ["chat.*"], "createdAt": "…"
}
```

- `400` invalid email or pattern, or granting to yourself.
- `404` unknown device (or not yours), or unknown grantee.
- `409` an active grant already exists for this pair.
- `429` too many grant requests from this account in the last minute.

Patterns: `*`, an exact event, or a prefix ending in `*`.

### `GET /grants`

```json
{ "owned": [ … ], "received": [ … ] }
```

Owned grants include `granteeEmail`; received grants do not include the owner's
email, only the device name and label.

### `DELETE /grants/{id}`

`204`. Either the owner or the grantee may revoke. A stranger gets `404`.

## Tickets

### `POST /tickets`

```json
{ "kind": "client" }
```

- A user access token may request `client` tickets.
- A device credential may request `device` tickets (and `client` tickets).

`201`:

```json
{
  "ticket": "…",
  "kind": "client",
  "expiresAt": "2026-01-01T00:01:30Z",
  "path": "/v1/connect?ticket=…",
  "url": "wss://airport.example.com/v1/connect?ticket=…"
}
```

`url` is absolute only when `AIRPORT_PUBLIC_URL` is configured. Tickets are
single-use and expire after 90 seconds (default). The ticket is a URL parameter,
which is safe precisely because it is short-lived and single-use; the device
credential never is. `429` is returned when the account mints tickets faster
than `AIRPORT_AUTH_ATTEMPTS_PER_MINUTE`.

The account's connection cap is enforced again when the socket is established,
not only when a ticket is minted: a burst of tickets cannot exceed the limit. A
refused upgrade completes the WebSocket handshake and then sends a fatal
`rate_limited` frame before closing.

When `AIRPORT_TRUSTED_ORIGINS` is configured, a browser `Origin` header on the
upgrade must match one of the listed origins. The check runs before the ticket is
consumed, and clients that send no `Origin` (native apps, servers) are allowed.

## Rate limits

- `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, and
  `/devices/pair`: per client IP, minute window
  (`AIRPORT_AUTH_ATTEMPTS_PER_MINUTE`).
- `POST /devices/pairing`, `POST /grants`, and `POST /tickets`: per account,
  minute window. Grant creation accepts an email address, so throttling it
  prevents the endpoint from becoming an address-enumeration oracle; ticket
  throttling keeps a caller from filling the database with unused credentials.
- `/tickets` and the WebSocket handshake: per account connection cap, in addition
  to the ticket rate limit.
- WebSocket messages: per connection token bucket; exceeding it returns
  `rate_limited` without closing the socket.
