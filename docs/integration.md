# Integrating Airport with Ekravo applications

> **Scope.** This guide describes how an Ekravo website or desktop application
> can adopt Airport. It is guidance, not a compatibility guarantee or a
> commitment to a particular product roadmap. The Airport repository is
> self-contained; the applications below are separate consumers.

## Relationship to existing clients

An Ekravo application may already contain a narrower local connector for one
specific job. That model is a useful reference and validates the Airport model:

| Existing connector | Airport equivalent |
| --- | --- |
| Per-device pairing code with a short TTL, single use | `airport_pair_…`, same semantics |
| Exchange for a long-lived device credential | `airport_dev_…`, hashed at rest; client stores it |
| One outbound WebSocket, no inbound port | Same |
| Versioned JSON frames with a size cap | Same framing, 1 MiB default frame cap |
| Server-authoritative protocol version | Same |
| Bearer secret on the upgrade request | Short-lived ticket on the upgrade URL, plus device bearer support |
| Work queue per device, one socket per device, `replaced` | Mailbox per device, one socket per device, `replaced` |
| Heartbeat and reconnect with jittered backoff | Heartbeat and jittered backoff in the SDK/client |
| No prompt/completion logging | Same policy, enforced for all payloads |

Airport generalizes the job tunnel into a relaying service for any event, adds
multi-account authorization (grants), durable at-least-once delivery, and
optional end-to-end encryption that the relay cannot read.

## Integration requirements

### Ekravo Desktop (device side)

1. **Embed a device client in the main process**, not the renderer. It needs the
   long-lived credential and a persistent outbound socket.
   - Rust: depend on `airport-protocol` and reuse the client logic from
     `crates/device-cli`, or spawn the reference binary.
   - TypeScript/Electron: use `@ekravo/airport-sdk` with a custom `WebSocket` if
     the runtime lacks one, and persist the identity with `onTokens` /
     `exportIdentity`.
2. **Store the credential in the OS credential store.** Keychain on macOS,
   libsecret on Linux, DPAPI/Credential Manager on Windows. The config file should
   contain only the server URL, device id, display name, and public key.
3. **Pairing flow.** The website shows a code; Desktop accepts it via a deep link
   (`ekravo://airport/pair?server=…&code=…`) or a paste field, then calls
   `POST /api/v1/devices/pair` with its X25519 public key. Never log the code.
4. **Event handlers are an allowlist.** Suggested first handlers:
   - `ping` → reply `pong` (health of the tunnel)
   - `app.focus` → bring the window forward
   - `workspace.open` → open a project the user has already approved
   - `chat.send` → route into the existing chat runtime
   No `exec`, no generic file read/write, no arbitrary URL fetch. Validate the
   payload again on the device.
5. **Respect revocation.** On a `revoked` frame, stop reconnecting, clear the
   credential, and show the user that the device was unpaired. On `replaced`,
   exit the tunnel loop rather than fighting the newer process.
6. **Presence is advisory.** Do not rely on `online` for correctness; it is a
   snapshot of the live registry.
7. **Ack before doing slow work**, then process, and copy the frame's `seq` into
   the ack. `seq` identifies this exact mailbox entry; acknowledging by `msgId`
   alone only clears the newest row because two senders may reuse an id.
   Otherwise an interrupted handler replays the message. Deduplicate by `msgId`
   for the lifetime of the process.
8. **Never trust the relay's payload shape.** Airport validates framing and size,
   not your application schema.

### Ekravo Website (client side)

1. **Configuration.** Add `AIRPORT_BASE_URL` (server origin) and an allowlist of
   event names the web app may send. Airport itself is origin-agnostic; CORS is
   controlled by `AIRPORT_TRUSTED_ORIGINS`.
2. **Ticket issuance.** The browser needs a short-lived ticket. Either:
   - call Airport directly from the browser with the user's Airport access token,
     or
   - proxy `POST /api/v1/tickets` server-side, mapping an Ekravo session to an
     Airport account.
   The second keeps Ekravo's existing session model and hides Airport from the
   user.
3. **Account mapping.** Decide whether an Ekravo user gets an Airport account
   automatically (provision on first use) or whether Ekravo itself authenticates
   to Airport with a service account and grants are managed by Ekravo. Airport
   deliberately has no notion of an Ekravo account; do not hardcode one.
4. **Device list UI.** Use `GET /api/v1/devices` for owned devices and
   `GET /api/v1/devices/shared` for devices shared with the user. Show `online`
   and `publicKey`.
5. **Sharing UI.** `POST /api/v1/grants` takes an email and event patterns.
   Default to the narrowest pattern that works (`chat.*`, not `*`). Revocation is
   `DELETE /api/v1/grants/{id}` and takes effect on the next message.
6. **No secret in the browser beyond the access token.** The refresh token may be
   kept in an httpOnly cookie if the website proxies auth; otherwise keep both in
   memory. Never put a device credential in a web page.
7. **Handle disconnect explicitly.** `recipient_unavailable` means the browser
   must queue or ask the user, not retry in a tight loop.
8. **E2EE requires the device's public key.** Use `encryptWith: device.publicKey`
   and let the device answer with `from.publicKey`. Persist the client identity
   if replies must survive a reload.

## Suggested migration path

1. **Stand up Airport** at a dedicated origin (for example
   `airport.example.com`), with `AIRPORT_PUBLIC_URL` set and TLS terminated at
   the proxy.
2. **Ship a Desktop build** that pairs and handles only `ping`. Verify presence,
   revocation, and reconnect in the field.
3. **Add one real feature** (for example “open this project on my computer”) with
   a narrow event and a narrow grant pattern.
4. **Move the local-model tunnel** only if the mailbox and presence semantics are
   a good fit. Keep the existing connector until then; nothing in Airport
   requires its removal.
5. **Add sharing** once single-account flows are stable.

## Compatibility notes

- Airport's protocol version is independent of the existing connector's. Both
  use `v: 1`, but frame types differ; do not point one client at the other's
  endpoint.
- Airport device ids are `dev_…`; an existing connector may use account-scoped
  ids. Map them, do not assume they are interchangeable.
- Airport's default payload limit is 256 KiB, lower than an 8 MiB frame cap.
  Large model outputs need chunking or a raised `AIRPORT_MAX_PAYLOAD_BYTES`.
- Airport does not implement friend codes. Sharing is an owner-created grant tied
  to an existing Airport account.
- Airport uses SQLite. A multi-instance Ekravo deployment would need the scaling
  work described in [Architecture → Scaling](architecture.md#scaling).

## Out of scope

Airport ships the relay, protocol, SDK, reference device client, and deployment
files. Changes to downstream applications, their DNS, their hosted
infrastructure, and any published image or service belong to their operators.
This document does not modify or make commitments for those systems.
