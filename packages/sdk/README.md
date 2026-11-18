# @ekravo/airport-sdk

Browser and Node client for [Ekravo Airport](../../README.md). Zero runtime
requirements beyond `fetch` and `WebSocket`; cryptography uses the audited
`@noble/*` primitives so browser and Rust implementations interoperate.

Node 22 and later provide a global `WebSocket`. On Node 20 or 21, pass an
implementation with the `WebSocket` option when constructing `AirportClient`
(`connect()` is the only part that needs it).

```bash
npm install @ekravo/airport-sdk
```

```ts
import { AirportClient } from "@ekravo/airport-sdk";

const airport = new AirportClient({ baseUrl: "https://airport.example.com" });
await airport.login("you@example.com", "your password");

const devices = await airport.listDevices();
const device = devices[0];

const connection = airport.connect();
await connection.ready;

const reply = await connection.request({
  to: { kind: "device", id: device.id },
  event: "chat.send",
  data: { text: "hello" },
  encryptWith: device.publicKey, // optional end-to-end encryption
  timeoutMs: 15_000,
});
console.log(reply.data);
connection.close();
```

## Delivery semantics

- Messages to devices are persisted and delivered **at least once**. Airport
  deduplicates by `msgId` per sender, and the SDK deduplicates by the same
  `(sender, msgId)` key for the session. Deduplicating by `msgId` alone would
  drop a message from a second sender that reused the id.
- Messages to connections and users are best-effort.
- `connection.request()` resolves when a reply with `replyTo === msgId` arrives.
- Acknowledgments include the server's `seq`, which identifies one mailbox row.
  Two senders may legitimately reuse a `msgId`; `seq` keeps their acknowledgments
  separate.
- `autoAck` defaults to `true`. Set it to `false` when the application needs to
  acknowledge only after persisting or completing work. Duplicate suppression is
  per session and bounded, so durable deduplication belongs in the application.

## Encryption

`encryptWith` expects the peer's 32-byte X25519 public key (base64). Devices
receive theirs when pairing (`publicKey` on the device). Clients advertise theirs
in `hello`, and Airport includes it in `from.publicKey`, so a device can encrypt
its reply.

The identity is generated per `AirportClient` and kept in memory. Persist it
yourself with `exportIdentity()` / `identityFromSecret()` if replies must survive
a page reload. Server-side Airport only sees ciphertext, an ephemeral public key,
and a nonce.

A fixed vector shared with the Rust client is asserted in both test suites, so
byte-for-byte interoperability is tested rather than assumed.

## Deadlines and reconnection

Every HTTP request has a 30-second deadline by default, including reading the
response body (`requestTimeoutMs` overrides it). `connect()` waits at most 15
seconds for the WebSocket handshake and first `welcome` (`connectTimeoutMs`),
then reconnects with jittered exponential backoff and requests a fresh
single-use ticket each time. Concurrent 401 responses share one refresh-token
rotation, so two requests cannot revoke the token family by racing. Listen for
`state`, `close`, `message`, `ack`, `delivered`, `presence`, and `error`. Call
`close()` to stop.
