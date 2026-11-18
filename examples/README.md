# Examples

## Prerequisites

```bash
cp .env.example .env
# Put a real secret in .env:
#   openssl rand -base64 48
cargo run -p airport-server
```

In another terminal:

```bash
# 1. Create an account and a pairing code through the API.
curl -s http://127.0.0.1:8787/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct horse battery","displayName":"You"}'

TOKEN=… # accessToken from the response
CODE=$(curl -s http://127.0.0.1:8787/api/v1/devices/pairing \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"Laptop"}' | jq -r .code)

# 2. Pair the reference device client and run it.
cargo run -p airport-device -- pair --code "$CODE" --name "Laptop"
cargo run -p airport-device -- run
```

## Node example

```bash
(cd packages/sdk && npm install && npm run build)

AIRPORT_EMAIL=you@example.com \
AIRPORT_PASSWORD='correct horse battery' \
node examples/node-echo.mjs
```

The device client answers every message with `echo.reply`, echoing the payload
back to the connection that sent it. When the incoming message advertises a
public key, the reply is end-to-end encrypted.

## Browser

The SDK is a plain ES module with no bundler requirement. After
`npm run build` in `packages/sdk`, serve this repository (for example
`python -m http.server`) and import:

```html
<script type="module">
  import { AirportClient } from "/packages/sdk/dist/index.js";
  // Same flow as the Node example. Browsers cannot pair a device (pairing needs
  // the credential to be stored securely), but they create pairing codes and
  // talk to already-paired devices.
</script>
```
