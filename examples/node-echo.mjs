// End-to-end example: sign in, pick a paired device, send an echo request, and
// print the answer. Run the reference device client (`airport-device run`)
// before this script.
//
//   AIRPORT_URL=http://127.0.0.1:8787 \
//   AIRPORT_EMAIL=you@example.com \
//   AIRPORT_PASSWORD='your password' \
//   node examples/node-echo.mjs
//
// Build the SDK first: (cd packages/sdk && npm install && npm run build)

import { AirportClient } from "../packages/sdk/dist/index.js";

const baseUrl = process.env.AIRPORT_URL ?? "http://127.0.0.1:8787";
const email = process.env.AIRPORT_EMAIL;
const password = process.env.AIRPORT_PASSWORD;

if (!email || !password) {
  console.error("Set AIRPORT_EMAIL and AIRPORT_PASSWORD.");
  process.exit(1);
}

const airport = new AirportClient({ baseUrl });
await airport.login(email, password);

const devices = await airport.listDevices();
if (devices.length === 0) {
  console.error("No paired devices. Run `airport-device pair --code …` first.");
  process.exit(1);
}
const device = devices.find((candidate) => candidate.online) ?? devices[0];
console.log(
  `Using ${device.name} (${device.id}), ${device.online ? "online" : "offline; the message will queue"}`,
);

const connection = airport.connect();
await connection.ready;
console.log(`Connected as ${connection.currentState}.`);

const reply = await connection.request({
  to: { kind: "device", id: device.id },
  event: "echo",
  data: { text: "hello from the browser SDK" },
  encryptWith: device.publicKey, // omit to send plaintext
  timeoutMs: 20_000,
});

console.log("Reply:", reply.data, reply.encrypted ? "(encrypted)" : "(plaintext)");
connection.close();
await airport.logout();
