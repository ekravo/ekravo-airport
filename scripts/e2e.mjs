#!/usr/bin/env node
/**
 * Checked-in end-to-end proof for Ekravo Airport.
 *
 * Usage:
 *   node scripts/e2e.mjs
 *
 * Requirements: Rust 1.89+, Node 22+ (for `node:sqlite`), npm, and OpenSSL.
 *
 * The parent process builds the shipped release binaries and the TypeScript
 * SDK, generates an ephemeral CA and server certificate, then re-executes this
 * file with `NODE_EXTRA_CA_CERTS` set before Node starts. The runner exercises
 * the real server and two real `airport-device` processes in plaintext and
 * TLS/WSS modes and exits non-zero on any failed assertion.
 *
 * Synchronisation rules:
 *   - No fixed settle delays. Every wait is on an observable condition:
 *     a presence frame, an ack/delivered frame, `/api/v1/devices` state, a
 *     process exit, `/healthz`, or a read-only SQLite state query.
 *   - The only timer here is the poll interval inside `waitFor`, plus bounded
 *     failure timeouts. A timeout is a test failure, never a retry.
 *   - Barriers (a normal message the device echoes) order each batch so a
 *     duplicate or late delivery cannot hide behind timing.
 *
 * The queue/replay window is driven repeatedly: each cycle sends a message and
 * kills the device immediately, waits for the server's offline presence, sends
 * a second message while the device is definitely offline and requires a
 * `queued` receipt, restarts the device, then sends a barrier. Both messages
 * must have exactly one stored row with `acked_at` set, one delivered receipt,
 * and no duplicate application replies.
 *
 * Two observables need a note:
 *   - A message sent while the device is closing can legitimately be delivered
 *     to the dying socket and replayed after reconnect. Its echo reply may be
 *     lost if the process died after acking; the proof therefore requires its
 *     durable ack and delivery, and permits zero or one reply. The offline
 *     message (sent after the offline presence) always requires a reply.
 *   - A message queued across a full server restart has no live sender
 *     connection to receive the device's reply. Its row in the preserved
 *     SQLite database is the observable: exactly one row, `acked_at` set after
 *     the device reconnects. This is a read-only state query, not a log check.
 *
 * Environment:
 *   E2E_MODES=plaintext,tls   transports to run (default: both)
 *   E2E_CYCLES=8              disconnect/send interleavings per transport
 *   E2E_KEEP=1                keep the temporary work directory on exit
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SDK_DIR = path.join(ROOT, "packages", "sdk");
const IS_RUNNER = process.argv.includes("--run");
const POLL_MS = 25;
const WAIT_MS = 30_000;
const PROCESS_WAIT_MS = 15_000;
const LOG_LIMIT = 40_000;

const log = (message) => console.log(`[e2e] ${message}`);
const warn = (message) => console.error(`[e2e] ${message}`);

// ---------------------------------------------------------------------------
// Parent: build, certificates, re-exec
// ---------------------------------------------------------------------------

async function orchestrate() {
  const keep = process.env.E2E_KEEP === "1";
  const modes = parseModes(process.env.E2E_MODES);
  const cycles = parseCycles(process.env.E2E_CYCLES);
  const work = fs.mkdtempSync(path.join(ROOT, ".e2e-"));
  let status = 1;

  try {
    log(`workspace: ${ROOT}`);
    log(`work directory: ${work}`);
    buildEverything(work);
    const tls = makeCertificates(path.join(work, "tls"));

    const child = spawnSync(
      process.execPath,
      ["--experimental-sqlite", fileURLToPath(import.meta.url), "--run"],
      {
        cwd: ROOT,
        env: {
          ...process.env,
          NODE_EXTRA_CA_CERTS: tls.ca,
          E2E_ROOT: work,
          E2E_CA: tls.ca,
          E2E_TLS_CERT: tls.cert,
          E2E_TLS_KEY: tls.key,
          E2E_MODES: modes.join(","),
          E2E_CYCLES: String(cycles),
        },
        stdio: "inherit",
        windowsHide: true,
      },
    );
    if (child.error) throw child.error;
    status = child.status ?? 1;
  } catch (error) {
    warn(error instanceof Error ? error.stack ?? error.message : String(error));
    status = 1;
  } finally {
    if (keep) {
      log(`kept work directory: ${work}`);
    } else {
      fs.rmSync(work, { recursive: true, force: true });
    }
  }
  process.exit(status);
}

function parseModes(raw) {
  const modes = (raw ?? "plaintext,tls")
    .split(",")
    .map((mode) => mode.trim())
    .filter(Boolean);
  if (modes.length === 0) throw new Error("E2E_MODES is empty");
  for (const mode of modes) {
    if (mode !== "plaintext" && mode !== "tls") {
      throw new Error(`unknown E2E mode ${JSON.stringify(mode)}; use plaintext or tls`);
    }
  }
  return [...new Set(modes)];
}

function parseCycles(raw) {
  if (raw === undefined || raw === "") return 8;
  const cycles = Number.parseInt(raw, 10);
  if (!Number.isInteger(cycles) || cycles < 1 || cycles > 100) {
    throw new Error("E2E_CYCLES must be an integer from 1 to 100");
  }
  return cycles;
}

function npmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? ROOT,
    env: { ...process.env, ...(options.env ?? {}) },
    stdio: "inherit",
    // Node's direct spawn of a `.cmd` shim is rejected on Windows; the shell
    // form is the supported invocation for npm there.
    shell: process.platform === "win32" && /\.[cC][mM][dD]$/.test(command),
    windowsHide: true,
  });
  if (result.error) {
    throw new Error(`could not run ${command}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }
}

function buildEverything(work) {
  const tempEnv = {
    TMP: work,
    TEMP: work,
    npm_config_cache: path.join(work, "npm-cache"),
  };
  log("building release binaries (cargo build --release --locked --workspace)");
  runCommand("cargo", ["build", "--release", "--locked", "--workspace"], {
    env: tempEnv,
  });
  log("installing and building the TypeScript SDK");
  runCommand(npmCommand(), ["ci", "--no-audit", "--no-fund"], {
    cwd: SDK_DIR,
    env: tempEnv,
  });
  runCommand(npmCommand(), ["run", "build"], {
    cwd: SDK_DIR,
    env: tempEnv,
  });
}

function openssl(args) {
  const result = spawnSync("openssl", args, { encoding: "utf8", windowsHide: true });
  if (result.error) {
    throw new Error(
      `OpenSSL is required to run the TLS/WSS end-to-end mode: ${result.error.message}`,
    );
  }
  if (result.status !== 0) {
    throw new Error(`openssl ${args.join(" ")} failed:\n${result.stderr ?? ""}`);
  }
}

function makeCertificates(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const caKey = path.join(directory, "ca.key");
  const caCert = path.join(directory, "ca.pem");
  const serverKey = path.join(directory, "server.key");
  const serverCsr = path.join(directory, "server.csr");
  const serverCert = path.join(directory, "server.pem");
  const fullchain = path.join(directory, "server-fullchain.pem");
  const extensions = path.join(directory, "server.ext");

  openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-sha256",
    "-days",
    "2",
    "-nodes",
    "-keyout",
    caKey,
    "-out",
    caCert,
    "-subj",
    "/CN=Airport E2E CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  openssl([
    "req",
    "-newkey",
    "rsa:2048",
    "-sha256",
    "-nodes",
    "-keyout",
    serverKey,
    "-out",
    serverCsr,
    "-subj",
    "/CN=127.0.0.1",
  ]);
  fs.writeFileSync(
    extensions,
    "subjectAltName=IP:127.0.0.1,DNS:localhost\n" +
      "extendedKeyUsage=serverAuth\n" +
      "keyUsage=digitalSignature,keyEncipherment\n",
  );
  openssl([
    "x509",
    "-req",
    "-in",
    serverCsr,
    "-CA",
    caCert,
    "-CAkey",
    caKey,
    "-CAcreateserial",
    "-out",
    serverCert,
    "-days",
    "2",
    "-sha256",
    "-extfile",
    extensions,
  ]);
  fs.writeFileSync(
    fullchain,
    `${fs.readFileSync(serverCert, "utf8")}${fs.readFileSync(caCert, "utf8")}`,
  );
  if (process.platform !== "win32") {
    fs.chmodSync(caKey, 0o600);
    fs.chmodSync(serverKey, 0o600);
  }
  return { ca: caCert, cert: fullchain, key: serverKey };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function runHarness() {
  const { DatabaseSync } = await import("node:sqlite");
  const sdk = await import(pathToFileURL(path.join(SDK_DIR, "dist", "index.js")).href);
  const { AirportClient } = sdk;

  const root = requiredEnv("E2E_ROOT");
  const modes = parseModes(process.env.E2E_MODES);
  const cycles = parseCycles(process.env.E2E_CYCLES);
  const ca = requiredEnv("E2E_CA");
  const tlsCert = requiredEnv("E2E_TLS_CERT");
  const tlsKey = requiredEnv("E2E_TLS_KEY");

  for (const mode of modes) {
    const scenario = new Scenario({
      root,
      mode,
      cycles,
      ca,
      tlsCert,
      tlsKey,
      AirportClient,
      DatabaseSync,
    });
    try {
      await scenario.run();
    } catch (error) {
      scenario.dumpLogs();
      throw error;
    } finally {
      await scenario.cleanup();
    }
  }
  log(`PASS: ${modes.join(" + ")} modes, ${cycles} disconnect races each`);
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is missing; invoke the harness through node scripts/e2e.mjs`);
  return value;
}

// Poll cadence, not a settle delay: `waitFor` re-evaluates an observable
// predicate after each tick and fails at the bounded deadline.
const pollInterval = () => new Promise((resolve) => setTimeout(resolve, POLL_MS));

async function waitFor(description, predicate, timeoutMs = WAIT_MS) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      const value = await predicate();
      if (value) return value;
    } catch (error) {
      if (error && error.fatal) throw error;
      lastError = error;
    }
    await pollInterval();
  }
  const detail = lastError instanceof Error ? ` (last error: ${lastError.message})` : "";
  throw new Error(`timed out after ${timeoutMs}ms waiting for ${description}${detail}`);
}

function newId(prefix = "msg") {
  return `${prefix}_${crypto.randomBytes(9).toString("hex")}`;
}

function tail(text, limit = LOG_LIMIT) {
  if (text.length <= limit) return text;
  return `… ${text.length - limit} bytes omitted …\n${text.slice(-limit)}`;
}

function assertIdentity(reply, ownerUser, device, label) {
  assert.equal(reply.from.userId, ownerUser.id, `${label}: authenticated sender userId`);
  assert.equal(reply.from.deviceId, device.id, `${label}: authenticated sender deviceId`);
  assert.equal(reply.from.connectionId.length > 0, true, `${label}: reply has a return connection`);
}

function assertBytes(actual, expected, label) {
  assert.equal(actual instanceof Uint8Array, true, `${label}: expected bytes`);
  assert.equal(Buffer.from(actual).equals(Buffer.from(expected)), true, `${label}: payload bytes`);
}

class Scenario {
  constructor({ root, mode, cycles, ca, tlsCert, tlsKey, AirportClient, DatabaseSync }) {
    this.root = root;
    this.mode = mode;
    this.cycles = cycles;
    this.ca = ca;
    this.tlsCert = tlsCert;
    this.tlsKey = tlsKey;
    this.AirportClient = AirportClient;
    this.DatabaseSync = DatabaseSync;
    this.tls = mode === "tls";

    const suffix = `${mode}-${crypto.randomBytes(4).toString("hex")}`;
    this.work = path.join(root, "runs", suffix);
    this.dbDir = path.join(this.work, "server");
    this.dbPath = path.join(this.dbDir, "airport.db");
    this.deviceDir = path.join(this.work, "devices");
    this.runId = suffix;
    this.binDir = path.join(ROOT, "target", "release");
    this.serverBin = path.join(
      this.binDir,
      process.platform === "win32" ? "airport.exe" : "airport",
    );
    this.deviceBin = path.join(
      this.binDir,
      process.platform === "win32" ? "airport-device.exe" : "airport-device",
    );

    this.secret = crypto.randomBytes(32).toString("hex");
    this.logs = [];
    this.processes = new Set();
    this.connections = [];
    this.rawConnections = [];
    this.server = null;
    this.owner = null;
    this.guest = null;
    this.ownerUser = null;
    this.guestUser = null;
    this.laptop = null;
    this.desktop = null;
    this.port = null;
    this.base = null;
  }

  async run() {
    fs.mkdirSync(this.work, { recursive: true });
    fs.mkdirSync(this.deviceDir, { recursive: true });
    this.port = await freePort();
    this.base = `${this.tls ? "https" : "http"}://127.0.0.1:${this.port}`;
    log(`${this.mode}: starting at ${this.base}`);

    await this.startServer(true);
    await this.registerAccounts();
    await this.pairDevices();
    await this.startDevice(this.laptop);
    await this.startDevice(this.desktop);
    log(`${this.mode}: two paired devices online`);

    await this.rawPhase();
    await this.e2eePhase();
    await this.grantPhase();
    await this.offlinePhase();
    await this.stressPhase();
    await this.restartPhase();
    await this.revocationPhase();

    console.log(
      `PASS [${this.mode}]: raw + SDK text/binary, grants, ${this.cycles} disconnect races, ` +
        "restart replay, revocation",
    );
  }

  async cleanup() {
    for (const raw of this.rawConnections) {
      try {
        raw.ws.close(1000, "test finished");
      } catch {
        // already closed
      }
    }
    for (const { conn } of this.connections) {
      try {
        conn.close();
      } catch {
        // already closed
      }
    }
    for (const proc of [...this.processes]) {
      await this.killProcess(proc, { quiet: true });
    }
    this.processes.clear();
    this.server = null;
  }

  dumpLogs() {
    for (const proc of this.processes) {
      const text = proc.logText ?? "";
      console.error(`\n--- ${proc.name} log (diagnostic only) ---\n${tail(text)}`);
    }
  }

  // -- server ---------------------------------------------------------------

  async startServer(fresh) {
    if (fresh) {
      fs.rmSync(this.dbDir, { recursive: true, force: true });
    }
    fs.mkdirSync(this.dbDir, { recursive: true });

    const env = {
      ...process.env,
      AIRPORT_BIND_ADDR: `127.0.0.1:${this.port}`,
      AIRPORT_DATABASE_URL: "sqlite://airport.db",
      AIRPORT_JWT_SECRET: this.secret,
      AIRPORT_ALLOW_REGISTRATION: "true",
      AIRPORT_AUTH_ATTEMPTS_PER_MINUTE: "1000",
      AIRPORT_LOG_FORMAT: "text",
      RUST_LOG: "airport_server=info,tower_http=warn",
      ...(this.tls
        ? {
            AIRPORT_TLS_CERT: this.tlsCert,
            AIRPORT_TLS_KEY: this.tlsKey,
            AIRPORT_PUBLIC_URL: this.base,
          }
        : {}),
    };
    const proc = this.spawnProcess("server", this.serverBin, [], this.dbDir, env);
    this.server = proc;
    await waitFor(`/healthz on ${this.base}`, async () => {
      if (proc.exitInfo) {
        throw new Error(`server exited during startup: ${JSON.stringify(proc.exitInfo)}`);
      }
      try {
        const response = await fetch(`${this.base}/healthz`, {
          signal: AbortSignal.timeout(2_000),
        });
        return response.ok;
      } catch {
        return false;
      }
    });
    log(`${this.mode}: server healthy`);
  }

  async stopServer() {
    if (!this.server) return;
    const proc = this.server;
    this.server = null;
    await this.killProcess(proc);
  }

  async restartServer() {
    await this.stopServer();
    await this.startServer(false);
  }

  // -- accounts and devices -------------------------------------------------

  async registerAccounts() {
    const password = `e2e-${crypto.randomBytes(12).toString("hex")}`;
    this.owner = new this.AirportClient({ baseUrl: this.base });
    this.guest = new this.AirportClient({ baseUrl: this.base });
    this.ownerEmail = `e2e-${this.runId}-owner@example.test`;
    this.guestEmail = `e2e-${this.runId}-guest@example.test`;

    const owner = await this.owner.register(this.ownerEmail, password, "E2E Owner");
    this.ownerUser = owner.user;
    const guest = await this.guest.register(this.guestEmail, password, "E2E Guest");
    this.guestUser = guest.user;
    assert.notEqual(this.ownerUser.id, this.guestUser.id, "two distinct accounts");
    const me = await this.owner.me();
    assert.equal(me.user.id, this.ownerUser.id, "owner /me identity");
  }

  async pairDevices() {
    this.laptop = await this.pairDevice("E2E Laptop");
    this.desktop = await this.pairDevice("E2E Desktop");
  }

  async pairDevice(name) {
    const pairing = await this.owner.createPairingCode(name, "e2e");
    const configPath = path.join(this.deviceDir, `${name.replaceAll(" ", "-")}.json`);
    const args = [
      "pair",
      "--server",
      this.base,
      "--code",
      pairing.code,
      "--name",
      name,
      "--platform",
      "e2e",
    ];
    if (this.tls) args.push("--ca-cert", this.ca);

    const result = spawnSync(this.deviceBin, args, {
      cwd: this.work,
      env: { ...process.env, AIRPORT_DEVICE_CONFIG: configPath },
      encoding: "utf8",
      windowsHide: true,
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(
        `pairing ${name} failed (${result.status}):\n${result.stdout ?? ""}${result.stderr ?? ""}`,
      );
    }
    assert.equal(fs.existsSync(configPath), true, `${name}: pairing wrote a config`);
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    assert.equal(config.server, this.base, `${name}: config points at the test server`);
    assert.equal(config.device_name, name, `${name}: config device name`);

    const devices = await this.owner.listDevices();
    const device = devices.find((candidate) => candidate.id === config.device_id);
    assert.ok(device, `${name}: device appears in /devices`);
    assert.equal(device.name, name, `${name}: server device name`);
    assert.equal(device.online, false, `${name}: paired device starts offline`);
    assert.equal(device.publicKey, config.public_key, `${name}: pairing key is stored`);

    return {
      name,
      id: device.id,
      publicKey: config.public_key,
      configPath,
      config,
      proc: null,
    };
  }

  async startDevice(device) {
    if (device.proc && !device.proc.exitInfo) return;
    const env = {
      AIRPORT_DEVICE_CONFIG: device.configPath,
      ...(this.tls ? { AIRPORT_CA_CERT: this.ca } : {}),
    };
    const proc = this.spawnProcess(device.name, this.deviceBin, ["run"], this.work, env);
    device.proc = proc;
    await waitFor(`${device.name} process online`, async () => {
      if (proc.exitInfo) {
        throw new Error(`${device.name} exited during startup: ${JSON.stringify(proc.exitInfo)}`);
      }
      const current = await this.findDevice(device.id);
      return current?.online === true;
    });
  }

  async stopDevice(device) {
    if (!device.proc) return;
    const proc = device.proc;
    device.proc = null;
    await this.killProcess(proc);
  }

  async findDevice(id) {
    const devices = await this.owner.listDevices();
    return devices.find((device) => device.id === id);
  }

  async waitDeviceState(id, online) {
    return waitFor(`device ${id} ${online ? "online" : "offline"} in /devices`, async () => {
      const device = await this.findDevice(id);
      return device?.online === online ? device : undefined;
    });
  }

  async waitSharedState(id, online) {
    return waitFor(
      `shared device ${id} ${online ? "online" : "offline"} in /devices/shared`,
      async () => {
        const devices = await this.guest.listSharedDevices();
        const device = devices.find((candidate) => candidate.id === id);
        return device?.online === online ? device : undefined;
      },
    );
  }

  // -- SDK connections ------------------------------------------------------

  async openSdk(client, label) {
    const conn = client.connect({ autoReconnect: false });
    const events = {
      opens: [],
      messages: [],
      acks: [],
      delivered: [],
      presence: [],
      errors: [],
      closes: [],
    };
    conn.on("open", (frame) => events.opens.push(frame));
    conn.on("message", (message) => events.messages.push(message));
    conn.on("ack", (ack) => events.acks.push(ack));
    conn.on("delivered", (delivered) => events.delivered.push(delivered));
    conn.on("presence", (presence) => events.presence.push(presence));
    conn.on("error", (error) => events.errors.push(error));
    conn.on("close", (close) => events.closes.push(close));
    const record = { conn, events, label };
    this.connections.push(record);
    try {
      await conn.ready;
    } catch (error) {
      throw new Error(`${label}: SDK connection failed: ${error.message}`);
    }
    return record;
  }

  closeSdk(record) {
    try {
      record.conn.close();
    } catch {
      // already closed
    }
  }

  assertOpen(record) {
    if (record.conn.currentState !== "open") {
      throw new Error(
        `${record.label}: connection is ${record.conn.currentState}, expected open (no silent reconnect)`,
      );
    }
  }

  sdkSend(record, device, event, data, options = {}) {
    this.assertOpen(record);
    return record.conn.send({
      to: { kind: "device", id: device.id },
      event,
      data,
      ...options,
    });
  }

  async waitSdkReply(record, msgId) {
    return waitFor(`${record.label}: reply to ${msgId}`, () =>
      record.events.messages.find((message) => message.replyTo === msgId),
    );
  }

  async waitSdkAck(record, msgId, statuses) {
    return waitFor(`${record.label}: ${statuses.join("/")} ack for ${msgId}`, () =>
      record.events.acks.find(
        (ack) => ack.msgId === msgId && statuses.includes(ack.status),
      ),
    );
  }

  async waitSdkDelivered(record, msgId) {
    return waitFor(`${record.label}: delivered receipt for ${msgId}`, () =>
      record.events.delivered.find((frame) => frame.msgId === msgId),
    );
  }

  async sdkBarrier(record, device) {
    const id = this.sdkSend(record, device, "e2e.barrier", "barrier");
    const reply = await this.waitSdkReply(record, id);
    const ack = await this.waitSdkAck(record, id, ["delivered"]);
    const delivered = await this.waitSdkDelivered(record, id);
    return { id, reply, ack, delivered };
  }

  async guestBarrier(record, device, data = "barrier") {
    const id = this.sdkSend(record, device, "chat.send", data);
    const reply = await this.waitSdkReply(record, id);
    const ack = await this.waitSdkAck(record, id, ["delivered"]);
    const delivered = await this.waitSdkDelivered(record, id);
    return { id, reply, ack, delivered };
  }

  // -- raw WebSocket --------------------------------------------------------

  async openRaw(label) {
    const ticket = await this.owner.createTicket("client");
    const url = ticket.url ?? `${this.base.replace(/^http/, "ws")}${ticket.path}`;
    const ws = new WebSocket(url);
    const raw = { ws, label, frames: [], closed: false, error: null };
    ws.addEventListener("message", (event) => {
      try {
        raw.frames.push(JSON.parse(event.data));
      } catch (error) {
        raw.error = `non-JSON frame: ${error.message}`;
      }
    });
    ws.addEventListener("error", (event) => {
      raw.error = `WebSocket error: ${event.message ?? "unknown"}`;
    });
    ws.addEventListener("close", () => {
      raw.closed = true;
    });
    this.rawConnections.push(raw);
    await waitFor(`${label}: welcome`, () => raw.frames.find((frame) => frame.type === "welcome"));
    return raw;
  }

  rawSend(raw, device, event, payload, contentType, extra = {}) {
    if (raw.ws.readyState !== 1) throw new Error(`${raw.label}: WebSocket is not open`);
    raw.ws.send(
      JSON.stringify({
        v: 1,
        type: "msg",
        to: { kind: "device", id: device.id },
        event,
        payload,
        contentType,
        ...extra,
      }),
    );
  }

  async waitRaw(raw, description, predicate) {
    return waitFor(`${raw.label}: ${description}`, () => raw.frames.find(predicate));
  }

  async rawBarrier(raw, device) {
    const id = newId("barrier");
    this.rawSend(raw, device, "e2e.barrier", "barrier", "text", { msgId: id });
    const reply = await this.waitRaw(
      raw,
      `barrier reply ${id}`,
      (frame) => frame.type === "msg" && frame.replyTo === id,
    );
    const ack = await this.waitRaw(
      raw,
      `barrier ack ${id}`,
      (frame) => frame.type === "ack" && frame.msgId === id && frame.status === "delivered",
    );
    const delivered = await this.waitRaw(
      raw,
      `barrier delivered ${id}`,
      (frame) => frame.type === "delivered" && frame.msgId === id,
    );
    return { id, reply, ack, delivered };
  }

  assertRawDelivery(raw, device, id, options = {}) {
    const replies = raw.frames.filter((frame) => frame.type === "msg" && frame.replyTo === id);
    const delivered = raw.frames.filter(
      (frame) => frame.type === "delivered" && frame.msgId === id,
    );
    const acks = raw.frames.filter((frame) => frame.type === "ack" && frame.msgId === id);

    const expectedReplies = options.replies ?? 1;
    if (Array.isArray(expectedReplies)) {
      assert.equal(
        expectedReplies.includes(replies.length),
        true,
        `${raw.label} ${id}: reply count ${replies.length} not in ${expectedReplies.join("/")}`,
      );
    } else {
      assert.equal(replies.length, expectedReplies, `${raw.label} ${id}: exactly one reply`);
    }
    if (replies.length > 0) {
      const reply = replies[0];
      assertIdentity(reply, this.ownerUser, device, `${raw.label} ${id}`);
      assert.equal(Boolean(reply.enc), false, `${raw.label} ${id}: raw path is plaintext`);
      if (options.payload !== undefined) {
        assert.equal(reply.payload, options.payload, `${raw.label} ${id}: reply payload`);
      }
      if (options.bytes !== undefined) {
        assert.equal(
          Buffer.from(reply.payload, "base64").equals(Buffer.from(options.bytes)),
          true,
          `${raw.label} ${id}: reply bytes`,
        );
      }
    }
    assert.equal(delivered.length, 1, `${raw.label} ${id}: exactly one delivered receipt`);
    const expectedAcks = options.ackStatuses ?? ["delivered"];
    assert.equal(
      acks.length,
      expectedAcks.length,
      `${raw.label} ${id}: expected ${expectedAcks.length} ack(s), got ${acks.length}`,
    );
    for (const status of expectedAcks) {
      assert.equal(
        acks.some((ack) => ack.status === status),
        true,
        `${raw.label} ${id}: missing ${status} ack`,
      );
    }
  }

  // -- SQLite state ---------------------------------------------------------

  queryMessage(msgId, deviceId) {
    const db = new this.DatabaseSync(this.dbPath, { readOnly: true });
    try {
      return db
        .prepare(
          "SELECT COUNT(*) AS n, " +
            "SUM(CASE WHEN acked_at IS NOT NULL THEN 1 ELSE 0 END) AS acked, " +
            "SUM(CASE WHEN enc IS NOT NULL THEN 1 ELSE 0 END) AS encrypted " +
            "FROM messages WHERE target_device_id = ? AND msg_id = ?",
        )
        .get(deviceId, msgId);
    } finally {
      db.close();
    }
  }

  async waitAcked(msgId, deviceId) {
    return waitFor(`SQLite row for ${msgId} to be acked`, () => {
      const row = this.queryMessage(msgId, deviceId);
      if (row.n > 1) {
        const error = new Error(
          `${msgId}: ${row.n} rows for one sender/msgId (duplicate storage)`,
        );
        error.fatal = true;
        throw error;
      }
      return row.n === 1 && Number(row.acked) === 1 ? row : undefined;
    });
  }

  assertStored(msgId, deviceId, { acked, encrypted }) {
    const row = this.queryMessage(msgId, deviceId);
    assert.equal(row.n, 1, `${msgId}: exactly one stored mailbox row`);
    if (acked !== undefined) {
      assert.equal(Number(row.acked), acked ? 1 : 0, `${msgId}: acked_at state`);
    }
    if (encrypted !== undefined) {
      assert.equal(
        Number(row.encrypted ?? 0),
        encrypted ? 1 : 0,
        `${msgId}: encryption header state`,
      );
    }
  }

  assertNotStored(msgId, deviceId) {
    const row = this.queryMessage(msgId, deviceId);
    assert.equal(row.n, 0, `${msgId}: rejected message must not be stored`);
  }

  // -- phases ---------------------------------------------------------------

  async rawPhase() {
    const raw = await this.openRaw("raw");
    const device = this.laptop;

    const textId = newId();
    this.rawSend(raw, device, "chat.send", "raw text payload", "text", { msgId: textId });
    await this.waitRaw(
      raw,
      `text reply ${textId}`,
      (frame) => frame.type === "msg" && frame.replyTo === textId,
    );
    await this.waitRaw(
      raw,
      `text ack ${textId}`,
      (frame) => frame.type === "ack" && frame.msgId === textId && frame.status === "delivered",
    );
    await this.waitRaw(
      raw,
      `text delivered ${textId}`,
      (frame) => frame.type === "delivered" && frame.msgId === textId,
    );

    const bytes = Uint8Array.from([0, 1, 2, 3, 250, 251, 252, 253]);
    const binaryId = newId();
    this.rawSend(raw, device, "chat.send", Buffer.from(bytes).toString("base64"), "binary", {
      msgId: binaryId,
    });
    await this.waitRaw(
      raw,
      `binary reply ${binaryId}`,
      (frame) => frame.type === "msg" && frame.replyTo === binaryId,
    );
    await this.waitRaw(
      raw,
      `binary ack ${binaryId}`,
      (frame) => frame.type === "ack" && frame.msgId === binaryId && frame.status === "delivered",
    );
    await this.waitRaw(
      raw,
      `binary delivered ${binaryId}`,
      (frame) => frame.type === "delivered" && frame.msgId === binaryId,
    );

    const forgedId = newId();
    this.rawSend(raw, device, "chat.send", "forged identity test", "text", {
      msgId: forgedId,
      from: {
        userId: "user_forged",
        deviceId: "device_forged",
        connectionId: "connection_forged",
        publicKey: this.guest.publicKey,
      },
    });
    await this.waitRaw(
      raw,
      `forged reply ${forgedId}`,
      (frame) => frame.type === "msg" && frame.replyTo === forgedId,
    );
    await this.waitRaw(
      raw,
      `forged ack ${forgedId}`,
      (frame) => frame.type === "ack" && frame.msgId === forgedId && frame.status === "delivered",
    );
    await this.waitRaw(
      raw,
      `forged delivered ${forgedId}`,
      (frame) => frame.type === "delivered" && frame.msgId === forgedId,
    );

    const duplicateId = newId();
    this.rawSend(raw, device, "chat.send", "duplicate once", "text", { msgId: duplicateId });
    await this.waitRaw(
      raw,
      `first duplicate reply ${duplicateId}`,
      (frame) => frame.type === "msg" && frame.replyTo === duplicateId,
    );
    await this.waitRaw(
      raw,
      `first duplicate ack ${duplicateId}`,
      (frame) =>
        frame.type === "ack" && frame.msgId === duplicateId && frame.status === "delivered",
    );
    await this.waitRaw(
      raw,
      `first duplicate delivered ${duplicateId}`,
      (frame) => frame.type === "delivered" && frame.msgId === duplicateId,
    );
    this.rawSend(raw, device, "chat.send", "duplicate twice", "text", { msgId: duplicateId });
    await this.waitRaw(
      raw,
      `duplicate ack ${duplicateId}`,
      (frame) => frame.type === "ack" && frame.msgId === duplicateId && frame.status === "duplicate",
    );

    const barrier = await this.rawBarrier(raw, device);
    assert.equal(barrier.reply.replyTo, barrier.id, "raw barrier ordering");
    assertIdentity(barrier.reply, this.ownerUser, device, "raw barrier");
    assert.equal(barrier.delivered.msgId, barrier.id, "raw barrier delivered");

    this.assertRawDelivery(raw, device, textId, { payload: "raw text payload" });
    this.assertRawDelivery(raw, device, binaryId, { bytes });
    this.assertRawDelivery(raw, device, forgedId, { payload: "forged identity test" });
    this.assertRawDelivery(raw, device, duplicateId, {
      payload: "duplicate once",
      ackStatuses: ["delivered", "duplicate"],
    });
    for (const id of [textId, binaryId, forgedId, duplicateId, barrier.id]) {
      await this.waitAcked(id, device.id);
    }
    assert.equal(raw.error, null, "raw socket reported no protocol errors");

    raw.ws.close(1000, "raw phase complete");
    await waitFor("raw socket close", () => raw.closed);
    console.log(`PASS [${this.mode}]: raw WebSocket text/binary, duplicate and forged identity`);
  }

  async e2eePhase() {
    const record = await this.openSdk(this.owner, "sdk-owner");
    const device = this.laptop;

    const textId = this.sdkSend(record, device, "chat.send", "sdk text");
    const jsonId = this.sdkSend(record, device, "chat.send", { hello: "world", n: 7 });
    const bytes = Uint8Array.from([9, 8, 7, 0, 255, 128]);
    const binaryId = this.sdkSend(record, device, "chat.send", bytes);
    const sealedId = this.sdkSend(record, device, "chat.send", "sealed payload", {
      encryptWith: device.publicKey,
    });

    const textReply = await this.waitSdkReply(record, textId);
    assert.equal(textReply.data, "sdk text", "sdk text payload");
    assert.equal(textReply.encrypted, true, "device replies are encrypted to the SDK identity");
    await this.waitSdkAck(record, textId, ["delivered"]);
    await this.waitSdkDelivered(record, textId);

    const jsonReply = await this.waitSdkReply(record, jsonId);
    assert.deepEqual(jsonReply.data, { hello: "world", n: 7 }, "sdk JSON payload");
    await this.waitSdkAck(record, jsonId, ["delivered"]);
    await this.waitSdkDelivered(record, jsonId);

    const binaryReply = await this.waitSdkReply(record, binaryId);
    assertBytes(binaryReply.data, bytes, "sdk binary payload");
    await this.waitSdkAck(record, binaryId, ["delivered"]);
    await this.waitSdkDelivered(record, binaryId);

    const sealedReply = await this.waitSdkReply(record, sealedId);
    assert.equal(sealedReply.data, "sealed payload", "sender-sealed payload");
    assert.equal(sealedReply.encrypted, true, "sender-sealed reply is encrypted");
    await this.waitSdkAck(record, sealedId, ["delivered"]);
    await this.waitSdkDelivered(record, sealedId);

    const duplicateId = newId();
    this.sdkSend(record, device, "chat.send", "sdk duplicate once", { msgId: duplicateId });
    await this.waitSdkReply(record, duplicateId);
    await this.waitSdkAck(record, duplicateId, ["delivered"]);
    await this.waitSdkDelivered(record, duplicateId);
    this.sdkSend(record, device, "chat.send", "sdk duplicate twice", { msgId: duplicateId });
    await this.waitSdkAck(record, duplicateId, ["duplicate"]);

    const barrier = await this.sdkBarrier(record, device);

    for (const [label, id, data] of [
      ["sdk text", textId, "sdk text"],
      ["sdk json", jsonId, { hello: "world", n: 7 }],
    ]) {
      this.assertSdkDelivery(record, device, id, { label, data, encrypted: true });
    }
    this.assertSdkDelivery(record, device, binaryId, {
      label: "sdk binary",
      bytes,
      encrypted: true,
    });
    this.assertSdkDelivery(record, device, sealedId, {
      label: "sdk sealed",
      data: "sealed payload",
      encrypted: true,
    });
    this.assertSdkDelivery(record, device, duplicateId, {
      label: "sdk duplicate",
      data: "sdk duplicate once",
      encrypted: true,
      ackStatuses: ["delivered", "duplicate"],
    });
    this.assertSdkDelivery(record, device, barrier.id, {
      label: "sdk barrier",
      data: "barrier",
      encrypted: true,
    });

    for (const id of [textId, jsonId, binaryId, sealedId, duplicateId, barrier.id]) {
      await this.waitAcked(id, device.id);
    }
    this.assertStored(textId, device.id, { acked: true, encrypted: false });
    this.assertStored(sealedId, device.id, { acked: true, encrypted: true });

    this.closeSdk(record);
    console.log(`PASS [${this.mode}]: SDK text/JSON/binary, E2EE reply, duplicate rejection`);
  }

  assertSdkDelivery(record, device, id, options) {
    const label = options.label ?? record.label;
    const replies = record.events.messages.filter((message) => message.replyTo === id);
    const delivered = record.events.delivered.filter((frame) => frame.msgId === id);
    const acks = record.events.acks.filter((ack) => ack.msgId === id);

    const expectedReplies = options.replies ?? 1;
    if (Array.isArray(expectedReplies)) {
      assert.equal(
        expectedReplies.includes(replies.length),
        true,
        `${label} ${id}: reply count ${replies.length} not in ${expectedReplies.join("/")}`,
      );
    } else {
      assert.equal(replies.length, expectedReplies, `${label} ${id}: exactly one reply`);
    }
    if (replies.length > 0) {
      const reply = replies[0];
      assertIdentity(reply, this.ownerUser, device, `${label} ${id}`);
      if (options.encrypted !== undefined) {
        assert.equal(reply.encrypted, options.encrypted, `${label} ${id}: encryption`);
      }
      if (options.data !== undefined) {
        assert.deepEqual(reply.data, options.data, `${label} ${id}: payload`);
      }
      if (options.bytes !== undefined) {
        assertBytes(reply.data, options.bytes, `${label} ${id}`);
      }
    }
    assert.equal(delivered.length, 1, `${label} ${id}: exactly one delivered receipt`);
    if (options.ackOneOf) {
      assert.equal(acks.length, 1, `${label} ${id}: exactly one ack`);
      assert.equal(
        options.ackOneOf.includes(acks[0].status),
        true,
        `${label} ${id}: ack status ${acks[0].status} not in ${options.ackOneOf.join("/")}`,
      );
      return;
    }
    const expectedAcks = options.ackStatuses ?? ["delivered"];
    assert.equal(
      acks.length,
      expectedAcks.length,
      `${label} ${id}: expected ${expectedAcks.length} ack(s), got ${acks.length}`,
    );
    for (const status of expectedAcks) {
      assert.equal(
        acks.some((ack) => ack.status === status),
        true,
        `${label} ${id}: missing ${status} ack`,
      );
    }
  }

  async grantPhase() {
    const grant = await this.owner.createGrant({
      deviceId: this.laptop.id,
      granteeEmail: this.guestEmail,
      label: "e2e",
      allowedEvents: ["chat.*"],
    });
    assert.equal(grant.deviceId, this.laptop.id, "grant device");
    assert.deepEqual(grant.allowedEvents, ["chat.*"], "grant event patterns");

    const shared = await this.guest.listSharedDevices();
    const sharedDevice = shared.find((device) => device.id === this.laptop.id);
    assert.ok(sharedDevice, "grantee sees the shared device");
    assert.equal(sharedDevice.grantId, grant.id, "grantee sees the grant");
    assert.equal(sharedDevice.publicKey, this.laptop.publicKey, "shared device public key");

    const record = await this.openSdk(this.guest, "sdk-guest");
    this.guestRecord = record;

    const allowedId = this.sdkSend(record, this.laptop, "chat.send", "granted event", {
      encryptWith: sharedDevice.publicKey,
    });
    const allowedReply = await this.waitSdkReply(record, allowedId);
    assert.equal(allowedReply.data, "granted event", "granted reply payload");
    assert.equal(allowedReply.encrypted, true, "granted reply is encrypted");
    assertIdentity(allowedReply, this.ownerUser, this.laptop, "granted event");
    await this.waitSdkAck(record, allowedId, ["delivered"]);
    await this.waitSdkDelivered(record, allowedId);

    const deniedId = newId();
    this.sdkSend(record, this.laptop, "shell.exec", "not allowed", { msgId: deniedId });
    const denied = await waitFor("forbidden error", () =>
      record.events.errors.find((error) => error.msgId === deniedId),
    );
    assert.equal(denied.code, "forbidden", "forbidden operation is rejected");

    const barrier = await this.guestBarrier(record, this.laptop);
    this.assertSdkDelivery(record, this.laptop, allowedId, {
      label: "granted",
      data: "granted event",
      encrypted: true,
    });
    this.assertSdkDelivery(record, this.laptop, barrier.id, {
      label: "grant barrier",
      data: "barrier",
      encrypted: true,
    });
    assert.equal(
      record.events.messages.some((message) => message.replyTo === deniedId),
      false,
      "forbidden message was not delivered to the device",
    );
    assert.equal(
      record.events.delivered.some((frame) => frame.msgId === deniedId),
      false,
      "forbidden message has no delivered receipt",
    );
    this.assertNotStored(deniedId, this.laptop.id);
    await this.waitAcked(allowedId, this.laptop.id);
    await this.waitAcked(barrier.id, this.laptop.id);

    console.log(`PASS [${this.mode}]: shared mailbox grant + forbidden operation`);
  }

  async offlinePhase() {
    const record = this.guestRecord;
    this.assertOpen(record);
    const device = this.laptop;

    await this.waitSharedState(device.id, true);
    await this.stopDevice(device);
    await this.waitSharedState(device.id, false);

    const offlineId = this.sdkSend(record, device, "chat.send", "offline queued", {
      encryptWith: device.publicKey,
    });
    const ack = await this.waitSdkAck(record, offlineId, ["queued"]);
    assert.equal(ack.status, "queued", "offline send must be queued, never delivered to a dead socket");
    this.assertStored(offlineId, device.id, { acked: false });

    await this.startDevice(device);
    await this.waitSharedState(device.id, true);

    const barrier = await this.guestBarrier(record, device);
    await this.waitSdkReply(record, offlineId);
    await this.waitSdkDelivered(record, offlineId);
    this.assertSdkDelivery(record, device, offlineId, {
      label: "offline queue",
      data: "offline queued",
      encrypted: true,
      ackStatuses: ["queued"],
    });
    this.assertSdkDelivery(record, device, barrier.id, {
      label: "offline barrier",
      data: "barrier",
      encrypted: true,
    });
    await this.waitAcked(offlineId, device.id);
    await this.waitAcked(barrier.id, device.id);

    this.closeSdk(record);
    console.log(`PASS [${this.mode}]: offline queue -> presence online -> replay`);
  }

  async stressPhase() {
    const record = await this.openSdk(this.owner, "sdk-cycles");
    const device = this.laptop;

    for (let cycle = 1; cycle <= this.cycles; cycle += 1) {
      await this.waitDeviceState(device.id, true);
      this.assertOpen(record);

      const raceId = this.sdkSend(record, device, "chat.send", `race ${cycle}`);
      const offlinePresence = record.events.presence.length;
      await this.stopDevice(device);

      await waitFor(`cycle ${cycle}: offline presence`, () =>
        record.events.presence
          .slice(offlinePresence)
          .find((presence) => presence.deviceId === device.id && presence.status === "offline"),
      );
      await this.waitDeviceState(device.id, false);

      const queuedId = this.sdkSend(record, device, "chat.send", `queued ${cycle}`);
      const queuedAck = await this.waitSdkAck(record, queuedId, ["queued"]);
      assert.equal(queuedAck.status, "queued", `cycle ${cycle}: offlined send is queued`);

      const onlinePresence = record.events.presence.length;
      await this.startDevice(device);
      await waitFor(`cycle ${cycle}: online presence`, () =>
        record.events.presence
          .slice(onlinePresence)
          .find((presence) => presence.deviceId === device.id && presence.status === "online"),
      );
      await this.waitDeviceState(device.id, true);

      const barrier = await this.sdkBarrier(record, device);
      await this.waitSdkAck(record, raceId, ["delivered", "queued"]);
      await this.waitSdkDelivered(record, raceId);
      await this.waitSdkReply(record, queuedId);
      await this.waitSdkDelivered(record, queuedId);

      this.assertSdkDelivery(record, device, raceId, {
        label: `cycle ${cycle} race`,
        replies: [0, 1],
        ackOneOf: ["delivered", "queued"],
      });
      this.assertSdkDelivery(record, device, queuedId, {
        label: `cycle ${cycle} queued`,
        data: `queued ${cycle}`,
        encrypted: true,
        ackStatuses: ["queued"],
      });
      this.assertSdkDelivery(record, device, barrier.id, {
        label: `cycle ${cycle} barrier`,
        data: "barrier",
        encrypted: true,
      });

      await this.waitAcked(raceId, device.id);
      await this.waitAcked(queuedId, device.id);
      await this.waitAcked(barrier.id, device.id);
      this.assertStored(raceId, device.id, { acked: true });
      this.assertStored(queuedId, device.id, { acked: true });
    }

    this.closeSdk(record);
    console.log(`PASS [${this.mode}]: ${this.cycles} send/kill/queue/reconnect races`);
  }

  async restartPhase() {
    this.closeSdk(this.guestRecord);
    await this.stopDevice(this.desktop);
    await this.waitDeviceState(this.desktop.id, false);

    const queueRecord = await this.openSdk(this.owner, "sdk-restart-queue");
    const queuedId = this.sdkSend(queueRecord, this.desktop, "chat.send", "queued across restart", {
      encryptWith: this.desktop.publicKey,
    });
    const ack = await this.waitSdkAck(queueRecord, queuedId, ["queued"]);
    assert.equal(ack.status, "queued", "message queued for the stopped device");
    this.assertStored(queuedId, this.desktop.id, { acked: false });

    const laptopAlive = this.laptop.proc;
    assert.ok(laptopAlive && !laptopAlive.exitInfo, "laptop stays running across the restart");
    await this.restartServer();
    assert.equal(laptopAlive.exitInfo, undefined, "laptop process survives the server restart");

    await this.waitDeviceState(this.laptop.id, true);
    await this.startDevice(this.desktop);
    await this.waitDeviceState(this.desktop.id, true);

    await this.waitAcked(queuedId, this.desktop.id);
    this.assertStored(queuedId, this.desktop.id, { acked: true });

    const after = await this.openSdk(this.owner, "sdk-after-restart");
    const toDesktop = this.sdkSend(after, this.desktop, "chat.send", "after restart desktop");
    const desktopReply = await this.waitSdkReply(after, toDesktop);
    assert.equal(desktopReply.data, "after restart desktop", "desktop relays after restart");
    assertIdentity(desktopReply, this.ownerUser, this.desktop, "after restart desktop");
    await this.waitSdkAck(after, toDesktop, ["delivered"]);
    await this.waitSdkDelivered(after, toDesktop);

    const toLaptop = this.sdkSend(after, this.laptop, "chat.send", "after restart laptop");
    const laptopReply = await this.waitSdkReply(after, toLaptop);
    assert.equal(laptopReply.data, "after restart laptop", "laptop relays after restart");
    assertIdentity(laptopReply, this.ownerUser, this.laptop, "after restart laptop");
    await this.waitSdkAck(after, toLaptop, ["delivered"]);
    await this.waitSdkDelivered(after, toLaptop);

    const barrier = await this.sdkBarrier(after, this.laptop);
    this.assertSdkDelivery(after, this.desktop, toDesktop, {
      label: "restart desktop",
      data: "after restart desktop",
      encrypted: true,
    });
    this.assertSdkDelivery(after, this.laptop, toLaptop, {
      label: "restart laptop",
      data: "after restart laptop",
      encrypted: true,
    });
    this.assertSdkDelivery(after, this.laptop, barrier.id, {
      label: "restart barrier",
      data: "barrier",
      encrypted: true,
    });
    await this.waitAcked(toDesktop, this.desktop.id);
    await this.waitAcked(toLaptop, this.laptop.id);
    await this.waitAcked(barrier.id, this.laptop.id);

    const me = await this.owner.me();
    assert.equal(me.user.id, this.ownerUser.id, "account survives restart");
    const devices = await this.owner.listDevices();
    assert.equal(devices.length, 2, "both devices survive restart");
    const shared = await this.guest.listSharedDevices();
    assert.equal(shared.length, 1, "grant survives restart");

    this.postRestartRecord = after;
    this.closeSdk(queueRecord);
    console.log(
      `PASS [${this.mode}]: restart on preserved DB, laptop reconnects, queued message acked`,
    );
  }

  async revocationPhase() {
    const record = this.postRestartRecord;
    this.assertOpen(record);
    const desktopProc = this.desktop.proc;
    assert.ok(desktopProc && !desktopProc.exitInfo, "desktop is running before revocation");

    await this.owner.revokeDevice(this.desktop.id);
    const exit = await waitFor("revoked desktop process exit", () => desktopProc.exitInfo);
    assert.equal(exit.signal, null, "revoked device exits cleanly, not by signal");
    assert.equal(exit.code, 0, "revoked device exits with status 0");
    this.desktop.proc = null;

    const devices = await this.owner.listDevices();
    assert.equal(
      devices.some((device) => device.id === this.desktop.id),
      false,
      "revoked device is gone from /devices",
    );
    const response = await fetch(`${this.base}/api/v1/tickets`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.desktop.config.credential}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ kind: "device" }),
    });
    assert.equal(response.status, 401, "revoked credential cannot mint a ticket");

    await this.waitDeviceState(this.laptop.id, true);
    const id = this.sdkSend(record, this.laptop, "chat.send", "still relaying");
    const reply = await this.waitSdkReply(record, id);
    assert.equal(reply.data, "still relaying", "remaining device still relays");
    assertIdentity(reply, this.ownerUser, this.laptop, "remaining device");
    await this.waitSdkAck(record, id, ["delivered"]);
    await this.waitSdkDelivered(record, id);

    const barrier = await this.sdkBarrier(record, this.laptop);
    this.assertSdkDelivery(record, this.laptop, id, {
      label: "post-revocation",
      data: "still relaying",
      encrypted: true,
    });
    this.assertSdkDelivery(record, this.laptop, barrier.id, {
      label: "post-revocation barrier",
      data: "barrier",
      encrypted: true,
    });
    await this.waitAcked(id, this.laptop.id);
    await this.waitAcked(barrier.id, this.laptop.id);

    console.log(`PASS [${this.mode}]: mid-session revocation; remaining device relays`);
  }

  // -- processes ------------------------------------------------------------

  spawnProcess(name, command, args, cwd, env) {
    const proc = spawn(command, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    proc.name = name;
    proc.logText = "";
    proc.exitInfo = undefined;
    const append = (chunk) => {
      proc.logText = tail(`${proc.logText}${chunk}`, LOG_LIMIT * 2);
    };
    proc.stdout?.setEncoding("utf8");
    proc.stderr?.setEncoding("utf8");
    proc.stdout?.on("data", append);
    proc.stderr?.on("data", append);
    proc.on("exit", (code, signal) => {
      proc.exitInfo = { code, signal };
    });
    proc.on("error", (error) => {
      proc.spawnError = error;
      proc.logText = tail(`${proc.logText}\nspawn error: ${error.stack ?? error.message}`);
    });
    this.processes.add(proc);
    return proc;
  }

  async killProcess(proc, options = {}) {
    if (!proc || proc.exitInfo) {
      this.processes.delete(proc);
      return;
    }
    try {
      proc.kill();
    } catch {
      // The process may already be gone.
    }
    try {
      await waitFor(`${proc.name} to exit`, () => proc.exitInfo, PROCESS_WAIT_MS);
    } catch {
      try {
        proc.kill("SIGKILL");
      } catch {
        // Best effort.
      }
      try {
        await waitFor(`${proc.name} to exit after SIGKILL`, () => proc.exitInfo, 5_000);
      } catch {
        if (!options.quiet) {
          throw new Error(`${proc.name} did not exit after SIGKILL`);
        }
      }
    }
    this.processes.delete(proc);
  }
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (!IS_RUNNER) {
  orchestrate().catch((error) => {
    warn(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exit(1);
  });
} else {
  runHarness()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      warn(error instanceof Error ? error.stack ?? error.message : String(error));
      process.exit(1);
    });
}
