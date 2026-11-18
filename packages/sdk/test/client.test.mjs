import test from "node:test";
import assert from "node:assert/strict";

import { AirportClient } from "../dist/index.js";

class FakeWebSocket {
  static instances = [];

  constructor(url) {
    this.url = url;
    this.listeners = new Map();
    this.readyState = 0;
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type, handler) {
    const handlers = this.listeners.get(type) ?? [];
    handlers.push(handler);
    this.listeners.set(type, handlers);
  }

  send() {}

  close() {
    this.readyState = 3;
    for (const handler of this.listeners.get("close") ?? []) handler({});
  }
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("concurrent 401s share one refresh-token rotation", async () => {
  let refreshCalls = 0;
  let meCalls = 0;
  const fetch = async (input, init = {}) => {
    const url = String(input);
    if (url.endsWith("/api/v1/auth/refresh")) {
      refreshCalls += 1;
      assert.equal(JSON.parse(init.body).refreshToken, "refresh-1");
      return response({
        accessToken: "access-2",
        refreshToken: "refresh-2",
        tokenType: "Bearer",
        expiresIn: 900,
      });
    }
    if (url.endsWith("/api/v1/me")) {
      meCalls += 1;
      const authorization = new Headers(init.headers).get("authorization");
      if (authorization === "Bearer access-1") {
        return response({ error: { code: "unauthorized", message: "expired" } }, 401);
      }
      return response({
        user: {
          id: "usr_1",
          email: "test@example.com",
          createdAt: "2026-01-01T00:00:00Z",
        },
        devices: 0,
      });
    }
    throw new Error(`unexpected request: ${url}`);
  };

  const client = new AirportClient({
    baseUrl: "http://airport.test",
    fetch,
    WebSocket: FakeWebSocket,
  });
  client.setTokens("access-1", "refresh-1");

  const results = await Promise.all([client.me(), client.me()]);
  assert.equal(refreshCalls, 1);
  assert.ok(meCalls >= 3);
  assert.equal(results[0].user.id, "usr_1");
  assert.deepEqual(client.tokens, {
    accessToken: "access-2",
    refreshToken: "refresh-2",
  });
});

test("an HTTP request has a deadline that includes body reading", async () => {
  const client = new AirportClient({
    baseUrl: "http://airport.test",
    fetch: () => new Promise(() => {}),
    WebSocket: FakeWebSocket,
    requestTimeoutMs: 10,
  });
  client.setTokens("access-1");

  await assert.rejects(client.me(), (error) => error?.code === "timeout");
});

test("a WebSocket that never reaches welcome fails the ready promise", async () => {
  const client = new AirportClient({
    baseUrl: "http://airport.test",
    fetch: async () =>
      response({
        ticket: "ticket-1",
        kind: "client",
        expiresAt: "2026-01-01T00:01:30Z",
        path: "/v1/connect?ticket=ticket-1",
        url: "ws://airport.test/v1/connect?ticket=ticket-1",
      }),
    WebSocket: FakeWebSocket,
    connectTimeoutMs: 10,
  });

  const connection = client.connect({ autoReconnect: false });
  const errors = [];
  connection.on("error", (error) => errors.push(error));

  await assert.rejects(
    connection.ready,
    (error) => /closed before it opened/.test(error.message),
  );
  assert.equal(errors[0]?.code, "connect_timeout");
});
