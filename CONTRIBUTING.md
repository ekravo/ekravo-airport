# Contributing

## Before you start

- Read [Architecture](docs/architecture.md) and [Protocol](docs/protocol.md).
- For anything that changes the wire format, open an issue first. Version 1 is
  already consumed by the TypeScript SDK and the Rust device client; additive
  changes need a compatibility note and a test in both.

## Checks

Every change must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

(cd packages/sdk && npm ci && npm test)

# End-to-end proof (Node 22+, npm, OpenSSL, Rust 1.89+)
node scripts/e2e.mjs

# Dependency advisories (install once: cargo install cargo-audit --locked --version 0.23.0)
cargo audit --deny warnings
(cd packages/sdk && npm audit --audit-level=high)
```

CI also runs the Rust suite on the declared MSRV (Rust 1.89) and the E2E proof
on Node 22. If you add a dependency, check its `rust-version` before raising
the floor. The pinned SQLite binding is explained in
[docs/security.md](docs/security.md#pinned-sqlite-binding); do not remove the
vendor patch without checking the removal conditions there.

End-to-end tests must synchronise on observable state: presence frames,
receipts, device state queries, health checks, process exits, or the read-only
SQLite acknowledgement check. Do not add fixed sleep-based settle delays; a
timeout must fail the test, not retry it.

Tests should use the real router and a real database, as
`crates/server/tests/integration.rs` does. Do not mock the relay to make a test
pass.

## Rules

- No secrets in the repository, logs, error messages, or test fixtures.
- Never log payloads, tokens, pairing codes, credentials, or email addresses.
- Preserve the distinction between a validation failure and an internal failure.
- Keep the server's public surface small: a new endpoint needs an authorization
  story, a rate-limit story, and a test.
- Do not add a dependency for something the standard library or an existing
  dependency already does.
- Cryptographic changes must be implemented in both Rust and TypeScript and
  covered by the shared interoperability vector in
  `crates/device-cli/src/crypto.rs` and `packages/sdk/test/crypto.test.mjs`.
  Both sides must produce the same ciphertext for the same fixed inputs.

## Community

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security
reports follow [SECURITY.md](SECURITY.md), not public issues.

## Commits

Small, focused commits with a message that explains the why. Include tests and
documentation with behavior changes.
