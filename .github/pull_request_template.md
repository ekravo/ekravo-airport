## Summary

Explain the problem and the change. Link the issue when one exists.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] `(cd packages/sdk && npm ci && npm test)`
- [ ] `node scripts/e2e.mjs` (or the affected transport mode)
- [ ] `cargo audit --deny warnings` and `(cd packages/sdk && npm audit --audit-level=high)`
- [ ] Public docs and configuration examples are updated if behavior changed.

## Safety

- [ ] No credentials, tokens, keys, certificates, or message contents are included.
- [ ] New request paths and untrusted input are bounded and have a documented failure response.
- [ ] Wire-format changes are mirrored in Rust and TypeScript with interoperability coverage.
