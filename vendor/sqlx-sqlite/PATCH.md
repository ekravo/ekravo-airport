# Vendored sqlx-sqlite 0.8.6

This is an unmodified copy of [`sqlx-sqlite` 0.8.6](https://crates.io/crates/sqlx-sqlite/0.8.6)
except for one line in `Cargo.toml` (and `Cargo.toml.orig`):

```toml
[dependencies.libsqlite3-sys]
version = "0.39.1"   # upstream: "0.30.1"
```

## Why

`libsqlite3-sys` before 0.39.0 bundles SQLite versions affected by
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459)
(CVE-2026-119375): a crafted database plus `-wal` pair can make queries return
uninitialized page-cache memory. `libsqlite3-sys` 0.39.1 bundles SQLite 3.54.1,
which contains the fix, and declares Rust 1.88.

The upstream fix is in `sqlx` 0.9.1, but that release requires Rust 1.94. This
project supports Rust 1.89. Vendoring lets the driver use the patched binding
without raising the MSRV or rewriting the storage layer.

Only the dependency version changed. If `sqlx-sqlite` needs source changes to
compile against 0.39, they are recorded here and kept minimal.

## Removal

Delete this directory and the `[patch.crates-io]` entry when a released
`sqlx` version:

1. depends on `libsqlite3-sys >= 0.39.0`, and
2. still builds on Rust 1.89.

The workspace `Cargo.lock` must be regenerated at that point, and the audit job
should remain green.

## License

`sqlx-sqlite` is MIT OR Apache-2.0. Both license texts are included here.
