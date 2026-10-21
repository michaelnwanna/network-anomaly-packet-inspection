# Traceglass Rust

Native asynchronous Rust implementation using Tokio, Hyper HTTP/1, rustls/rcgen,
and rusqlite. **Go remains the primary implementation** at the repository root.
No Go executable is required at runtime.

Features HTTP forwarding, encrypted CONNECT passthrough, scoped HTTPS MITM,
domain/size/port classification, a bounded metadata queue, prepared SQLite/WAL
batches, indexed age/count retention, and the canonical embedded dashboard/API.

## Build and run

From the repository root, with current stable Rust and a native C toolchain for
bundled SQLite:

```sh
cargo build --locked --release --manifest-path implementations/rust/Cargo.toml
./implementations/rust/target/release/traceglass-rust serve
```

For authorized HTTPS inspection, stop the server and run:

```sh
./implementations/rust/target/release/traceglass-rust ca init -data-dir ./data-rust
./implementations/rust/target/release/traceglass-rust serve -data-dir ./data-rust -inspect example.com
```

Explicitly trust `./data-rust/traceglass-ca.crt` in the intended client only.
Root trust is never installed automatically. Single-dash Go-style serve flags
and Rust-style double-dash flags are accepted.

## Verify

```sh
cargo fmt --manifest-path implementations/rust/Cargo.toml --check
cargo test --locked --manifest-path implementations/rust/Cargo.toml
cargo clippy --locked --manifest-path implementations/rust/Cargo.toml --all-targets -- -D warnings
export TRACEGLASS_CONFORMANCE_COMMAND="[\"$PWD/implementations/rust/target/release/traceglass-rust\"]"
go test ./conformance -count=1 -v -timeout=180s
```

Native tests cover rule and scope boundaries, destinations, filters, CLI
durations, bounded queues, writer locking, and retained metadata. The shared
executable suite checks actual proxy traffic and dashboard interoperability.

## Runtime boundaries

- Default state: `./data-rust/rust-metadata.db`; do not share with another implementation.
- Forwarded responses close their client connection. Upstream HTTP is HTTP/1.1.
- Leaf certificates are generated per inspected CONNECT rather than cached.
- Response headers have a twenty-second budget, dialing and TLS handshakes ten
  seconds each. Outer HTTP connections have a two-minute overall budget.
  Tunnel lifetime/deadline behavior is not identical to Go's sliding idle timer.
- Unix permissions are enforced on macOS/Linux; Windows ACL hardening is not implemented.
- Build against current stable Rust; an older minimum compiler version is not claimed.

See [compatibility](../../docs/IMPLEMENTATIONS.md), [API](../../docs/API.md),
and [threat model](../../docs/THREAT-MODEL.md).
