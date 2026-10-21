# Traceglass

### See what leaves your device.

[![Go CI](https://github.com/michaelnwanna/network-anomaly-packet-inspection/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelnwanna/network-anomaly-packet-inspection/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A local-first HTTP/HTTPS inspection proxy and network anomaly observatory, built in Go. Traceglass helps you investigate outgoing telemetry without sending traffic history to a cloud service.

**Go is the primary implementation.** Native [C#](implementations/csharp/),
[C++](implementations/cpp/), and [Rust](implementations/rust/) implementations
live alongside it, with their own builds, tests, and CI. See
[compatibility and runtime differences](docs/IMPLEMENTATIONS.md).

**Opt-in HTTPS interception. Streaming I/O. Bounded queues. SQLite WAL. No persisted payloads.**

> Use only on devices and traffic you own or have explicit permission to inspect. HTTPS inspection creates a powerful trust credential; read [the threat model](docs/THREAT-MODEL.md) before enabling it.

## What it does

| Capability | Implementation |
| --- | --- |
| HTTP visibility | Forward HTTP requests and record destination, method, status, timing, and body-byte counts |
| Selective HTTPS MITM | A local ECDSA root signs short-lived leaf certificates for explicitly allowlisted hosts |
| Default HTTPS passthrough | Unlisted hosts use opaque CONNECT tunnels; certificates and payloads remain end-to-end encrypted |
| Rule-based signals | Known tracker domains, unusually large transfers, and unsanctioned destination ports |
| Local observatory | Embedded, responsive dashboard with live polling, host search, flagged-only filtering, and cursor pagination |
| Durable metadata | Prepared inserts in batches of up to 256, a bounded queue, WAL, indexed retention, and keyset reads |
| Deliberate privacy | No bodies, headers, credentials, URL paths, or query strings stored; no cloud endpoints or dashboard CDN dependencies |

### Scope, honestly

This is an **explicit application-layer proxy**, not a transparent system-wide interceptor or a raw packet sniffer. Configure each client to use it. Records describe completed HTTP exchanges or completed CONNECT tunnels, **not individual network packets**.

- No packet capture, VPN/TUN integration, OS routing changes, or root privileges.
- No HTTP/3, UDP, DNS capture, WebSocket upgrades, or HTTP trailer forwarding.
- Clients that ignore proxy settings bypass inspection. Pinned certificates and mutual TLS are not bypassed.
- Inspected client connections use HTTP/1.1; upstream HTTP/2 is supported by Go's transport.
- Exact scopes match only that host. `*.example.com` matches subdomains, not the apex.
- Signals are deterministic heuristics, not proof of exfiltration or an ML anomaly model. The small bundled tracker list is a starter list, not a comprehensive blocklist.
- Alerts do not block traffic. The separate destination policy denies private/local networks by default.
- Built for local macOS/Linux desktop use. The Go core is portable, but Windows ACL handling and on-device Android/iOS execution are not implemented or validated. Mobile clients can use an explicitly configured, authorized local forwarding setup; the proxy itself intentionally refuses LAN binds.

## Quick start

Requires Go 1.24+ (a current supported Go release is recommended); no Node, frontend build, C compiler, or external database server is required.

```sh
git clone https://github.com/michaelnwanna/network-anomaly-packet-inspection.git
cd network-anomaly-packet-inspection
go mod download
go build -trimpath -o bin/traceglass ./cmd/traceglass
./bin/traceglass serve
```

Default endpoints:

- Proxy: `http://127.0.0.1:8080`
- Dashboard: open the **full URL printed in the terminal**, including `#token=...`.
- Local state: `./data/metadata.db`

The dashboard token is regenerated each run. Its URL fragment is removed by the frontend and the token stays in that tab's session storage; it is not embedded in public assets or sent in URL query parameters. Do not share the startup link or screenshots containing it.

Generate traffic in another terminal:

```sh
# HTTP metadata
curl --noproxy "" --proxy http://127.0.0.1:8080 http://example.com/

# Opaque HTTPS tunnel: no local CA needed
curl --noproxy "" --proxy http://127.0.0.1:8080 https://example.com/
```

Or set per-shell proxy variables for applications that honor them:

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
# Keep local services direct; do not proxy the dashboard.
export NO_PROXY=localhost,127.0.0.1,::1
export no_proxy="$NO_PROXY"
```

Remove those variables when finished. `Ctrl-C` stops listeners, closes tunnels, and drains accepted metadata to SQLite. Pending queue entries can be lost on a crash or forced kill.

## Opt-in HTTPS inspection

First stop any running instance, then create a dedicated CA:

```sh
./bin/traceglass ca init
./bin/traceglass serve -inspect 'example.com,*.example.org'
```

CA creation **does not install system or browser trust**, change routing, or enable interception by itself. Re-initialization refuses to overwrite existing CA material.

Prefer trusting the certificate in a single test client rather than system-wide:

```sh
curl --noproxy "" \
  --proxy http://127.0.0.1:8080 \
  --cacert ./data/traceglass-ca.crt \
  https://example.com/
```

Only named destinations are decrypted. Requests outside the scope remain encrypted tunnels. The proxy verifies the real upstream certificate using the normal system trust store; there is no insecure-upstream switch. A client rejecting the local root produces a `client-tls-failed` record; an invalid upstream certificate produces a `502` and `upstream-failed`.

For a browser, use an isolated test profile and explicitly import **only the public** `traceglass-ca.crt` as a trusted certificate authority using that browser's certificate manager. Browser trust procedures vary; avoid installing a debugging root into your daily-use profile. Never distribute `traceglass-ca.key`. Protect the dedicated data directory and remove any trust you added when finished. The root lasts two years; leaves last at most 24 hours and never outlive the root.

## Classification rules

The default rules flag:

- `known-tracker`: exact or subdomain match against the bundled domain list;
- `large-payload`: **upload + download > 1 MiB**, not greater-than-or-equal;
- `unsanctioned-port`: destination port outside `80` and `443`.

For HTTP and inspected HTTPS, byte counts are body bytes (including any content encoding, excluding framing and headers). For tunnels they are opaque transferred bytes, including TLS overhead. Tunnels have no visible HTTP status; their status field is the proxy's CONNECT result.

Classification is emitted when an exchange/tunnel ends. A long-lived tunnel stays in the active count but is not persisted incrementally.

Provide a replacement rules file:

```json
{
  "tracking_domains": ["tracker.example", "analytics.example"],
  "allowed_ports": [80, 443, 8443],
  "large_payload_bytes": 2097152
}
```

```sh
./bin/traceglass serve -rules ./my-rules.json
```

Unknown fields, invalid ports/domains, multiple JSON values, non-positive thresholds, and files larger than 1 MiB are rejected at startup. Tracking domains include subdomains automatically; do not prefix them with `*.`. HTTPS inspection scope is a separate setting.

## Operational controls

```sh
./bin/traceglass serve \
  -listen 127.0.0.1:8080 \
  -dashboard 127.0.0.1:9090 \
  -data-dir ./data \
  -max-records 1000000 \
  -max-age 168h \
  -queue-size 8192 \
  -max-active 256
```

Use `serve -h` for all flags. Both listeners require a loopback IP literal, including `[::1]` for IPv6. Port `0` selects an available ephemeral port. Only one process can write a given database.

For controlled upstream fixtures or private PKI, `-upstream-ca FILE` adds PEM
certificates to the upstream trust roots. Certificate-chain and hostname
verification remain enabled; this is not a TLS verification bypass. This file
is separate from the local inspection CA trusted by your test client.

Private, loopback, and link-local destinations are denied by default; DNS answers are validated before dialing an IP literal. For an authorized local test server, opt in with `-allow-private`. This broadens access to local services and metadata endpoints; never use it with untrusted clients.

**Resource limits and failure behavior:**

- At most 256 active proxy handlers/tunnels by default; excess work receives `503`. Idle connections are subject to timeouts but this is not an OS-level connection quota.
- Metadata producers never wait for disk. When the queue is full, forwarding continues, the new record is dropped, a rate-limited error is logged, and the dashboard's session drop counter/warning increases. This is **not** a lossless audit logger.
- The writer commits every 250 ms or 256 records. Fatal storage errors are surfaced to the CLI, which shuts down instead of claiming persistence succeeded.
- Retention runs at startup, on batches, and approximately once a minute when idle. The row cap is enforced per committed batch. Age-based deletion is not secure erasure; SQLite pages and WAL may retain deleted bytes.
- Cached aggregates avoid scanning the whole table on every dashboard refresh or batch. Startup rebuilds aggregates once; filtering by a hostname substring can still require a scan and API queries have a five-second deadline.
- Data files are local and unencrypted. Database and CA key files use `0600` permissions. Use a dedicated, access-restricted directory and encrypted disk.
- HTTP exchanges have two-minute read/write budgets, upstream response headers a 20-second budget, DNS resolution plus destination dialing a shared 10-second budget, TLS handshakes a 10-second budget, and tunnels a sliding two-minute I/O idle timeout. Interrupted response streams are aborted rather than presented as successfully completed. This is an inspection tool, not a perfectly transparent reverse proxy for arbitrary long-lived protocols.

## Architecture

```text
Configured application
        |
        v
Loopback explicit proxy  ---- destination policy / bounded concurrency
        |
        +-- HTTP ----------------------------+
        |                                    |
        +-- CONNECT: unlisted --> byte tunnel+--> upstream (verified TLS for MITM)
        |                                    |
        +-- CONNECT: allowlisted --> local TLS termination
                                     |
                                HTTP exchange
                                     |
                           Completed-flow classifier
                                     |
                          Bounded queue (8,192 records)
                                     |
                     Single writer / 256-row transactions
                                     |
                         SQLite WAL + indexed retention
                                     |
                   Token-protected, read-only loopback API
                                     |
                      Embedded dashboard / 3-second polling
```

Go goroutines and the runtime netpoller multiplex connections; payloads are copied as streams rather than accumulated in memory. Leaf certificates have a 256-host cache. SQLite's single-writer design is isolated from the proxy hot path, while WAL allows concurrent reads.

See [the threat model](docs/THREAT-MODEL.md) for trust boundaries and [the API reference](docs/API.md) for schemas and pagination.

## Development and verification

```sh
make build
make check

# Throughput of the actual SQLite transaction path, 256 records per operation
go test ./internal/store -run '^$' -bench BenchmarkBatchedPersistence -benchmem

# Opt-in scale test: insert 1,000,448 records, retain exactly 1,000,000,
# verify the latest record and a 128 MiB retained-Go-heap-growth budget
TRACEGLASS_SCALE_TEST=1 go test ./internal/store -run TestMillionRecordRetention -count=1 -v
```

The scale test calls the writer's transaction path with a fixed 256-record input batch, not a million-row in-memory slice; queue behavior is tested separately. It checks SQLite's actual row count and oldest ID, not just cached counters. Heap growth is measured after GC and is **not process RSS**, peak allocation, or a universal memory guarantee. The benchmark isolates persistence and does not measure proxy throughput. Results depend on hardware, disk, OS, and workload; no production throughput claim is implied.

One observed local scale-test run (macOS/amd64, Go 1.27.2, October 20, 2026):

| Measurement | Observed result |
| --- | --- |
| Inserted records | 1,000,448 |
| Retained records, verified in SQLite | 1,000,000 |
| Persistence and validation elapsed time | 115.91 seconds |
| Retained Go-heap growth after GC | 189,064 bytes |

These are synthetic storage-path measurements from this workstation, not an end-to-end proxy benchmark or an independent production evaluation.

Tests cover dynamic certificate verification, allowlist boundaries, HTTP forwarding and privacy, HTTPS interception, unlisted TLS passthrough, upstream trust failure, destination policy, dashboard authentication/origin/Host checks, concurrent close, queue overflow, retention, cursor pagination, writer failure, and CLI startup/shutdown with persistent state.

GitHub Actions runs formatting checks, `go vet`, race-enabled tests, and a CGO-free Linux build on Go 1.24.x and the current stable Go release. No certificate trust changes or external network fixtures are needed by tests.

Separate [C#](.github/workflows/csharp.yml), [C++](.github/workflows/cpp.yml),
and [Rust](.github/workflows/rust.yml) workflows build and test each native
implementation. All four run the same executable conformance suite against
local HTTP/TLS fixtures. Native runtimes embed the canonical dashboard and
classifier defaults rather than maintaining divergent copies. See
[implementation verification](docs/IMPLEMENTATIONS.md#reproducible-verification).

## Project layout

```text
cmd/traceglass/       CLI, lifecycle, and listener policy
internal/authority/  Local root CA and bounded dynamic leaf cache
internal/classify/   Validated domain/port/payload rules
internal/proxy/      Streaming HTTP forwarding, CONNECT, selective MITM
internal/store/      Bounded writer, SQLite metadata, retention and queries
internal/dashboard/ Read-only API and embedded HTML/CSS/JavaScript
docs/                Threat model and API contract
conformance/         Shared black-box executable contract tests
testdata/conformance/ Classification and inspection-scope vectors
implementations/     Native C#, C++, and Rust implementations (Go stays primary)
```

## Author

Built for [Michael Nwanna](https://github.com/michaelnwanna)'s systems engineering portfolio: network protocols, asynchronous I/O, privacy boundaries, and durable local storage.

## License

[MIT](LICENSE)
