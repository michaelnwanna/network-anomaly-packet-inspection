# Native implementations and compatibility

**Go is the primary, default, and reference implementation.** Root build commands,
the Makefile, and the main CI workflow continue to target Go. Additional native
implementations live in:

| Runtime | Source and instructions | Networking / persistence |
| --- | --- | --- |
| Go | [Root README](../README.md) | net/http, goroutines, modernc SQLite |
| C# / .NET 10 | [C#](../implementations/csharp/README.md) | asynchronous streams, SslStream, Microsoft.Data.Sqlite |
| C++17 | [C++](../implementations/cpp/README.md) | Boost.Asio/Beast, OpenSSL 3, SQLite3 |
| Rust | [Rust](../implementations/rust/README.md) | Tokio/Hyper, rustls/rcgen, rusqlite |

These are native servers, not language-specific launchers around Go.

## Shared behavior

- Loopback-only explicit HTTP proxies; no transparent OS interception, TUN,
  packet capture, UDP, or HTTP/3.
- `serve`, `ca init`, version/help commands, and common operational flags.
- HTTP forwarding, unlisted HTTPS CONNECT tunnels, and **opt-in** exact/wildcard
  HTTPS inspection. A wildcard excludes its domain apex.
- Dynamic certificates from a dedicated local CA. Re-initialization refuses to
  overwrite keys; no system trust installation or automatic trust changes.
- Verified upstream TLS, including hostnames. `-upstream-ca FILE` adds explicit
  PEM trust for controlled fixtures/private PKI, not an insecure TLS bypass.
- Default denial of private/local destinations, with explicit `-allow-private`
  for authorized local fixtures only.
- Deterministic tracker, combined body-size, and port signals. Signals do not
  block traffic.
- Metadata-only SQLite/WAL storage: destination, method, status, byte counters,
  timing, flags, and sanitized error codes. No persisted bodies, headers, paths,
  queries, or credentials.
- Bounded producer queues, prepared batched writes, exclusive writer locks,
  indexed age/count retention, and cached retained-flow aggregates.
- The exact same embedded frontend assets, protected local API, session token,
  Host/Origin checks, host/flag filtering, and descending-ID cursor pagination.
- Graceful interrupt closes listeners/connections and drains accepted metadata.

Storage queue overflow drops metadata rather than blocking traffic. Drop
counters and rate-limited logs make this visible; fatal writer failures stop the
service. This is not a lossless or encrypted audit log.

## Separate identities and databases

Use a **different data directory per implementation**. Defaults are `./data`
(Go), `./data-csharp`, `./data-cpp`, and `./data-rust`. Native schemas and CA
formats are private to their implementation; cross-runtime migrations or
database sharing are unsupported. Never point a native server at your Go state.
Only one writer may open a particular implementation's database.

All servers use ports 8080/9090 by default. Stop one before starting another,
or choose different loopback ports. Always use the dashboard URL printed by the
currently running server.

## Deliberate differences

The native variants are **not performance- or transport-identical**. Go supports
upstream HTTP/2 and client keepalive; native forwarding uses HTTP/1.1 and closes
client connections after each exchange. C# counts accepted connections toward its
active limit; C++ uses bounded threads. Deadline, overload, certificate-cache,
and connection-budget differences are documented in each native README.

The million-record retention and heap-growth measurements in the root README
apply **only to Go**. Native tests validate bounded queues and retained rows, not
the same million-record benchmark. No cross-language throughput or memory
superiority claim is made.

Native implementations are validated on local macOS and Linux CI. Windows ACL
hardening and mobile hosting are not implemented or claimed.

## Reproducible verification

[Shared classification vectors](../testdata/conformance/classification.json)
define signal ordering, strict size thresholds, domain boundaries, scope
matching, and overflow cases.

The [Go conformance package](../conformance/) tests a built executable selected
by `TRACEGLASS_CONFORMANCE_COMMAND`, a JSON array containing an executable and
optional fixed arguments. **Paths must be absolute**: Go executes tests from
the package directory. Without this variable, executable tests explicitly skip;
the Go classification test still runs.

Example after building Go:

```sh
export TRACEGLASS_CONFORMANCE_COMMAND="[\"$PWD/bin/traceglass\"]"
go test ./conformance -race -count=1 -v -timeout=180s
```

The black-box suite uses loopback fixtures and explicit temporary CA trust to
check HTTP forwarding, HTTPS interception, untouched HTTPS tunnels, upstream
certificate rejection, CONNECT authority pinning, API auth/Host/Origin,
canonical assets, privacy, metadata byte counts, filters/cursors, retention,
streaming uploads, truncated-response rejection, early upstream rejections,
default destination policy, and graceful shutdown. Native unit/integration
suites supplement this contract; each runtime has a separate CI workflow.
