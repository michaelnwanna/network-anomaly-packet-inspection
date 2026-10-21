# Traceglass C++

Native C++17 implementation using Boost.Asio/Beast, **OpenSSL 3**, SQLite3, and
nlohmann JSON. **Go remains the primary implementation** at the repository root.
The C++ executable does not launch or depend on a Go server.

Implements streaming HTTP forwarding, CONNECT tunnels, scoped HTTPS MITM,
rule-based signals, bounded single-writer SQLite/WAL persistence, and the
canonical embedded dashboard and read-only API.

## Build and run

Requires a C++17 compiler, CMake 3.24+, OpenSSL 3 development headers, SQLite3
development headers, and Python 3 for build-time resource embedding and tests.
Install Boost 1.74+ and nlohmann JSON 3.11+ development packages to avoid CMake's
version-pinned download fallbacks.

```sh
# Ubuntu/Debian dependencies
sudo apt-get install cmake g++ libboost-dev libssl-dev libsqlite3-dev nlohmann-json3-dev python3

cmake -S implementations/cpp -B implementations/cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build implementations/cpp/build --parallel 2
./implementations/cpp/build/traceglass serve
```

On macOS, install the same libraries with your package manager. If another
OpenSSL major version is the default, select OpenSSL 3 explicitly with
`-DOPENSSL_ROOT_DIR=/path/to/openssl@3`. OpenSSL 4 is not supported.

For authorized HTTPS inspection, stop the server and run:

```sh
./implementations/cpp/build/traceglass ca init -data-dir ./data-cpp
./implementations/cpp/build/traceglass serve -data-dir ./data-cpp -inspect example.com
```

Explicitly trust `./data-cpp/traceglass-ca.crt` in the intended client only.
Trust is never installed automatically; keep the private key private.

## Verify

```sh
ctest --test-dir implementations/cpp/build --output-on-failure
export TRACEGLASS_CONFORMANCE_COMMAND="[\"$PWD/implementations/cpp/build/traceglass\"]"
go test ./conformance -count=1 -v -timeout=180s
```

CTest runs native unit checks and a local Python integration test covering
HTTP/TLS, large streaming uploads, incomplete responses, auth, filters,
metadata privacy, retention, and reopening SQLite state. Fixtures use explicit
test-client trust, not changes to the OS trust store.

## Runtime boundaries

- Supported platform: POSIX macOS/Linux, not Windows.
- Default state: `./data-cpp/metadata-cpp.db`; never share across implementations.
- Bounded thread-per-connection workers, not Go's goroutine/netpoller model.
  Slow clients consume worker slots; excess accepted clients are closed.
- One HTTP exchange per client connection; upstream traffic is HTTP/1.1.
- Upload and early-response handling share an Asio executor; bodies use fixed
  buffers. Deadline behavior differs from Go; this is not a throughput parity claim.

See [compatibility](../../docs/IMPLEMENTATIONS.md), [API](../../docs/API.md),
and [threat model](../../docs/THREAT-MODEL.md).
