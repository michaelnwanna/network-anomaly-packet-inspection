# Traceglass C#

Native .NET 10 implementation. **Go remains the primary implementation** at the
repository root; this is not a wrapper around the Go executable.

Uses `TcpListener`, asynchronous streams, and `SslStream`
for HTTP forwarding, CONNECT tunnels, and opt-in per-domain HTTPS inspection.
An ASP.NET Core loopback dashboard embeds the canonical frontend. A bounded
channel feeds prepared SQLite/WAL transactions on a single writer.

## Build and run

From the repository root, with the .NET 10 SDK:

```sh
dotnet restore implementations/csharp/Traceglass.sln --locked-mode
dotnet build implementations/csharp/Traceglass.sln -c Release --no-restore
dotnet implementations/csharp/src/Traceglass/bin/Release/net10.0/traceglass-csharp.dll serve
```

For authorized HTTPS inspection, stop the server and run:

```sh
dotnet implementations/csharp/src/Traceglass/bin/Release/net10.0/traceglass-csharp.dll ca init -data-dir ./data-csharp
dotnet implementations/csharp/src/Traceglass/bin/Release/net10.0/traceglass-csharp.dll serve -data-dir ./data-csharp -inspect example.com
```

Trust `./data-csharp/traceglass-ca.crt` only in the intended test client.
No trust installation is automatic. Protect the corresponding private key.

## Verify

```sh
dotnet test implementations/csharp/Traceglass.sln -c Release --no-restore
export TRACEGLASS_CONFORMANCE_COMMAND="[\"dotnet\",\"$PWD/implementations/csharp/src/Traceglass/bin/Release/net10.0/traceglass-csharp.dll\"]"
go test ./conformance -count=1 -v -timeout=180s
```

Use an absolute DLL path: Go runs package tests from the package directory.

The xUnit suite tests the shared classification vectors, independent certificate
handle lifetimes, queue saturation, writer exclusivity, age/count retention,
cached aggregates, and reopening persisted metadata.

## Runtime boundaries

- Default state: `./data-csharp/metadata-csharp.db`; never share with another runtime.
- Each client connection handles one HTTP exchange, then closes. Native upstream
  traffic uses HTTP/1.1, not Go's optional upstream HTTP/2.
- Accepted proxy connections count toward `-max-active`, including idle clients;
  excess connections close rather than receiving a guaranteed HTTP 503.
- Connections have a two-minute overall budget; destination dialing has ten seconds.
  These are not identical to Go's sliding tunnel idle deadlines.
- Unix file modes are enforced on macOS/Linux. Windows ACL hardening is not implemented.

See [the compatibility contract](../../docs/IMPLEMENTATIONS.md), [API](../../docs/API.md),
and [threat model](../../docs/THREAT-MODEL.md) before use.
