# Threat model

## Intended use

Traceglass is an authorized debugging tool for a single-user workstation. It is not a network boundary, a multi-user service, an endpoint protection agent, or a compliance-grade audit log.

The operating-system account, executable, data directory, and selected clients are trusted. Upstream servers, DNS responses, web origins, HTTP content, and traffic history displayed by the UI are untrusted inputs. The OS trust store and resolver are relied on.

## Trust boundaries

| Boundary | Control | Remaining risk |
| --- | --- | --- |
| Network to local proxy | Loopback-only listeners; no LAN bind option | Local processes can use the proxy; there is no per-application identity or proxy authentication |
| Browser to dashboard API | Random 256-bit session bearer token, exact Host validation, origin checks, no CORS, read-only routes | Local malware/browser extensions or a compromised account can steal the token |
| Dashboard content | Embedded local assets, restrictive CSP, `textContent` rendering, no external fonts/scripts | The OS/browser and installed extensions remain trusted |
| Proxy to destination | Validate all resolved IPs and dial literals; deny private, loopback, link-local, unspecified and multicast destinations by default | This is not a full reserved-address firewall; trusted client traffic can still use public destinations and an upstream public server can relay traffic |
| Client to inspected TLS | Explicit domain scope, TLS 1.2+, dynamic SANs, no cross-authority requests inside a CONNECT | Trusting the local CA permits impersonation by whoever controls its private key |
| Inspected TLS to upstream | Normal certificate/hostname verification, TLS 1.2+, no insecure bypass option | A compromised system root store or upstream service remains outside the protection model |
| Flow to metadata | Only fixed metadata fields; no persisted payloads, paths, queries, headers, or credentials | Hostnames, timing, methods and transfer sizes can themselves reveal sensitive behavior |
| Metadata to disk | Prepared SQL, bounded queue, one writer, WAL, `0600` database/key, row/age retention | No encryption at rest, no secure deletion, no protection from the same account or root |

The dashboard's static shell is public on loopback and contains no secret. Only authenticated API calls return history and statistics. The startup URL fragment is consumed into tab-scoped session storage and removed from the address bar. Do not put the token in query parameters.

## CA lifecycle

1. `ca init` generates a new ECDSA P-256 root and private key in a dedicated directory.
2. Creation uses exclusive files and refuses to overwrite an existing root or key.
3. Trust is never installed automatically. Prefer a per-client CA file or isolated browser profile.
4. Interception requires both a loaded CA and an explicit `-inspect` scope.
5. The root is valid for two years. Leaves last at most 24 hours and never outlive the root.
6. Remove any browser/system trust you deliberately added after use.
7. For rotation, stop the proxy, remove old trust, securely archive or dispose of the old key according to your policy, and initialize a **new dedicated data directory**. There is no automatic rotation or revocation service.

Keep the private key out of source control, shared folders, and backups without equivalent protection. The ignore rules help but are not a substitute for key hygiene. If creation is interrupted and leaves partial material, inspect that dedicated directory manually; startup will not overwrite it.

## Explicit limitations

- Other local users/processes are not strongly isolated by loopback alone. Do not use this on an untrusted multi-user host.
- `-allow-private` deliberately opens access to local services and cloud metadata IPs. Use only for controlled fixtures.
- No automatic traffic blocking for tracker/size/port alerts. A threshold match is not evidence of malicious behavior.
- Payloads pass through process memory during authorized inspection, even though they are not persisted. Core dumps, swap, debuggers, and system diagnostics are outside the no-payload-storage guarantee.
- Queue saturation drops **metadata**, not forwarded bytes. A warning and counter reveal loss, but the history is incomplete. A storage failure stops the service; queued/in-flight records may be lost.
- A crash or forced kill may lose queued records. WAL with `synchronous=NORMAL` is not a guarantee against every power-loss scenario.
- Completed-flow summaries omit live tunnel details until closure. Protocol upgrades, HTTP trailers, HTTP/3, UDP, and apps bypassing proxy settings are outside visibility.
- Retention limits live rows, not allocated database size. Deleted pages may be reused; SQLite files need not shrink. Stop the service before offline maintenance/backups; do not copy only the main file while WAL is active.
- Rate limits, timeouts, and bounded active work reduce accidental exhaustion but do not guarantee denial-of-service resistance against hostile local clients.
- Private key mode checks are Unix-oriented. Windows ACL behavior needs dedicated implementation and validation before claiming equivalent support.

## Reporting a problem

Do not publish traffic dumps, tokens, CA keys, or credentials in issues. Contact the maintainer privately through the contact information on their [GitHub profile](https://github.com/michaelnwanna). Provide a minimal, synthetic reproduction where possible.
