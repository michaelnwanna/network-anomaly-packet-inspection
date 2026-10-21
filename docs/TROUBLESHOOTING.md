# Troubleshooting

Start with the [first-run walkthrough](USAGE.md). These instructions use Go's
default endpoints and flags; consult the native READMEs for build/runtime
differences. Never post session tokens, CA private keys, or real traffic dumps.

## The dashboard opens, but it is empty

Opening the dashboard does **not** configure the browser or device to use the
proxy. Traceglass sees only clients explicitly configured to send traffic to it.

1. Keep the server terminal open.
2. Try this known request in a second terminal:

   ```sh
   curl --noproxy "" --proxy http://127.0.0.1:8080 http://example.com/
   ```

3. Clear the destination filter, uncheck **Flagged only**, and select **Apply
   filter**. Resume live updates or select **Back to latest** if viewing history.
4. Keep the dashboard tab visible and allow a few seconds for commit/polling.

Only completed exchanges/tunnels are persisted. Close a test site's tabs or its
dedicated browser window to finish long-lived tunnels. Seeing active work with
no completed row yet is not necessarily an error. Check `NO_PROXY`, browser
bypass rules, and any VPN/managed policies if curl works but browser traffic
does not appear.

## Authentication error / "Open the dashboard link printed by Traceglass"

The startup link contains a session token in `#token=...`. Open the **full link
from the current server terminal**, not just the base address.

- Restarting the server changes the token; an old tab may have the previous one.
- A new tab/profile, cleared session storage, or different origin may lack the token.
- The fragment disappearing from the address bar after opening is intentional.
- Do not put the token in a query parameter or disable authentication.

If the terminal output is unavailable, stop and restart your own instance to get
a new link. Do not share the link in a screenshot or issue.

## Cannot connect / connection needs attention

Verify the server is still running and you are using its actual port:

```sh
curl --silent --show-error --output /dev/null \
  --write-out 'Dashboard HTTP status: %{http_code}\n' \
  http://127.0.0.1:9090/
```

`200` confirms the static dashboard is reachable, **not** that API
authentication succeeded. An unauthenticated API request returning `401` is
expected. Do not run the dashboard itself through the inspection proxy.

Use the exact loopback address printed at startup. `localhost`, `127.0.0.1`,
and `[::1]` are different browser origins/Host values; substituting one can
invalidate the API Host check or leave the tab without a saved token.

## Port already in use / "bind: address already in use"

Another process, possibly another Traceglass runtime, already owns the port.
Do not kill an unknown process. Stop your previous instance in its terminal,
or choose other loopback ports:

```sh
./bin/traceglass serve -listen 127.0.0.1:8081 -dashboard 127.0.0.1:9091
```

Update your client's proxy to port `8081` and use the newly printed dashboard
link. Alternatively, use port `0` for available ports and read the selected
addresses from startup output. C#, C++, Rust, and Go all default to 8080/9090.

## Certificate error in the client / `client-tls-failed`

First determine whether inspection is enabled for that destination.

- **No matching inspection scope:** the site certificate is still the real
  upstream certificate. A local inspection root should not be needed.
- **Matching scope:** the client must trust the public CA certificate generated
  in the running server's data directory.

For an authorized curl test, use:

```sh
curl --noproxy "" --proxy http://127.0.0.1:8080 \
  --cacert ./data-inspection-demo/traceglass-ca.crt https://example.com/
```

Adjust the path to the actual data directory. A certificate from a different
directory/runtime will not establish the correct trust. Check system time and
certificate expiry. Certificate pinning and mutual TLS are not bypassed.

Do not use `curl -k`, disable certificate validation, or import the private
`.key` file. Prefer per-command trust over system-wide CA installation.

## `502` / `upstream-failed` / `connect-failed`

These can indicate DNS failure, an unreachable destination, destination-policy
denial, or (for inspected HTTPS) upstream certificate failure.

1. Verify the destination works directly and that Internet/DNS access is available.
2. Check whether it resolves to a private, loopback, or link-local address:
   those destinations are denied by default.
3. For private PKI, explicitly supply trusted upstream roots with
   `-upstream-ca /path/to/upstream-roots.pem`. Hostname and chain checks remain on.
   This is separate from the inspection CA trusted by your client.
4. Check the terminal for errors without sharing sensitive traffic.

For a controlled local fixture only, `-allow-private` permits private/local
destinations. Do not enable it merely to make an unknown destination work, and
never use it with untrusted clients.

## Database locked / writer already running / unsupported schema

Use one process per database and a **different data directory per runtime**.
Stop your earlier instance before reopening its state. Do not delete a lock
file to bypass an active writer or point a native implementation at the Go DB.

For a separate Go session:

```sh
./bin/traceglass serve -data-dir ./data-separate \
  -listen 127.0.0.1:8081 -dashboard 127.0.0.1:9091
```

A changed data directory has no inspection CA until you explicitly initialize
one. Do not delete or overwrite existing keys to fix a startup error.

## Dropped records / storage backpressure / writer stops the server

The bounded queue protects forwarding from slow storage. When it fills,
**metadata can be lost**, and the dashboard/logs show the dropped count.
That session's history is incomplete.

- Check free disk space, permissions, and storage performance.
- Reduce request concurrency/workload before increasing `-queue-size`.
- A larger queue uses more memory and does not repair lost records.
- Fatal writer failures stop the service instead of claiming persistence worked.

Do not use Traceglass as a lossless audit logger. Avoid copying only the main
SQLite file while the service is active: WAL may contain committed data.

## Signals or byte counts look unexpected

- `known-tracker` is a domain-list match, not a malware verdict.
- `large-payload` uses combined upload plus download and a **strictly greater**
  threshold.
- `unsanctioned-port` uses the requested destination port, not the proxy port.
- HTTP/inspected counts are body bytes, not headers or framing. Tunnel counts
  include opaque TLS/wire bytes, so they are not comparable to plaintext size.
- Retained totals decrease when retention removes old rows.
- URL paths, queries, and bodies are deliberately unavailable.

## Browser stops working after testing

Restore the test profile's original proxy settings or close the isolated
Chrome/Chromium process. A client still configured to use port 8080 cannot
connect through it after Traceglass stops. Remove any CA trust you deliberately
added, and restore shell proxy variables if changed.

See the [cleanup checklist](USAGE.md#stop-and-clean-up).

## Still stuck

Provide the runtime/version, OS, sanitized startup error, and a minimal synthetic
reproduction. Report whether the curl first-run example works. Exclude session
tokens, private keys, credentials, personal destinations, and traffic databases.
See [reporting guidance](THREAT-MODEL.md#reporting-a-problem).
