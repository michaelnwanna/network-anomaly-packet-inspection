# Local read-only API

The dashboard and API share the loopback listener (default `127.0.0.1:9090`). Use the **exact listener authority** as Host; aliases such as `localhost` are intentionally rejected when the listener is `127.0.0.1`.

Every `/api/` request requires:

```http
Authorization: Bearer <token printed at startup>
```

No CORS is enabled. Browser origins must match `http://<listener-authority>`. Only GET is supported. Tokens reset on restart. Never include them in query strings or saved screenshots.

## `GET /api/status`

```json
{
  "stats": {
    "records": 123,
    "flagged": 7,
    "request_bytes": 21000,
    "response_bytes": 85000,
    "dropped": 0,
    "queued": 2
  },
  "active": 3,
  "proxy": "127.0.0.1:8080",
  "inspect": ["example.com"],
  "max_records": 1000000,
  "max_age": "168h0m0s",
  "allow_private": false
}
```

`records`, `flagged`, and byte counts describe **currently retained committed rows**, not lifetime traffic. `dropped` counts queue overflows in the current process session. `queued` excludes the writer's uncommitted batch. `active` counts current proxy handlers, including CONNECT tunnels. Status and records are independent snapshots, not one transactional API read. Empty inspection scope may be `null` or `[]`.

## `GET /api/records`

| Query | Default | Validation |
| --- | --- | --- |
| `limit` | `100` | Integer, 1-200 |
| `before` | None | Positive record ID; returns IDs strictly below it |
| `host` | None | Lowercased literal hostname substring, at most 253 bytes |
| `flagged` | `false` | `true` or `false` |

```json
{
  "records": [
    {
      "id": 123,
      "timestamp": 1792490400000,
      "method": "GET",
      "scheme": "https",
      "host": "example.com",
      "port": 443,
      "mode": "inspected",
      "status": 200,
      "request_bytes": 0,
      "response_bytes": 2048,
      "duration_ms": 84,
      "flags": [],
      "error_code": ""
    }
  ],
  "next_before": 123
}
```

Rows are ordered by ID descending. `timestamp` is the exchange/tunnel start time in Unix milliseconds, not completion time. IDs reflect insertion/completion order, so timestamps need not be monotonic.

Pass `next_before` as the next request's `before`; `0` means there is no full next page indicated. A full final page may still return a cursor and the subsequent page can be empty. An empty result always has `"records": []`. Retention and new traffic may change the set between requests; cursors are not snapshot isolation.

Modes:

- `http`: plain HTTP exchange.
- `inspected`: decrypted HTTP exchange within explicitly scoped HTTPS, or its failed client TLS handshake.
- `tunnel`: opaque CONNECT stream; status is the CONNECT result rather than an unseen upstream HTTP status.

`flags` may contain `known-tracker`, `large-payload`, and `unsanctioned-port`. Error codes are deliberately coarse and do not contain full URLs or raw request data: `upstream-failed`, `request-body-failed`, `response-body-failed`, `stream-failed`, `connect-failed`, `client-tls-failed`, `tunnel-io`, `upgrade-unsupported`, `proxy-io-failed`.

If an upstream response is interrupted after its headers have been forwarded, the downstream connection is aborted so the client observes an incomplete body rather than a successful chunked completion. The record keeps the upstream status and reports `stream-failed`.

Early upstream responses (for example, a `413` before an upload finishes) are forwarded immediately. Incomplete client uploads are interrupted after the response and their connection is closed rather than reused. Byte counts describe bytes actually read, not the client's declared Content-Length.

Rejected malformed requests and excess concurrency do not generate flow records. Completed flows are classified and queued; persistence is eventually visible after the batch commit.

## Errors

Errors use a plain-text body and a non-success HTTP status:

- `400`: invalid filter or cursor.
- `401`: missing/invalid bearer token.
- `403`: unexpected Host or cross-origin request.
- `405`: method other than GET.
- `500`: metadata query failure (also logged on the server).

Responses include `Cache-Control: no-store`. Do not expose this listener through an internet-facing reverse proxy.
