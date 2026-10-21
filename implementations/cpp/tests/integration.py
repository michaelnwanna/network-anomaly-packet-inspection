"""Real local HTTP, TLS, CONNECT and SQLite tests; no external traffic or skips."""
import concurrent.futures
import contextlib
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import select
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

EXE = str(pathlib.Path(sys.argv[1]).resolve())
ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = ROOT / "test-runs" / uuid.uuid4().hex
RUN.mkdir(parents=True)
PROCESSES = []
SECRET = "must-not-persist-sensitive-12345"


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class Fixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path.startswith("/truncated"):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"short")
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path.startswith("/chunk-truncated"):
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"5\r\nshort\r\n")
            self.wfile.flush()
            self.close_connection = True
            return
        body = (SECRET + "\n").encode() * 100
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Secret", SECRET)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        remaining = int(self.headers.get("Content-Length", "0"))
        digest = hashlib.sha256()
        while remaining:
            data = self.rfile.read(min(16384, remaining))
            if not data:
                break
            remaining -= len(data)
            digest.update(data)
        body = digest.hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Service:
    def __init__(self, name, *extra, ca=False):
        self.data = RUN / name
        self.data.mkdir()
        if ca:
            run(EXE, "ca", "init", "-data-dir", str(self.data))
            assert (self.data / "traceglass-ca.key").stat().st_mode & 0o777 == 0o600
            again = subprocess.run([EXE, "ca", "init", "-data-dir", str(self.data)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert again.returncode != 0, "CA must not overwrite existing keys"
        self.log = (self.data / "output.log").open("w+")
        self.proc = subprocess.Popen([EXE, "serve", "-listen", "127.0.0.1:0",
                                      "-dashboard", "127.0.0.1:0", "-data-dir",
                                      str(self.data), "-queue-size", "256",
                                      "-max-active", "32", *extra],
                                     stdout=self.log, stderr=self.log)
        PROCESSES.append(self)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.log.seek(0)
            lines = self.log.read().splitlines()
            proxy = next((s.removeprefix("Proxy: ") for s in lines if s.startswith("Proxy: ")), None)
            dashboard = next((s.removeprefix("Dashboard: ") for s in lines if s.startswith("Dashboard: ")), None)
            if proxy and dashboard:
                p, d = urllib.parse.urlsplit(proxy), urllib.parse.urlsplit(dashboard)
                self.proxy = (p.hostname, p.port)
                self.ui = (d.hostname, d.port)
                self.token = d.fragment.removeprefix("token=")
                return
            assert self.proc.poll() is None, f"startup failed: {lines}"
            time.sleep(.02)
        raise AssertionError("startup timed out")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=8)
        assert self.proc.returncode == 0, self.contents()

    def contents(self):
        self.log.seek(0)
        return self.log.read()

    def api(self, path="/api/records", auth=True, host=None, origin=None, method="GET"):
        conn = http.client.HTTPConnection(*self.ui, timeout=5)
        headers = {}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
        if host:
            headers["Host"] = host
        if origin:
            headers["Origin"] = origin
        conn.request(method, path, headers=headers)
        res = conn.getresponse()
        body = res.read()
        assert res.getheader("Access-Control-Allow-Origin") is None
        assert res.getheader("Cache-Control") == "no-store"
        status = res.status
        conn.close()
        return status, body

    def rows(self):
        status, body = self.api()
        assert status == 200
        return json.loads(body)["records"]


def wait_for(fn, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError("condition timed out")


def request(service, port, path="/", method="GET", body=None):
    conn = http.client.HTTPConnection(*service.proxy, timeout=8)
    conn.request(method, f"http://127.0.0.1:{port}{path}", body=body,
                 headers={"X-Secret": SECRET})
    response = conn.getresponse()
    data = response.read()
    status = response.status
    conn.close()
    return status, data


def tls_request(service, port, trusted_ca, path="/", inner_host=None):
    conn = http.client.HTTPSConnection(*service.proxy,
                                      context=ssl.create_default_context(cafile=str(trusted_ca)), timeout=8)
    conn.set_tunnel("127.0.0.1", port, headers={"Host": f"127.0.0.1:{port}"})
    conn.request("GET", path, headers={"Host": inner_host or f"127.0.0.1:{port}"})
    response = conn.getresponse()
    body = response.read()
    status = response.status
    conn.close()
    return status, body


def main():
    # A local self-signed fixture with a real SAN; explicitly add trust only to
    # the test process. The inspection CA and fixture key are distinct.
    openssl = shutil.which("openssl")
    assert openssl, "OpenSSL CLI is required for the local TLS fixture"
    config = RUN / "fixture.cnf"
    config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                      "[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n"
                      "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,digitalSignature,keyEncipherment\n")
    cert, key = RUN / "fixture.crt", RUN / "fixture.key"
    run(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", str(key), "-out", str(cert), "-config", str(config))
    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    tls = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
    for server in (plain, tls):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    port, tls_port = plain.server_port, tls.server_port
    try:
        service = Service("primary", "-allow-private", "-inspect", "127.0.0.1",
                          "-upstream-ca", str(cert), ca=True)
        assert service.api(auth=False)[0] == 401
        assert service.api(host=f"localhost:{service.ui[1]}")[0] == 403
        assert service.api(origin="https://evil.invalid")[0] == 403
        assert service.api(method="POST")[0] == 405
        for invalid in ("?limit=0", "?limit=201", "?before=-1", "?flagged=yes",
                        "?host=" + "x"*254, "?limit=2&limit=3"):
            assert service.api("/api/records"+invalid)[0] == 400
        assert service.api(origin=f"http://127.0.0.1:{service.ui[1]}")[0] == 200
        assert json.loads(service.api("/api/status")[1])["allow_private"]
        for file in ("index.html", "app.js", "style.css"):
            route = "/" if file == "index.html" else "/"+file
            data = service.api(route, auth=False)[1]
            expected = (ROOT.parents[1] / "internal/dashboard/web" / file).read_bytes()
            assert data == expected, file
        assert request(service, port, "/"+SECRET+"?secret="+SECRET)[0] == 200
        payload = (SECRET.encode()+b"x")*50000
        status, body = request(service, port, "/", "POST", payload)
        assert status == 200 and body == hashlib.sha256(payload).hexdigest().encode()
        status, body = tls_request(service, tls_port, service.data / "traceglass-ca.crt", "/"+SECRET)
        assert status == 200 and SECRET.encode() in body
        assert tls_request(service, tls_port, service.data / "traceglass-ca.crt",
                           inner_host="wrong.example")[0] == 421
        with contextlib.suppress(ssl.SSLError, ConnectionResetError):
            tls_request(service, tls_port, cert)
            raise AssertionError("MITM certificate accepted without inspection CA")
        # Both truncation framings must fail client reads, not become successful completions.
        for path in ("/truncated", "/chunk-truncated"):
            try:
                result = request(service, port, path)
            except http.client.IncompleteRead:
                pass
            else:
                raise AssertionError(f"truncated upstream response appeared complete: {path} {result!r}")
        rows = wait_for(lambda: service.rows() if len(service.rows()) >= 6 else None)
        assert any(r["mode"] == "inspected" and r["status"] == 200 for r in rows)
        assert any(r["error_code"] == "stream-failed" for r in rows)
        assert any("large-payload" in r["flags"] for r in rows)
        assert SECRET not in json.dumps(rows)
        assert all(set(r) == {"id", "timestamp", "method", "scheme", "host", "port", "mode",
                              "status", "request_bytes", "response_bytes", "duration_ms",
                              "flags", "error_code"} for r in rows)
        one = json.loads(service.api("/api/records?limit=1")[1])
        assert len(one["records"]) == 1 and one["next_before"] > 0
        older = json.loads(service.api("/api/records?before="+str(one["next_before"]))[1])
        assert all(r["id"] < one["next_before"] for r in older["records"])
        assert json.loads(service.api("/api/records?host=%25")[1])["records"] == []
        # Re-opening the same port-specific directory is prohibited.
        locked = subprocess.run([EXE, "serve", "-data-dir", str(service.data),
                                 "-listen", "127.0.0.1:0", "-dashboard", "127.0.0.1:0"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        assert locked.returncode != 0
        # Retention applies in the writer transaction and on startup.
        retention = Service("retention", "-allow-private", "-max-records", "2", "-max-age", "1h")
        for _ in range(4):
            assert request(retention, port)[0] == 200
        wait_for(lambda: len(retention.rows()) == 2)
        retention.stop()
        db = retention.data / "metadata-cpp.db"
        with sqlite3.connect(db) as sql:
            sql.execute("UPDATE records SET timestamp=0")
        proc = subprocess.Popen([EXE, "serve", "-data-dir", str(retention.data),
                                 "-listen", "127.0.0.1:0", "-dashboard", "127.0.0.1:0",
                                 "-max-age", "1h"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(.5)
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=5) == 0
        with sqlite3.connect(db) as sql:
            assert sql.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 0
        tunnel = Service("tunnel", "-allow-private")
        assert tls_request(tunnel, tls_port, cert)[0] == 200
        wait_for(lambda: any(r["mode"] == "tunnel" for r in tunnel.rows()))
        denied = Service("denied")
        assert request(denied, port)[0] == 502
        untrusted = Service("untrusted", "-allow-private", "-inspect", "127.0.0.1", ca=True)
        assert tls_request(untrusted, tls_port, untrusted.data / "traceglass-ca.crt")[0] == 502
        wait_for(lambda: any(r["error_code"] == "upstream-failed" for r in untrusted.rows()))
        for listen in ("0.0.0.0:0", "localhost:0", "[::]:0", "127.0.0.1:65536"):
            result = subprocess.run([EXE, "serve", "-listen", listen, "-dashboard", "127.0.0.1:0",
                                     "-data-dir", str(RUN / "invalid")],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            assert result.returncode != 0, listen
        # Shutdown must interrupt an idle accepted client and an active opaque tunnel.
        idle = socket.create_connection(service.proxy)
        active = socket.create_connection(tunnel.proxy)
        active.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
        assert b"200" in active.recv(4096)
        for item in PROCESSES:
            item.stop()
        idle.close()
        active.close()
        for file in service.data.glob("metadata-cpp.db*"):
            assert SECRET.encode() not in file.read_bytes(), file
        print("Local integration passed: HTTP streaming, scoped MITM, encrypted passthrough, trust failures, "
              "authority boundaries, API, embedded assets, privacy, retention, locks, shutdown")
    finally:
        for item in PROCESSES:
            if item.proc.poll() is None:
                item.proc.terminate()
                try:
                    item.proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    item.proc.kill()
                    item.proc.wait()
        for server in (plain, tls):
            server.shutdown()
            server.server_close()


try:
    main()
except Exception:
    for service in PROCESSES:
        print(service.data.name, service.contents(), file=sys.stderr)
    print("Failed test artifacts retained:", RUN, file=sys.stderr)
    raise
else:
    for service in PROCESSES:
        service.log.close()
    shutil.rmtree(RUN)
