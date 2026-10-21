package conformance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

type outputBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.b.Len() < 64<<10 {
		b.b.Write(p[:min(len(p), (64<<10)-b.b.Len())])
	}
	return len(p), nil
}

func (b *outputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var safe []string
	for _, line := range strings.Split(b.b.String(), "\n") {
		if !strings.Contains(line, "token=") {
			safe = append(safe, line)
		}
	}
	return strings.Join(safe, "\n")
}

type runningProxy struct {
	proxyURL *url.URL
	uiURL    *url.URL
	token    string
	dir      string
	process  *exec.Cmd
	done     chan struct{}
	err      error
	logs     *outputBuffer
	stopOnce sync.Once
}

func executable(t *testing.T) []string {
	t.Helper()
	value := os.Getenv("TRACEGLASS_CONFORMANCE_COMMAND")
	if value == "" {
		t.Skip("set TRACEGLASS_CONFORMANCE_COMMAND to a JSON command array to test a built implementation")
	}
	var command []string
	if err := json.Unmarshal([]byte(value), &command); err != nil || len(command) == 0 || command[0] == "" {
		t.Fatalf("invalid TRACEGLASS_CONFORMANCE_COMMAND: provide a nonempty JSON command array")
	}
	return command
}

func launch(t *testing.T, command []string, trustFile string, maxRecords int, allowPrivate bool) *runningProxy {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	initArgs := append(slices.Clone(command[1:]), "ca", "init", "-data-dir", dir)
	init := exec.CommandContext(ctx, command[0], initArgs...)
	if output, err := init.CombinedOutput(); err != nil {
		t.Fatalf("ca init failed: %v\n%s", err, output)
	}
	if err := exec.CommandContext(ctx, command[0], initArgs...).Run(); err == nil {
		t.Fatal("ca init replaced existing identity")
	}
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(`{"tracking_domains":["localhost"],"allowed_ports":[80,443],"large_payload_bytes":100}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(slices.Clone(command[1:]), "serve", "-listen", "127.0.0.1:0", "-dashboard", "127.0.0.1:0",
		"-data-dir", dir, "-inspect", "127.0.0.1", "-upstream-ca", trustFile,
		"-max-records", strconv.Itoa(maxRecords), "-max-age", "1h", "-queue-size", "256", "-max-active", "32", "-rules", rulesPath)
	if allowPrivate {
		args = append(args, "-allow-private")
	}
	cmd := exec.CommandContext(ctx, command[0], args...)
	logs := &outputBuffer{}
	cmd.Stderr = logs
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	running := &runningProxy{dir: dir, process: cmd, done: make(chan struct{}), logs: logs}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			text := scanner.Text()
			fmt.Fprintln(logs, text)
			if strings.HasPrefix(text, "Proxy: ") || strings.HasPrefix(text, "Dashboard: ") {
				lines <- text
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(logs, "read process output:", err)
		}
		close(lines)
	}()
	go func() { running.err = cmd.Wait(); close(running.done) }()
	t.Cleanup(func() { running.stop(t) })
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for running.proxyURL == nil || running.uiURL == nil {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("proxy exited before readiness:\n%s", logs.String())
			}
			if value, ok := strings.CutPrefix(line, "Proxy: "); ok {
				running.proxyURL = parseEndpoint(t, value)
			}
			if value, ok := strings.CutPrefix(line, "Dashboard: "); ok {
				running.uiURL = parseEndpoint(t, value)
				fragment, err := url.ParseQuery(running.uiURL.Fragment)
				if err != nil {
					t.Fatal("invalid dashboard token fragment")
				}
				running.token = fragment.Get("token")
				running.uiURL.Fragment = ""
			}
		case <-running.done:
			t.Fatalf("proxy exited before readiness: %v\n%s", running.err, logs.String())
		case <-timeout.C:
			t.Fatalf("proxy startup timed out:\n%s", logs.String())
		}
	}
	if len(running.token) < 32 {
		t.Fatal("dashboard startup URL lacks a strong session token")
	}
	return running
}

func parseEndpoint(t *testing.T, value string) *url.URL {
	t.Helper()
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.Port() == "" || u.Port() == "0" {
		t.Fatalf("invalid ready endpoint %q", value)
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		t.Fatal("listener is not loopback")
	}
	return u
}

func (p *runningProxy) stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		select {
		case <-p.done:
			if p.err != nil {
				t.Errorf("proxy exited unexpectedly: %v\n%s", p.err, p.logs.String())
			}
			return
		default:
		}
		if err := p.process.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("interrupt proxy: %v", err)
		}
		select {
		case <-p.done:
			if p.err != nil {
				t.Errorf("proxy shutdown failed: %v\n%s", p.err, p.logs.String())
			}
		case <-time.After(15 * time.Second):
			if err := p.process.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill unresponsive test process: %v", err)
			}
			<-p.done
			t.Error("proxy failed to shut down and drain metadata in 15 seconds")
		}
	})
}

func (p *runningProxy) api(t *testing.T, path string, authenticated bool, host, origin string) (int, []byte) {
	t.Helper()
	u := *p.uiURL
	u.Path, u.RawQuery, _ = strings.Cut(path, "?")
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	if host != "" {
		req.Host = host
	}
	req.Header.Set("Origin", origin)
	resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}).Do(req)
	if err != nil {
		t.Fatalf("local API request: %v\n%s", err, p.logs.String())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("dashboard must disable caching")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("dashboard CSP missing")
	}
	return resp.StatusCode, body
}

func (p *runningProxy) records(t *testing.T, minimum int, query string) []store.Record {
	t.Helper()
	until := time.Now().Add(8 * time.Second)
	for {
		status, body := p.api(t, "/api/records?limit=200"+query, true, "", "")
		if status != 200 {
			t.Fatalf("records API returned %d: %s", status, body)
		}
		var page struct {
			Records []store.Record `json:"records"`
			Next    int64          `json:"next_before"`
		}
		if err := json.Unmarshal(body, &page); err != nil || page.Records == nil {
			t.Fatalf("invalid records API shape: %s / %v", body, err)
		}
		if len(page.Records) >= minimum {
			for i, record := range page.Records {
				if record.Flags == nil {
					t.Fatalf("flags must be a JSON array: %+v", record)
				}
				if i > 0 && record.ID >= page.Records[i-1].ID {
					t.Fatal("records are not in descending ID order")
				}
			}
			return page.Records
		}
		if time.Now().After(until) {
			t.Fatalf("expected %d records, got %d\n%s", minimum, len(page.Records), p.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func fixtureTLS(t *testing.T, handler http.Handler, names ...string) (*httptest.Server, []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Traceglass Conformance Upstream"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if len(names) > 0 {
		leaf.DNSNames, leaf.IPAddresses = names, nil
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func proxyClient(t *testing.T, p *runningProxy, roots *x509.CertPool) *http.Client {
	t.Helper()
	transport := &http.Transport{Proxy: http.ProxyURL(p.proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 8 * time.Second}
}

func responseBody(t *testing.T, resp *http.Response, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestExecutableContract(t *testing.T) {
	command := executable(t)
	const secret = "conformance-private-body-query-and-credential"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err != nil || string(body) != secret || r.URL.Query().Get("secret") != secret || r.Header.Get("Authorization") != secret {
				t.Errorf("proxy changed request data")
			}
			if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
				t.Error("hop-by-hop request headers reached the origin")
			}
		}
		w.Header().Set("Connection", "X-Hop-Response")
		w.Header().Set("X-Hop-Response", "must-be-removed")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, strings.Repeat("reply", 32))
	})
	trusted, rootPEM := fixtureTLS(t, handler)
	wrongName, otherRoot := fixtureTLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("hostname-mismatched upstream must not receive HTTP requests")
	}), "wrong-name.invalid")
	rootPEM = append(rootPEM, otherRoot...)
	trustFile := filepath.Join(t.TempDir(), "upstream.crt")
	if err := os.WriteFile(trustFile, rootPEM, 0600); err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewServer(handler)
	defer plain.Close()
	p := launch(t, command, trustFile, 1000, true)
	localPEM, err := os.ReadFile(filepath.Join(p.dir, "traceglass-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(localPEM) || !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid generated root certificates")
	}
	client := proxyClient(t, p, roots)

	t.Run("protected-dashboard-and-shared-assets", func(t *testing.T) {
		for _, check := range []struct {
			path, host, origin string
			auth               bool
			status             int
		}{
			{"/api/status", "", "", false, 401},
			{"/api/status", "evil.invalid", "", true, 403},
			{"/api/status", "", "https://evil.invalid", true, 403},
			{"/api/status", "", "", true, 200},
			{"/api/records?limit=201", "", "", true, 400},
			{"/api/records?before=-1", "", "", true, 400},
			{"/api/records?flagged=maybe", "", "", true, 400},
		} {
			status, _ := p.api(t, check.path, check.auth, check.host, check.origin)
			if status != check.status {
				t.Errorf("%s: got status %d, want %d", check.path, status, check.status)
			}
		}
		for _, asset := range []string{"index.html", "app.js", "style.css"} {
			status, body := p.api(t, "/"+asset, false, "", "")
			expected, err := os.ReadFile(filepath.Join("..", "internal", "dashboard", "web", asset))
			if err != nil {
				t.Fatal(err)
			}
			if status != 200 || !bytes.Equal(body, expected) {
				t.Errorf("canonical dashboard asset %s differs or unavailable", asset)
			}
		}
	})
	t.Run("http-forwarding-and-privacy", func(t *testing.T) {
		req, err := http.NewRequest("POST", plain.URL+"/private?secret="+secret, strings.NewReader(secret))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", secret)
		req.Header.Set("Proxy-Authorization", secret)
		req.Header.Set("Connection", "X-Hop")
		req.Header.Set("X-Hop", "must-be-removed")
		resp, err := client.Do(req)
		body := responseBody(t, resp, err)
		if resp.StatusCode != 201 || len(body) != 160 || resp.Header.Get("X-Hop-Response") != "" {
			t.Fatalf("HTTP response status/body/hop headers changed: status=%d bytes=%d hop-header=%q", resp.StatusCode, len(body), resp.Header.Get("X-Hop-Response"))
		}
		rows := p.records(t, 1, "")
		record := rows[0]
		if record.Mode != "http" || record.RequestBytes != int64(len(secret)) || record.ResponseBytes != 160 ||
			record.Status != 201 || record.ErrorCode != "" || !slices.Contains(record.Flags, "large-payload") ||
			!slices.Contains(record.Flags, "unsanctioned-port") {
			t.Fatalf("incorrect HTTP metadata: %+v", record)
		}
		_, stored := p.api(t, "/api/records", true, "", "")
		if bytes.Contains(stored, []byte(secret)) || bytes.Contains(stored, []byte("/private")) {
			t.Fatal("sensitive request content persisted")
		}
	})
	t.Run("selective-https-inspection", func(t *testing.T) {
		resp, err := client.Get(trusted.URL + "/inspected")
		body := responseBody(t, resp, err)
		if resp.StatusCode != 201 || len(body) != 160 {
			t.Fatalf("inspected HTTPS failed: status=%d body=%s", resp.StatusCode, body)
		}
		if resp.TLS == nil || bytes.Equal(resp.TLS.PeerCertificates[0].Raw, trusted.Certificate().Raw) {
			t.Fatal("allowlisted destination was not MITM inspected")
		}
		rows := p.records(t, 2, "")
		if rows[0].Mode != "inspected" || rows[0].ResponseBytes != 160 || rows[0].ErrorCode != "" {
			t.Fatalf("incorrect inspected metadata: %+v", rows[0])
		}
	})
	t.Run("unlisted-https-remains-encrypted", func(t *testing.T) {
		tunnelURL := strings.Replace(trusted.URL, "127.0.0.1", "localhost", 1)
		resp, err := client.Get(tunnelURL)
		body := responseBody(t, resp, err)
		if resp.StatusCode != 201 || len(body) != 160 || resp.TLS == nil ||
			!bytes.Equal(resp.TLS.PeerCertificates[0].Raw, trusted.Certificate().Raw) {
			t.Fatal("unlisted HTTPS was changed or intercepted")
		}
		rows := p.records(t, 3, "")
		record := rows[0]
		if record.Mode != "tunnel" || record.Method != "CONNECT" || record.RequestBytes <= 0 || record.ResponseBytes <= 0 ||
			!slices.Contains(record.Flags, "known-tracker") {
			t.Fatalf("incorrect tunnel metadata/classification: %+v", record)
		}
	})
	t.Run("upstream-certificate-trust-is-required", func(t *testing.T) {
		untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("untrusted upstream must not receive HTTP requests")
		}))
		defer untrusted.Close()
		resp, err := client.Get(untrusted.URL)
		body := responseBody(t, resp, err)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("invalid upstream certificate accepted: %d %s", resp.StatusCode, body)
		}
		rows := p.records(t, 4, "")
		if rows[0].ErrorCode != "upstream-failed" {
			t.Fatalf("upstream TLS failure not surfaced: %+v", rows[0])
		}
	})
	t.Run("authority-pinned-to-connect", func(t *testing.T) {
		req, err := http.NewRequest("GET", trusted.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "outside-scope.invalid"
		resp, err := client.Do(req)
		responseBody(t, resp, err)
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("mismatched authority accepted: %d", resp.StatusCode)
		}
	})
	t.Run("extra-trust-does-not-bypass-hostname-checks", func(t *testing.T) {
		resp, err := client.Get(wrongName.URL)
		responseBody(t, resp, err)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("trusted but hostname-mismatched upstream was accepted: %d", resp.StatusCode)
		}
	})
	t.Run("pagination-and-filters", func(t *testing.T) {
		rows := p.records(t, 4, "")
		oldest := rows[len(rows)-1]
		status, body := p.api(t, "/api/records?limit=1&before="+strconv.FormatInt(oldest.ID+1, 10), true, "", "")
		var result struct {
			Records []store.Record `json:"records"`
			Next    int64          `json:"next_before"`
		}
		if err := json.Unmarshal(body, &result); err != nil || status != 200 ||
			len(result.Records) != 1 || result.Records[0].ID != oldest.ID || result.Next != oldest.ID {
			t.Fatalf("cursor pagination mismatch: %s / %v", body, err)
		}
		filtered := p.records(t, 1, "&host=localhost&flagged=true")
		for _, record := range filtered {
			if record.Host != "localhost" || len(record.Flags) == 0 {
				t.Fatalf("filtered result does not match: %+v", record)
			}
		}
	})
	p.stop(t)
}

func TestExecutableRetention(t *testing.T) {
	command := executable(t)
	origin, root := fixtureTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "retention")
	}))
	trustFile := filepath.Join(t.TempDir(), "upstream.crt")
	if err := os.WriteFile(trustFile, root, 0600); err != nil {
		t.Fatal(err)
	}
	p := launch(t, command, trustFile, 3, true)
	pemData, err := os.ReadFile(filepath.Join(p.dir, "traceglass-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		t.Fatal("invalid local CA")
	}
	client := proxyClient(t, p, roots)
	for range 7 {
		resp, err := client.Get(origin.URL)
		responseBody(t, resp, err)
		if resp.StatusCode != 200 {
			t.Fatalf("retention fixture returned %d", resp.StatusCode)
		}
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		rows := p.records(t, 3, "")
		if rows[0].ID >= 7 {
			if len(rows) != 3 {
				t.Fatalf("max-records=3 not enforced: %+v", rows)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("last exchanges never reached durable metadata")
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.stop(t)
}

func TestExecutableStreaming(t *testing.T) {
	command := executable(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/early":
			if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
				t.Error(err)
			}
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		case "/length-truncated", "/chunk-truncated":
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if r.URL.Path == "/length-truncated" {
				io.WriteString(rw, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nshort")
			} else {
				io.WriteString(rw, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nshort\r\n")
			}
			if err := rw.Flush(); err != nil {
				t.Error(err)
			}
		default:
			hash := sha256.New()
			if _, err := io.Copy(hash, r.Body); err != nil {
				t.Error(err)
				return
			}
			fmt.Fprintf(w, "%x", hash.Sum(nil))
		}
	})
	_, root := fixtureTLS(t, handler)
	trustFile := filepath.Join(t.TempDir(), "upstream.crt")
	if err := os.WriteFile(trustFile, root, 0600); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(handler)
	defer origin.Close()
	p := launch(t, command, trustFile, 1000, true)
	client := proxyClient(t, p, nil)
	payload := bytes.Repeat([]byte("streaming-regression-"), 100_000)
	expected := fmt.Sprintf("%x", sha256.Sum256(payload))
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("large-upload-chunked-%t", chunked), func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, origin.URL+"/upload", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if chunked {
				req.ContentLength = -1
			}
			resp, err := client.Do(req)
			body := responseBody(t, resp, err)
			if resp.StatusCode != 200 || string(body) != expected {
				t.Fatalf("upload changed in transit: status=%d digest=%q", resp.StatusCode, body)
			}
		})
	}
	for _, path := range []string{"/length-truncated", "/chunk-truncated"} {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(origin.URL + path)
			if err != nil {
				t.Fatalf("truncated fixture failed before headers: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("truncated fixture status=%d, want 200", resp.StatusCode)
			}
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Fatal("truncated upstream body appeared complete")
			}
		})
	}
	t.Run("early-rejection-with-unfinished-upload", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", p.proxyURL.Host, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(conn, "POST %s/early HTTP/1.1\r\nHost: %s\r\nContent-Length: 16000000\r\n\r\nshort", origin.URL, u.Host); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "POST"})
		if err != nil {
			t.Fatalf("proxy blocked the early rejection behind an unfinished upload: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("early rejection changed: got %d, want 413", resp.StatusCode)
		}
	})
	rows := p.records(t, 5, "")
	streamFailures := 0
	for _, row := range rows {
		if row.ErrorCode == "stream-failed" {
			streamFailures++
		}
	}
	if streamFailures != 2 {
		t.Fatalf("truncated streams not recorded as failures: %+v", rows)
	}
	p.stop(t)

	t.Run("private-destinations-denied-by-default", func(t *testing.T) {
		denied := launch(t, command, trustFile, 1000, false)
		resp, err := proxyClient(t, denied, nil).Get(origin.URL + "/denied")
		responseBody(t, resp, err)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("private HTTP destination was not denied: status=%d", resp.StatusCode)
		}
		denied.stop(t)
	})
}
