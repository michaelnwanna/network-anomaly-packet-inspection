package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/authority"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/classify"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

type memorySink struct {
	mu      sync.Mutex
	records []store.Record
}

func (s *memorySink) Enqueue(r store.Record) error {
	s.mu.Lock()
	s.records = append(s.records, r)
	s.mu.Unlock()
	return nil
}

func (s *memorySink) wait(t *testing.T, count int) []store.Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		records := append([]store.Record{}, s.records...)
		s.mu.Unlock()
		if len(records) >= count {
			return records
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected at least %d completed flow records", count)
	return nil
}

func newTestProxy(t *testing.T, inspect bool) (*Proxy, *httptest.Server, *memorySink, *x509.CertPool) {
	t.Helper()
	engine, err := classify.Load(strings.NewReader(`{"tracking_domains":["tracker.test"],"allowed_ports":[80,443],"large_payload_bytes":16}`))
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Classifier: engine, AllowPrivate: true, MaxActive: 16}
	var roots *x509.CertPool
	if inspect {
		dir := t.TempDir()
		if err := authority.Init(dir); err != nil {
			t.Fatal(err)
		}
		opts.CA, err = authority.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		opts.Scope = classify.Scope{"127.0.0.1"}
		pem, err := os.ReadFile(filepath.Join(dir, authority.CertFile))
		if err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("could not load client inspection root")
		}
	}
	sink := &memorySink{}
	opts.Store = sink
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p)
	t.Cleanup(func() { p.Close(); server.Close() })
	return p, server, sink, roots
}

func clientFor(t *testing.T, proxyURL string, roots *x509.CertPool) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: roots},
		DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func readResponse(t *testing.T, response *http.Response, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestHTTPForwardingAndMetadataPrivacy(t *testing.T) {
	const secret = "very-private-credential"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(body) != secret || r.URL.Query().Get("secret") != secret || r.Header.Get("Authorization") != secret {
			t.Error("end-to-end request data was changed")
		}
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Error("hop-by-hop headers leaked upstream")
		}
		w.Header().Set("Connection", "X-Upstream-Hop")
		w.Header().Set("X-Upstream-Hop", "remove")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "reply")
	}))
	defer upstream.Close()
	_, proxyServer, sink, _ := newTestProxy(t, false)
	client := clientFor(t, proxyServer.URL, nil)
	req, err := http.NewRequest("POST", upstream.URL+"/private-path?secret="+secret, strings.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", secret)
	req.Header.Set("Proxy-Authorization", "Basic private-proxy-credential")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "remove")
	resp, err := client.Do(req)
	body := readResponse(t, resp, err)
	if body != "reply" || resp.StatusCode != 201 || resp.Header.Get("X-Upstream-Hop") != "" {
		t.Fatalf("incorrect response: %s, %+v", body, resp)
	}
	record := sink.wait(t, 1)[0]
	if record.RequestBytes != int64(len(secret)) || record.ResponseBytes != 5 || record.ErrorCode != "" || record.Mode != "http" {
		t.Fatalf("incorrect HTTP metadata: %+v", record)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{secret, "private-path", "Authorization", "private-proxy-credential"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("sensitive request data persisted: %s", encoded)
		}
	}
	if len(record.Flags) != 2 {
		t.Fatalf("expected large-payload and unsanctioned-port: %+v", record.Flags)
	}
}

func TestEarlyUpstreamResponseDoesNotWaitForUpload(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			t.Error(err)
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
			t.Error(err)
		}
	}()
	_, server, _, _ := newTestProxy(t, false)
	client, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "POST http://"+upstream.Addr().String()+"/ HTTP/1.1\r\nHost: "+upstream.Addr().String()+"\r\nContent-Length: 1048576\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("early upstream response blocked on an unfinished upload: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 413 {
		t.Fatalf("got %d, want upstream 413", response.StatusCode)
	}
	<-upstreamDone
}

func TestInterruptedChunkedResponseIsNotReportedComplete(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		name := "http"
		if inspect {
			name = "inspected-https"
		}
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n")
				if err != nil {
					t.Error(err)
				}
			}))
			if inspect {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			defer upstream.Close()
			p, server, sink, roots := newTestProxy(t, inspect)
			if inspect {
				p.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
				p.transport.TLSClientConfig.RootCAs.AddCert(upstream.Certificate())
			}
			resp, err := clientFor(t, server.URL, roots).Get(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				t.Fatalf("interrupted upstream response was presented as complete: %q", body)
			}
			if record := sink.wait(t, 1)[0]; record.ErrorCode != "stream-failed" {
				t.Fatalf("stream failure was not recorded: %+v", record)
			}
		})
	}
}

func TestHTTPSInspection(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-End-To-End", "yes")
		io.WriteString(w, "inspected response")
	}))
	defer upstream.Close()
	p, proxyServer, sink, roots := newTestProxy(t, true)
	p.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	p.transport.TLSClientConfig.RootCAs.AddCert(upstream.Certificate())
	client := clientFor(t, proxyServer.URL, roots)
	resp, err := client.Get(upstream.URL + "/secret")
	body := readResponse(t, resp, err)
	if body != "inspected response" || resp.Header.Get("X-End-To-End") != "yes" {
		t.Fatal("inspected response changed")
	}
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Issuer.CommonName != "Traceglass Local Inspection CA" {
		t.Fatal("client did not receive a dynamically signed inspection certificate")
	}
	record := sink.wait(t, 1)[0]
	if record.Mode != "inspected" || record.Method != "GET" || record.Status != 200 || record.ResponseBytes != 18 || record.ErrorCode != "" {
		t.Fatalf("unexpected inspection record: %+v", record)
	}
}

func TestHTTPSInspectionKeepsConnectionAlive(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "reusable")
	}))
	defer upstream.Close()
	p, proxyServer, sink, roots := newTestProxy(t, true)
	p.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	p.transport.TLSClientConfig.RootCAs.AddCert(upstream.Certificate())
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	var previous net.Conn
	for i := range 2 {
		reused := false
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			reused = info.Reused && info.Conn == previous
			if previous == nil {
				previous = info.Conn
				reused = true
			}
		}}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", upstream.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if got := readResponse(t, resp, err); got != "reusable" || !reused {
			t.Fatalf("exchange %d: inspected connection was not reusable: body=%q reused=%v records=%+v", i+1, got, reused, sink.wait(t, i+1))
		}
	}
	sink.wait(t, 2)
}

func TestStreamingResponseArrivesBeforeCompletion(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "last")
	}))
	defer upstream.Close()
	defer unblock()
	_, server, sink, _ := newTestProxy(t, false)
	client := clientFor(t, server.URL, nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first chunk was buffered: %q / %v", first, err)
	}
	unblock()
	last, err := io.ReadAll(resp.Body)
	if err != nil || string(last) != "last" {
		t.Fatalf("stream suffix changed: %q / %v", last, err)
	}
	if record := sink.wait(t, 1)[0]; record.ResponseBytes != 9 {
		t.Fatalf("stream byte count wrong: %+v", record)
	}
}

func TestHTTPSUnlistedDomainTunnels(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "opaque response")
	}))
	defer upstream.Close()
	p, proxyServer, sink, _ := newTestProxy(t, true)
	p.opts.Scope = classify.Scope{"other.test"}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	client := clientFor(t, proxyServer.URL, roots)
	resp, err := client.Get(upstream.URL)
	if got := readResponse(t, resp, err); got != "opaque response" {
		t.Fatalf("unexpected tunnel response: %q", got)
	}
	if resp.TLS.PeerCertificates[0].Issuer.CommonName == "Traceglass Local Inspection CA" {
		t.Fatal("unlisted TLS was intercepted")
	}
	record := sink.wait(t, 1)[0]
	if record.Mode != "tunnel" || record.Method != "CONNECT" || record.RequestBytes == 0 || record.ResponseBytes == 0 {
		t.Fatalf("unexpected tunnel record: %+v", record)
	}
}

func TestInspectionRejectsInvalidUpstreamTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted upstream request was forwarded")
	}))
	defer upstream.Close()
	_, proxyServer, sink, roots := newTestProxy(t, true)
	client := clientFor(t, proxyServer.URL, roots)
	resp, err := client.Get(upstream.URL)
	readResponse(t, resp, err)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted upstream TLS accepted: %d", resp.StatusCode)
	}
	if record := sink.wait(t, 1)[0]; record.ErrorCode != "upstream-failed" {
		t.Fatalf("TLS failure was not recorded: %+v", record)
	}
}

func TestInspectedAuthorityCannotEscapeScope(t *testing.T) {
	_, proxyServer, _, roots := newTestProxy(t, true)
	client := clientFor(t, proxyServer.URL, roots)
	req, err := http.NewRequest("GET", "https://127.0.0.1:443/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "outside-scope.test"
	resp, err := client.Do(req)
	readResponse(t, resp, err)
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("authority mismatch accepted: %d", resp.StatusCode)
	}
}

func TestPrivateDestinationsBlockedByDefault(t *testing.T) {
	p, server, sink, _ := newTestProxy(t, false)
	p.opts.AllowPrivate = false
	client := clientFor(t, server.URL, nil)
	resp, err := client.Get("http://127.0.0.1:9/")
	readResponse(t, resp, err)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("private destination not blocked: %d", resp.StatusCode)
	}
	if sink.wait(t, 1)[0].ErrorCode != "upstream-failed" {
		t.Fatal("private-network denial was not recorded")
	}
	for _, address := range []string{"0.0.0.0:9", "224.0.0.1:9", "[::]:9", "169.254.169.254:80", "[::ffff:127.0.0.1]:9"} {
		if conn, err := p.dial(context.Background(), "tcp", address); err == nil {
			conn.Close()
			t.Errorf("disallowed address accepted: %s", address)
		}
	}
}

func TestProxyClosesIdleTunnels(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	p, server, sink, _ := newTestProxy(t, false)
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(conn, "CONNECT "+upstream.Listener.Addr().String()+" HTTP/1.1\r\nHost: "+upstream.Listener.Addr().String()+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("tunnel failed: %v", err)
	}
	p.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel still open after shutdown")
	}
	sink.wait(t, 1)
}

func TestTargetValidationAndConcurrencyLimit(t *testing.T) {
	for _, authority := range []string{"user:pass@host.test", "host.test/path", "host.test?query", "host.test?", "host.test#", "host.test:", "host.test:0", "host.test:65536", "host.test:abc", "host..test"} {
		if _, err := parseTarget(authority, "443"); err == nil {
			t.Errorf("accepted invalid authority %q", authority)
		}
	}
	p, _, _, _ := newTestProxy(t, false)
	for range cap(p.slots) {
		p.slots <- struct{}{}
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://example.test", nil))
	if w.Code != 503 {
		t.Fatal("concurrency limit not enforced")
	}
}

func TestHijackedBufferedBytesThenRawConnection(t *testing.T) {
	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	reader := bufio.NewReader(strings.NewReader("buffered"))
	if _, err := reader.Peek(8); err != nil {
		t.Fatal(err)
	}
	conn := &bufferedConn{Conn: client, reader: reader}
	data := make([]byte, 32)
	n, err := conn.Read(data)
	if err != nil || string(data[:n]) != "buffered" {
		t.Fatalf("hijacked prefix was lost: %q / %v", data[:n], err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := remote.Write([]byte("raw"))
		written <- err
	}()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(data)
	if err != nil || string(data[:n]) != "raw" {
		t.Fatalf("raw connection was not used after the prefix: %q / %v", data[:n], err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}
