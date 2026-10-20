package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/authority"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/classify"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

type Sink interface {
	Enqueue(store.Record) error
}

type Options struct {
	Scope        classify.Scope
	CA           *authority.Authority
	Classifier   *classify.Engine
	Store        Sink
	AllowPrivate bool
	MaxActive    int
}

type Proxy struct {
	opts      Options
	transport *http.Transport
	slots     chan struct{}
	active    atomic.Int64
	lastDrop  atomic.Int64
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closing   bool
	handlers  sync.WaitGroup
}

func New(opts Options) (*Proxy, error) {
	if opts.Classifier == nil || opts.Store == nil || opts.MaxActive < 1 {
		return nil, errors.New("proxy requires a classifier, store, and positive connection limit")
	}
	if len(opts.Scope) > 0 && opts.CA == nil {
		return nil, errors.New("inspection scope requires an initialized CA")
	}
	p := &Proxy{opts: opts, slots: make(chan struct{}, opts.MaxActive), conns: make(map[net.Conn]struct{})}
	p.transport = &http.Transport{
		Proxy: nil, DialContext: p.dial,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true, MaxIdleConns: 128, MaxIdleConnsPerHost: 8,
		MaxConnsPerHost: opts.MaxActive, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 1 << 20,
		DisableCompression: true,
	}
	return p, nil
}

func (p *Proxy) Active() int64 { return p.active.Load() }

// Close finishes metadata emission after the outer HTTP server has been stopped.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closing = true
	for conn := range p.conns {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			slog.Warn("close intercepted connection", "error", err)
		}
	}
	p.mu.Unlock()
	p.handlers.Wait()
	p.transport.CloseIdleConnections()
}

func (p *Proxy) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.conns[conn] = struct{}{}
	return true
}

func (p *Proxy) untrack(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		http.Error(w, "proxy is shutting down", http.StatusServiceUnavailable)
		return
	}
	p.handlers.Add(1)
	p.mu.Unlock()
	defer p.handlers.Done()
	if len(r.Method) > 32 {
		http.Error(w, "method exceeds metadata limit", http.StatusBadRequest)
		return
	}
	select {
	case p.slots <- struct{}{}:
		p.active.Add(1)
		defer func() { <-p.slots; p.active.Add(-1) }()
	default:
		http.Error(w, "proxy concurrency limit reached", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
		http.Error(w, "use this endpoint as an explicit HTTP proxy", http.StatusBadRequest)
		return
	}
	target, err := parseTarget(r.URL.Host, "80")
	if err != nil {
		http.Error(w, "invalid destination", http.StatusBadRequest)
		return
	}
	p.exchange(w, r, target, "http", "http")
}

type target struct {
	host string
	port int
	addr string
}

func parseTarget(authority, defaultPort string) (target, error) {
	u, err := url.Parse("http://" + authority)
	if err != nil || u.Host == "" || u.Host != authority || u.User != nil || strings.HasSuffix(authority, ":") {
		return target{}, errors.New("invalid destination authority")
	}
	host := classify.NormalizeHost(u.Hostname())
	if !classify.ValidDomain(host) && net.ParseIP(host) == nil {
		return target{}, errors.New("invalid destination host")
	}
	portText := u.Port()
	if portText == "" {
		portText = defaultPort
	}
	port, err := classify.ParsePort(portText)
	if err != nil {
		return target{}, err
	}
	return target{host: host, port: port, addr: net.JoinHostPort(host, fmt.Sprint(port))}, nil
}

func (p *Proxy) dial(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("destination resolved to no addresses")
	}
	// Validate every DNS answer, then connect to an IP literal to prevent rebinding.
	for _, ip := range ips {
		if ip.Zone != "" || ip.IP.IsUnspecified() || ip.IP.IsMulticast() ||
			!p.opts.AllowPrivate && (ip.IP.IsPrivate() || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast()) {
			return nil, errors.New("destination address disallowed by local-network policy")
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var dialErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	return nil, dialErr
}

type countedBody struct {
	io.ReadCloser
	mu        sync.Mutex
	n         atomic.Int64
	eof       atomic.Bool
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

func (b *countedBody) Read(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := b.ReadCloser.Read(data)
	b.n.Add(int64(n))
	if err == io.EOF {
		b.eof.Store(true)
	}
	return n, err
}

func (b *countedBody) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.ReadCloser.Close()
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
	})
	return b.closeErr
}

func (b *countedBody) Count() int64 {
	return b.n.Load()
}

type flushingWriter struct{ http.ResponseWriter }

func (w flushingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

func responseWriter(w http.ResponseWriter) func(*http.Response) (int64, error) {
	return func(resp *http.Response) (int64, error) {
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return 0, err
		}
		return io.Copy(flushingWriter{w}, resp.Body)
	}
}

func stripHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}

func (p *Proxy) exchange(w http.ResponseWriter, r *http.Request, dest target, scheme, mode string) {
	start := time.Now()
	record := store.Record{Timestamp: start.UnixMilli(), Method: r.Method, Host: dest.host,
		Port: dest.port, Scheme: scheme, Mode: mode}
	defer func() {
		record.DurationMS = time.Since(start).Milliseconds()
		p.record(record)
	}()
	controller := http.NewResponseController(w)
	if err := controller.EnableFullDuplex(); err != nil {
		slog.Error("enable streaming proxy response", "error", err)
		record.Status, record.ErrorCode = http.StatusInternalServerError, "proxy-io-failed"
		http.Error(w, "streaming response unavailable", record.Status)
		return
	}
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.Host = scheme, dest.addr, dest.addr
	out.RequestURI = ""
	out.Close = false
	out.Trailer = nil
	out.Header = r.Header.Clone()
	upgrade := out.Header.Get("Upgrade") != ""
	stripHopHeaders(out.Header)
	body := &countedBody{ReadCloser: http.NoBody}
	if r.Body != nil && r.Body != http.NoBody {
		body.ReadCloser = r.Body
		out.Body = body
	} else {
		out.Body = nil
	}
	var resp *http.Response
	var err error
	if upgrade {
		record.ErrorCode = "upgrade-unsupported"
		resp = errorResponse(r, http.StatusNotImplemented, "protocol upgrades are not supported")
	} else {
		resp, err = p.transport.RoundTrip(out)
		if err != nil {
			record.ErrorCode = "upstream-failed"
			resp = errorResponse(r, http.StatusBadGateway, "upstream connection failed; check destination policy and TLS trust")
		}
	}
	complete := out.Body == nil || body.eof.Load() || r.ContentLength >= 0 && body.Count() >= r.ContentLength
	stripHopHeaders(resp.Header)
	if !complete {
		resp.Header.Set("Connection", "close")
	}
	record.Status = resp.StatusCode
	record.ResponseBytes, err = responseWriter(w)(resp)
	streamFailed := err != nil
	if err != nil {
		record.ErrorCode = "stream-failed"
	}
	if err := resp.Body.Close(); err != nil && record.ErrorCode == "" {
		record.ErrorCode = "response-body-failed"
	}
	// Return early upstream rejections before stopping an unfinished upload.
	// Interrupt pending reads so Transport's asynchronous Body.Close cannot stall.
	if !complete {
		if err := controller.SetReadDeadline(time.Now()); err != nil {
			slog.Warn("interrupt unfinished upload", "error", err)
			if record.ErrorCode == "" {
				record.ErrorCode = "proxy-io-failed"
			}
		}
	}
	if err := body.Close(); err != nil && record.ErrorCode == "" {
		record.ErrorCode = "request-body-failed"
	}
	record.RequestBytes = body.Count()
	if streamFailed {
		// Do not let net/http emit a successful terminal chunk for a partial stream.
		panic(http.ErrAbortHandler)
	}
}

func errorResponse(r *http.Request, status int, message string) *http.Response {
	body := message + "\n"
	return &http.Response{StatusCode: status, Status: http.StatusText(status),
		ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}
}

func (p *Proxy) record(record store.Record) {
	record.Flags = p.opts.Classifier.Flags(record.Host, record.Port, record.RequestBytes, record.ResponseBytes)
	if err := p.opts.Store.Enqueue(record); err != nil {
		now := time.Now().Unix()
		last := p.lastDrop.Load()
		if now-last >= 5 && p.lastDrop.CompareAndSwap(last, now) {
			slog.Error("metadata not persisted; inspect dropped counter and storage health", "error", err)
		}
	}
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	dest, err := parseTarget(r.Host, "443")
	if err != nil {
		http.Error(w, "invalid CONNECT destination", http.StatusBadRequest)
		return
	}
	inspect := p.opts.Scope.Matches(dest.host)
	var upstream net.Conn
	var cert *tls.Certificate
	if inspect {
		cert, err = p.opts.CA.Certificate(dest.host)
	} else {
		upstream, err = p.dial(r.Context(), "tcp", dest.addr)
	}
	if err != nil {
		p.record(store.Record{Timestamp: time.Now().UnixMilli(), Method: "CONNECT", Scheme: "https",
			Host: dest.host, Port: dest.port, Mode: "tunnel", Status: 502, ErrorCode: "connect-failed"})
		http.Error(w, "CONNECT failed; check destination policy", http.StatusBadGateway)
		return
	}
	if upstream != nil {
		defer upstream.Close()
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	client, buffer, err := hijacker.Hijack()
	if err != nil {
		slog.Warn("hijack CONNECT connection", "error", err)
		return
	}
	defer client.Close()
	if !p.track(client) {
		return
	}
	defer p.untrack(client)
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	conn := &bufferedConn{Conn: client, reader: buffer.Reader}
	if inspect {
		p.inspect(r.Context(), conn, dest, cert)
	} else {
		p.tunnel(conn, upstream, dest)
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if c.reader.Buffered() > 0 {
		return c.reader.Read(b)
	}
	// Once hijacked bytes are drained, bypass the old HTTP server's connReader.
	// Its timeout handling would cancel CONNECT during inner keep-alive reads.
	return c.Conn.Read(b)
}

type idleConn struct{ net.Conn }

func (c idleConn) Read(b []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c idleConn) Write(b []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (p *Proxy) tunnel(client, upstream net.Conn, dest target) {
	start := time.Now()
	type result struct {
		bytes int64
		err   error
	}
	sent := make(chan result, 1)
	go func() {
		n, err := io.Copy(idleConn{upstream}, idleConn{client})
		if closer, ok := upstream.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		}
		if err != nil {
			upstream.Close()
		}
		sent <- result{n, err}
	}()
	received, receiveErr := io.Copy(idleConn{client}, idleConn{upstream})
	// Closing the client releases a copy blocked on a stalled local sender.
	client.Close()
	upload := <-sent
	record := store.Record{Timestamp: start.UnixMilli(), Method: "CONNECT", Host: dest.host,
		Port: dest.port, Scheme: "https", Mode: "tunnel", Status: 200,
		RequestBytes: upload.bytes, ResponseBytes: received, DurationMS: time.Since(start).Milliseconds()}
	if receiveErr != nil || upload.err != nil && !errors.Is(upload.err, net.ErrClosed) {
		record.ErrorCode = "tunnel-io"
	}
	p.record(record)
}

func (p *Proxy) inspect(ctx context.Context, conn net.Conn, dest target, cert *tls.Certificate) {
	start := time.Now()
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
	})
	defer tlsConn.Close()
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := tlsConn.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		p.record(store.Record{Timestamp: start.UnixMilli(), Method: "CONNECT", Host: dest.host, Port: dest.port,
			Scheme: "https", Mode: "inspected", Status: 502, ErrorCode: "client-tls-failed",
			DurationMS: time.Since(start).Milliseconds()})
		return
	}
	p.serveInspected(ctx, tlsConn, dest)
}

type singleListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
	used bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return &signalConn{Conn: l.conn, listener: l}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }

type signalConn struct {
	net.Conn
	listener *singleListener
}

func (c *signalConn) Close() error {
	err := c.Conn.Close()
	c.listener.Close()
	return err
}

func (p *Proxy) serveInspected(ctx context.Context, conn net.Conn, dest target) {
	listener := &singleListener{conn: conn, done: make(chan struct{})}
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
		BaseContext:    func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Method) > 32 {
				http.Error(w, "method exceeds metadata limit", http.StatusBadRequest)
				return
			}
			actual, err := parseTarget(r.Host, "443")
			if err != nil || actual != dest || r.URL.IsAbs() || r.Method == http.MethodConnect {
				http.Error(w, "request authority must match the inspected CONNECT destination", http.StatusMisdirectedRequest)
				return
			}
			p.exchange(w, r, dest, "https", "inspected")
		}),
	}
	err := server.Serve(listener)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		slog.Warn("inspected HTTP server failed", "error", err)
	}
	if err := server.Close(); err != nil {
		slog.Warn("close inspected HTTP server", "error", err)
	}
}
