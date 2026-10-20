package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/authority"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/classify"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/dashboard"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/proxy"
	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		slog.Error("traceglass stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := fmt.Fprintln(out, `Traceglass - local-first network anomaly & inspection proxy

Usage:
  traceglass serve [flags]       Start the proxy and local dashboard
  traceglass ca init [flags]     Create a local CA; never installs system trust
  traceglass version            Print build version

Start without a CA to tunnel HTTPS. Use "serve -h" for options.
Only inspect devices and traffic you own or have permission to inspect.`)
		return err
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintln(out, version)
		return err
	case "serve":
		return serve(ctx, args[1:], out, errOut)
	case "ca":
		if len(args) < 2 || args[1] != "init" {
			return errors.New("usage: traceglass ca init [-data-dir ./data]")
		}
		flags := flag.NewFlagSet("ca init", flag.ContinueOnError)
		flags.SetOutput(errOut)
		dir := flags.String("data-dir", "./data", "dedicated directory for local CA and metadata")
		if err := flags.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected ca init arguments")
		}
		if err := authority.Init(*dir); err != nil {
			return err
		}
		_, err := fmt.Fprintf(out, "Local CA created: %s\nPrivate key: %s\nNo trust was installed. Prefer per-client --cacert trust; see README before enabling inspection.\n",
			filepath.Join(*dir, authority.CertFile), filepath.Join(*dir, authority.KeyFile))
		return err
	default:
		return fmt.Errorf("unknown command %q; run traceglass help", args[0])
	}
}

func loopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("listener must be an IP:port pair: %w", err)
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || p < 0 || p > 65535 {
		return errors.New("listeners must use a loopback IP literal and a port between 0 and 65535")
	}
	return nil
}

func serve(ctx context.Context, args []string, out, errOut io.Writer) (result error) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(errOut)
	listen := flags.String("listen", "127.0.0.1:8080", "loopback HTTP proxy listener")
	ui := flags.String("dashboard", "127.0.0.1:9090", "loopback dashboard listener")
	dir := flags.String("data-dir", "./data", "dedicated directory for CA and SQLite files")
	inspect := flags.String("inspect", "", "comma-separated exact hosts or *.domain patterns to inspect")
	rulesFile := flags.String("rules", "", "custom classifier rules JSON (replaces defaults)")
	maxRecords := flags.Int64("max-records", 1_000_000, "maximum retained metadata records")
	maxAge := flags.Duration("max-age", 7*24*time.Hour, "maximum record age")
	queueSize := flags.Int("queue-size", 8192, "bounded metadata queue capacity")
	maxActive := flags.Int("max-active", 256, "maximum concurrent proxy exchanges/tunnels")
	allowPrivate := flags.Bool("allow-private", false, "allow destinations on private/local networks (use with care)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected serve arguments")
	}
	for _, address := range []string{*listen, *ui} {
		if err := loopbackAddress(address); err != nil {
			return err
		}
	}
	if *maxActive < 1 || *maxActive > 4096 || *queueSize < 1 || *queueSize > 1_000_000 || *maxRecords < 1 || *maxAge <= 0 {
		return errors.New("invalid limits: active 1..4096, queue 1..1000000, retention limits must be positive")
	}
	scope, err := classify.ParseScope(*inspect)
	if err != nil {
		return err
	}
	var ca *authority.Authority
	if len(scope) > 0 {
		ca, err = authority.Load(*dir)
		if err != nil {
			return fmt.Errorf("load inspection CA (run traceglass ca init first): %w", err)
		}
	}
	var rules io.Reader
	if *rulesFile != "" {
		file, err := os.Open(*rulesFile)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, file.Close()) }()
		rules = file
	}
	engine, err := classify.Load(rules)
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(*dir, "metadata.db"), store.Options{
		MaxRecords: *maxRecords, MaxAge: *maxAge, QueueSize: *queueSize,
	})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, db.Close()) }()
	p, err := proxy.New(proxy.Options{Scope: scope, CA: ca, Classifier: engine,
		Store: db, AllowPrivate: *allowPrivate, MaxActive: *maxActive})
	if err != nil {
		return err
	}
	defer p.Close()
	proxyListener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("bind proxy: %w", err)
	}
	defer proxyListener.Close()
	uiListener, err := net.Listen("tcp", *ui)
	if err != nil {
		return fmt.Errorf("bind dashboard: %w", err)
	}
	defer uiListener.Close()
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	proxyServer := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return runCtx }}
	uiServer := &http.Server{Handler: dashboard.Handler(db, p.Active, dashboard.Config{
		Token: token, Host: uiListener.Addr().String(), ProxyAddr: proxyListener.Addr().String(),
		Inspect: []string(scope), MaxRecords: *maxRecords, MaxAge: maxAge.String(), AllowPrivate: *allowPrivate,
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return runCtx }}
	serverErrors := make(chan error, 2)
	go func() { serverErrors <- proxyServer.Serve(proxyListener) }()
	go func() { serverErrors <- uiServer.Serve(uiListener) }()
	_, printErr := fmt.Fprintf(out, "Traceglass %s\nProxy: http://%s\nDashboard: http://%s/#token=%s\nHTTPS inspection scope: %v\nData: %s\nOnly use with authorized traffic. Dashboard link is a session secret.\n",
		version, proxyListener.Addr(), uiListener.Addr(), token, []string(scope), *dir)
	if *allowPrivate {
		slog.Warn("private-network destinations enabled; do not proxy untrusted clients")
	}
	if printErr != nil {
		result = printErr
	} else {
		select {
		case <-ctx.Done():
		case err := <-db.Errors():
			result = err
		case err := <-serverErrors:
			result = fmt.Errorf("HTTP listener stopped unexpectedly: %w", err)
		}
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	// Cancellation unblocks upstream work; force-close any slow ordinary clients
	// after the graceful window. Proxy.Close then joins ordinary and hijacked work.
	for _, server := range []*http.Server{uiServer, proxyServer} {
		if err := server.Shutdown(shutdownCtx); err != nil {
			result = errors.Join(result, err, server.Close())
		}
	}
	p.Close()
	return result
}
