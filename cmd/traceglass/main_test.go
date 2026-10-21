package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestListenerPolicy(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", ":8080", "localhost:8080", "192.168.1.1:8080", "127.0.0.1:-1", "127.0.0.1:65536"} {
		if err := loopbackAddress(address); err == nil {
			t.Errorf("accepted unsafe listener %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:8080", "[::1]:9090"} {
		if err := loopbackAddress(address); err != nil {
			t.Error(err)
		}
	}
}

func TestCommands(t *testing.T) {
	for _, args := range [][]string{{}, {"help"}, {"version"}, {"serve", "-h"}} {
		if err := run(context.Background(), args, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"ca"}, {"serve", "-inspect", "*"}, {"serve", "-max-active", "0"}, {"serve", "unexpected"}} {
		if err := run(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Errorf("invalid command accepted: %v", args)
		}
	}
	dir := t.TempDir()
	if err := run(context.Background(), []string{"ca", "init", "-data-dir", dir}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"ca", "init", "-data-dir", dir}, io.Discard, io.Discard); err == nil {
		t.Fatal("CA was overwritten")
	}
}

func TestInvalidUpstreamTrust(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(malformed, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing.pem"), malformed} {
		err := run(context.Background(), []string{"serve", "-data-dir", dir, "-upstream-ca", path}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "upstream CA") {
			t.Fatalf("invalid upstream trust did not fail explicitly: %v", err)
		}
	}
}

func TestServeLifecycle(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &lockedBuffer{}
	done := make(chan error, 1)
	stopped := false
	go func() {
		done <- run(ctx, []string{"serve", "-listen", "127.0.0.1:0", "-dashboard", "127.0.0.1:0",
			"-data-dir", dir, "-allow-private"}, out, io.Discard)
	}()
	t.Cleanup(func() {
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("serve did not finish after cancellation")
		}
	})
	var proxyAddr, dashboardLink string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(line, "Proxy: ") {
				proxyAddr = strings.TrimPrefix(line, "Proxy: ")
			}
			if strings.HasPrefix(line, "Dashboard: ") {
				dashboardLink = strings.TrimPrefix(line, "Dashboard: ")
			}
		}
		if proxyAddr != "" && dashboardLink != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if proxyAddr == "" || dashboardLink == "" {
		t.Fatal("listeners did not start or print their endpoints")
	}
	ui, err := url.Parse(dashboardLink)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(ui.Fragment, "token=")
	ui.Fragment = ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "fixture")
	}))
	defer upstream.Close()
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "fixture" || resp.StatusCode != 200 {
		t.Fatalf("proxy not responsive: %q / %v", body, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	localClient := &http.Client{Timeout: 2 * time.Second}
	for {
		req, err := http.NewRequest("GET", ui.String()+"api/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := localClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Records []store.Record `json:"records"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if decodeErr != nil || resp.StatusCode != 200 {
			t.Fatalf("dashboard not responsive: %d / %v", resp.StatusCode, decodeErr)
		}
		if len(page.Records) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("metadata did not become visible through dashboard API")
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not shut down")
	}
	db, err := store.Open(filepath.Join(dir, "metadata.db"), store.Options{
		MaxRecords: 1000, MaxAge: time.Hour, QueueSize: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	records, err := db.List(context.Background(), store.Filter{Limit: 10})
	if err != nil || len(records) != 1 || records[0].ResponseBytes != 7 {
		t.Fatalf("completed flow did not survive shutdown: %+v / %v", records, err)
	}
}
