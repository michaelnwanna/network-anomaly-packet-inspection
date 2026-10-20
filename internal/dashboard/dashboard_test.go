package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

func TestDashboardBoundary(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "metadata.db"),
		store.Options{MaxRecords: 100, MaxAge: time.Hour, QueueSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := Handler(db, func() int64 { return 3 }, Config{Token: "test-secret", Host: "127.0.0.1:9090"})
	for _, tc := range []struct {
		name, method, path, host, token, origin string
		status                                  int
	}{
		{"public shell", "GET", "/", "127.0.0.1:9090", "", "", 200},
		{"scripts", "GET", "/app.js", "127.0.0.1:9090", "", "", 200},
		{"stylesheet", "GET", "/style.css", "127.0.0.1:9090", "", "", 200},
		{"missing token", "GET", "/api/status", "127.0.0.1:9090", "", "", 401},
		{"wrong token", "GET", "/api/status", "127.0.0.1:9090", "wrong", "", 401},
		{"rebinding", "GET", "/api/status", "evil.test:9090", "test-secret", "", 403},
		{"cross origin", "GET", "/api/status", "127.0.0.1:9090", "test-secret", "https://evil.test", 403},
		{"same origin", "GET", "/api/status", "127.0.0.1:9090", "test-secret", "http://127.0.0.1:9090", 200},
		{"read only", "POST", "/api/records", "127.0.0.1:9090", "test-secret", "", 405},
		{"array shape", "GET", "/api/records", "127.0.0.1:9090", "test-secret", "", 200},
		{"unbounded limit", "GET", "/api/records?limit=201", "127.0.0.1:9090", "test-secret", "", 400},
		{"invalid limit", "GET", "/api/records?limit=abc", "127.0.0.1:9090", "test-secret", "", 400},
		{"negative cursor", "GET", "/api/records?before=-1", "127.0.0.1:9090", "test-secret", "", 400},
		{"invalid flag", "GET", "/api/records?flagged=yes", "127.0.0.1:9090", "test-secret", "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, nil)
			r.Header.Set("Origin", tc.origin)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") == "" {
				t.Fatal("missing privacy response headers")
			}
			if strings.Contains(w.Body.String(), "test-secret") {
				t.Fatal("dashboard token embedded in public assets or responses")
			}
			if tc.name == "array shape" {
				var result struct {
					Records    []store.Record `json:"records"`
					NextBefore int64          `json:"next_before"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Records == nil || result.NextBefore != 0 {
					t.Fatalf("invalid empty records shape: %s / %v", w.Body, err)
				}
			}
		})
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:9090/api/status", nil)
	r.Header.Set("Authorization", "test-secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("authorization without the Bearer scheme was accepted")
	}
}
