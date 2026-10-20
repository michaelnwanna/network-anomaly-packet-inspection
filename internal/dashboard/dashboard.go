package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/michaelnwanna/network-anomaly-packet-inspection/internal/store"
)

//go:embed web/*
var assets embed.FS

type Config struct {
	Token        string
	Host         string
	ProxyAddr    string
	Inspect      []string
	MaxRecords   int64
	MaxAge       string
	AllowPrivate bool
}

func Handler(db *store.Store, active func() int64, config Config) http.Handler {
	web, err := fs.Sub(assets, "web")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(web))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"stats": db.Stats(), "active": active(), "proxy": config.ProxyAddr,
			"inspect": config.Inspect, "max_records": config.MaxRecords,
			"max_age": config.MaxAge, "allow_private": config.AllowPrivate,
		})
	})
	mux.HandleFunc("GET /api/records", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		limit := 100
		var before int64
		var err error
		if query.Has("limit") {
			limit, err = strconv.Atoi(query.Get("limit"))
			if err != nil || limit < 1 || limit > 200 {
				http.Error(w, "limit must be between 1 and 200", http.StatusBadRequest)
				return
			}
		}
		if query.Has("before") {
			before, err = strconv.ParseInt(query.Get("before"), 10, 64)
			if err != nil || before < 1 {
				http.Error(w, "before must be a positive record ID", http.StatusBadRequest)
				return
			}
		}
		flagged := query.Get("flagged")
		host := strings.ToLower(query.Get("host"))
		if len(host) > 253 || flagged != "" && flagged != "true" && flagged != "false" {
			http.Error(w, "invalid host or flagged filter", http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		records, err := db.List(ctx, store.Filter{Limit: limit, Before: before, Host: host, Flagged: flagged == "true"})
		if err != nil {
			slog.Error("query metadata", "error", err)
			http.Error(w, "metadata query failed", http.StatusInternalServerError)
			return
		}
		var next int64
		if len(records) == limit {
			next = records[len(records)-1].ID
		}
		writeJSON(w, map[string]any{"records": records, "next_before": next})
	})
	mux.Handle("/", files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != config.Host {
			http.Error(w, "unexpected dashboard host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+config.Host {
			http.Error(w, "cross-origin access denied", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if config.Token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+config.Token)) != 1 {
				http.Error(w, "dashboard bearer token required", http.StatusUnauthorized)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "read-only API", http.StatusMethodNotAllowed)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("write dashboard response", "error", err)
	}
}
