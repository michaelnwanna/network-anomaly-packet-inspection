package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
	_ "modernc.org/sqlite"
)

var ErrQueueFull = errors.New("metadata queue full")
var ErrClosed = errors.New("metadata store closed")

type Record struct {
	ID            int64    `json:"id"`
	Timestamp     int64    `json:"timestamp"`
	Method        string   `json:"method"`
	Scheme        string   `json:"scheme"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Mode          string   `json:"mode"`
	Status        int      `json:"status"`
	RequestBytes  int64    `json:"request_bytes"`
	ResponseBytes int64    `json:"response_bytes"`
	DurationMS    int64    `json:"duration_ms"`
	Flags         []string `json:"flags"`
	ErrorCode     string   `json:"error_code"`
}

type Stats struct {
	Records       int64  `json:"records"`
	Flagged       int64  `json:"flagged"`
	RequestBytes  int64  `json:"request_bytes"`
	ResponseBytes int64  `json:"response_bytes"`
	Dropped       uint64 `json:"dropped"`
	Queued        int    `json:"queued"`
}

type Options struct {
	MaxRecords int64
	MaxAge     time.Duration
	QueueSize  int
}

type Store struct {
	db        *sql.DB
	opts      Options
	queue     chan Record
	done      chan struct{}
	errors    chan error
	mu        sync.RWMutex
	closed    bool
	writeErr  error
	statsMu   sync.RWMutex
	stats     Stats
	dropped   atomic.Uint64
	lock      *flock.Flock
	closeOnce sync.Once
	closeErr  error
}

func Open(path string, opts Options) (opened *Store, openErr error) {
	if opts.MaxRecords < 1 || opts.MaxAge <= 0 || opts.QueueSize < 1 {
		return nil, errors.New("positive retention and queue limits are required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock := flock.New(path + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock database: %w", err)
	}
	if !locked {
		return nil, errors.New("data directory is already in use by another Traceglass process")
	}
	releaseLock := true
	defer func() {
		if releaseLock {
			openErr = errors.Join(openErr, lock.Unlock())
		}
	}()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: path}
	q := u.Query()
	for _, pragma := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if version > 1 {
		return nil, errors.Join(fmt.Errorf("unsupported database schema version %d", version), db.Close())
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS records (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 timestamp INTEGER NOT NULL, method TEXT NOT NULL, scheme TEXT NOT NULL,
 host TEXT NOT NULL, port INTEGER NOT NULL, mode TEXT NOT NULL, status INTEGER NOT NULL,
 request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
 flags TEXT NOT NULL, flagged INTEGER NOT NULL, error_code TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS records_timestamp ON records(timestamp);
CREATE INDEX IF NOT EXISTS records_flagged_id ON records(flagged, id);
PRAGMA user_version = 1;`)
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	s := &Store{db: db, opts: opts, queue: make(chan Record, opts.QueueSize),
		done: make(chan struct{}), errors: make(chan error, 1), lock: lock}
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(flagged),0),
 COALESCE(SUM(request_bytes),0), COALESCE(SUM(response_bytes),0) FROM records`).
		Scan(&s.stats.Records, &s.stats.Flagged, &s.stats.RequestBytes, &s.stats.ResponseBytes); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := s.flush(nil); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	go s.run()
	releaseLock = false
	return s, nil
}

func (s *Store) Errors() <-chan error { return s.errors }

func (s *Store) Enqueue(r Record) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	select {
	case s.queue <- r:
		return nil
	default:
		s.dropped.Add(1)
		return ErrQueueFull
	}
}

func (s *Store) Stats() Stats {
	s.statsMu.RLock()
	stats := s.stats
	s.statsMu.RUnlock()
	stats.Dropped = s.dropped.Load()
	stats.Queued = len(s.queue)
	return stats
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if !s.closed {
			s.closed = true
			close(s.queue)
		}
		s.mu.Unlock()
		<-s.done
		s.closeErr = errors.Join(s.writeErr, s.db.Close(), s.lock.Unlock())
	})
	return s.closeErr
}

func (s *Store) run() {
	defer close(s.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	batch := make([]Record, 0, 256)
	lastPrune := time.Now()
	for {
		select {
		case r, ok := <-s.queue:
			if !ok {
				s.fail(s.flush(batch))
				return
			}
			batch = append(batch, r)
			if len(batch) < cap(batch) {
				continue
			}
		case <-tick.C:
			if len(batch) == 0 && time.Since(lastPrune) < time.Minute {
				continue
			}
		}
		if err := s.flush(batch); err != nil {
			s.fail(err)
			return
		}
		clear(batch)
		batch = batch[:0]
		lastPrune = time.Now()
	}
}

func (s *Store) fail(err error) {
	if err == nil {
		return
	}
	s.writeErr = fmt.Errorf("persist metadata: %w", err)
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	s.errors <- s.writeErr
}

func (s *Store) flush(batch []Record) (err error) {
	s.statsMu.RLock()
	stats := s.stats
	s.statsMu.RUnlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	if len(batch) > 0 {
		stmt, prepareErr := tx.Prepare(`INSERT INTO records
 (timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,flagged,error_code)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if prepareErr != nil {
			return prepareErr
		}
		for _, r := range batch {
			if r.Flags == nil {
				r.Flags = []string{}
			}
			flags, marshalErr := json.Marshal(r.Flags)
			if marshalErr != nil {
				return errors.Join(marshalErr, stmt.Close())
			}
			_, execErr := stmt.Exec(r.Timestamp, r.Method, r.Scheme, r.Host, r.Port, r.Mode,
				r.Status, r.RequestBytes, r.ResponseBytes, r.DurationMS, string(flags), len(r.Flags) > 0, r.ErrorCode)
			if execErr != nil {
				return errors.Join(execErr, stmt.Close())
			}
			stats.Records++
			stats.RequestBytes += r.RequestBytes
			stats.ResponseBytes += r.ResponseBytes
			if len(r.Flags) > 0 {
				stats.Flagged++
			}
		}
		if err := stmt.Close(); err != nil {
			return err
		}
	}
	if err := subtractAndDelete(tx, &stats, "timestamp < ?", time.Now().Add(-s.opts.MaxAge).UnixMilli()); err != nil {
		return err
	}
	if excess := stats.Records - s.opts.MaxRecords; excess > 0 {
		if err := subtractAndDelete(tx, &stats, "id IN (SELECT id FROM records ORDER BY id LIMIT ?)", excess); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.statsMu.Lock()
	s.stats = stats
	s.statsMu.Unlock()
	return nil
}

func subtractAndDelete(tx *sql.Tx, stats *Stats, where string, arg any) error {
	var removed Stats
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(flagged),0),
 COALESCE(SUM(request_bytes),0), COALESCE(SUM(response_bytes),0) FROM records WHERE `+where, arg).
		Scan(&removed.Records, &removed.Flagged, &removed.RequestBytes, &removed.ResponseBytes); err != nil {
		return err
	}
	if removed.Records == 0 {
		return nil
	}
	if _, err := tx.Exec("DELETE FROM records WHERE "+where, arg); err != nil {
		return err
	}
	stats.Records -= removed.Records
	stats.Flagged -= removed.Flagged
	stats.RequestBytes -= removed.RequestBytes
	stats.ResponseBytes -= removed.ResponseBytes
	return nil
}

type Filter struct {
	Before  int64
	Limit   int
	Host    string
	Flagged bool
}

func (s *Store) List(ctx context.Context, filter Filter) ([]Record, error) {
	if filter.Limit < 1 || filter.Limit > 200 || filter.Before < 0 || len(filter.Host) > 253 {
		return nil, errors.New("invalid metadata filter")
	}
	query := `SELECT id,timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,error_code FROM records WHERE 1=1`
	args := []any{}
	if filter.Before > 0 {
		query += " AND id < ?"
		args = append(args, filter.Before)
	}
	if filter.Host != "" {
		query += " AND instr(host, ?) > 0"
		args = append(args, filter.Host)
	}
	if filter.Flagged {
		query += " AND flagged = 1"
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, filter.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]Record, 0, filter.Limit)
	for rows.Next() {
		var r Record
		var flags string
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.Method, &r.Scheme, &r.Host, &r.Port,
			&r.Mode, &r.Status, &r.RequestBytes, &r.ResponseBytes, &r.DurationMS, &flags, &r.ErrorCode); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(flags), &r.Flags); err != nil {
			return nil, fmt.Errorf("decode stored flags: %w", err)
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
