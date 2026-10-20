package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func options() Options {
	return Options{MaxRecords: 1000, MaxAge: time.Hour, QueueSize: 1024}
}

func TestPersistenceRetentionAndFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	opts := options()
	opts.MaxRecords = 3
	db, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		r := Record{Timestamp: time.Now().UnixMilli(), Host: fmt.Sprintf("host%d.test", i),
			RequestBytes: 10, ResponseBytes: 20, Method: "GET"}
		if i%2 == 0 {
			r.Flags = []string{"known-tracker"}
		}
		if err := db.Enqueue(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Enqueue(Record{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("enqueue after close: %v", err)
	}
	db, err = Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stats := db.Stats()
	if stats.Records != 3 || stats.Flagged != 1 || stats.RequestBytes != 30 || stats.ResponseBytes != 60 {
		t.Fatalf("incorrect retained stats: %+v", stats)
	}
	rows, err := db.List(context.Background(), Filter{Limit: 2})
	if err != nil || len(rows) != 2 || rows[0].Host != "host5.test" || rows[1].Host != "host4.test" {
		t.Fatalf("unexpected first page: %+v, %v", rows, err)
	}
	rows, err = db.List(context.Background(), Filter{Limit: 2, Before: rows[1].ID})
	if err != nil || len(rows) != 1 || rows[0].Host != "host3.test" {
		t.Fatalf("unexpected cursor page: %+v, %v", rows, err)
	}
	rows, err = db.List(context.Background(), Filter{Limit: 10, Flagged: true, Host: "host4"})
	if err != nil || len(rows) != 1 || len(rows[0].Flags) != 1 {
		t.Fatalf("unexpected filtered page: %+v, %v", rows, err)
	}
	if _, err := db.List(context.Background(), Filter{Limit: 201}); err == nil {
		t.Fatal("unbounded limit accepted")
	}
}

func TestAgeRetentionAndExclusiveWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	db, err := Open(path, options())
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path, options()); err == nil {
		other.Close()
		t.Fatal("second writer accepted")
	}
	if err := db.Enqueue(Record{Timestamp: time.Now().Add(-2 * time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if db.Stats().Records != 0 {
		t.Fatal("expired metadata retained")
	}
}

func TestBoundedQueue(t *testing.T) {
	s := &Store{queue: make(chan Record, 1)}
	if err := s.Enqueue(Record{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(Record{}); !errors.Is(err, ErrQueueFull) || s.Stats().Dropped != 1 {
		t.Fatalf("queue overflow must be observable: %v, %+v", err, s.Stats())
	}
}

func TestConcurrentEnqueueAndClose(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "metadata.db"), options())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				err := db.Enqueue(Record{Timestamp: time.Now().UnixMilli()})
				if err != nil && !errors.Is(err, ErrClosed) {
					t.Error(err)
				}
			}
		}()
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestWriterFailureIsFatal(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "metadata.db"), options())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	if err := db.Enqueue(Record{Timestamp: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-db.Errors():
		if err == nil {
			t.Fatal("nil writer error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer failure was not surfaced")
	}
	if err := db.Close(); err == nil {
		t.Fatal("close must report persistence failure")
	}
}

func stopWriter(db *Store) {
	db.mu.Lock()
	db.closed = true
	close(db.queue)
	db.mu.Unlock()
	<-db.done
}

func benchmarkBatch() []Record {
	batch := make([]Record, 256)
	for i := range batch {
		batch[i] = Record{Timestamp: time.Now().UnixMilli(), Host: "example.test",
			Method: "GET", Scheme: "https", Port: 443, Mode: "inspected", Flags: []string{}}
	}
	return batch
}

func BenchmarkBatchedPersistence(b *testing.B) {
	opts := options()
	opts.MaxRecords = 1_000_000
	db, err := Open(filepath.Join(b.TempDir(), "bench.db"), opts)
	if err != nil {
		b.Fatal(err)
	}
	stopWriter(db)
	b.Cleanup(func() {
		if err := db.Close(); err != nil {
			b.Error(err)
		}
	})
	batch := benchmarkBatch()
	b.ResetTimer()
	for range b.N {
		if err := db.flush(batch); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N*len(batch))/b.Elapsed().Seconds(), "records/s")
}

func TestMillionRecordRetention(t *testing.T) {
	if os.Getenv("TRACEGLASS_SCALE_TEST") != "1" {
		t.Skip("set TRACEGLASS_SCALE_TEST=1 to exercise million-row persistence")
	}
	opts := options()
	opts.MaxRecords = 1_000_000
	db, err := Open(filepath.Join(t.TempDir(), "scale.db"), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stopWriter(db)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	batch := benchmarkBatch()
	const batches = 3908
	for range batches {
		if err := db.flush(batch); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	stats := db.Stats()
	var actualRows, oldestID int64
	if err := db.db.QueryRow("SELECT COUNT(*), MIN(id) FROM records").Scan(&actualRows, &oldestID); err != nil {
		t.Fatal(err)
	}
	if actualRows != 1_000_000 || stats.Records != actualRows || oldestID != batches*256-999999 {
		t.Fatalf("retention bound not enforced: stats=%+v rows=%d oldest=%d", stats, actualRows, oldestID)
	}
	rows, err := db.List(context.Background(), Filter{Limit: 1})
	if err != nil || len(rows) != 1 || rows[0].ID != batches*256 {
		t.Fatalf("unexpected latest record: %+v, %v", rows, err)
	}
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if growth > 128<<20 {
		t.Fatalf("retained Go heap grew by %d bytes; budget is 128 MiB", growth)
	}
	t.Logf("inserted=%d retained=%d elapsed=%s retained-Go-heap-growth=%d bytes",
		batches*256, stats.Records, time.Since(start), growth)
}
