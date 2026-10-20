package authority

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAuthorityLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err == nil {
		t.Fatal("CA initialization must not overwrite existing identity")
	}
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	for _, host := range []string{"example.test", "127.0.0.1", "::1"} {
		pair, err := a.Certificate(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Fatal(err)
		}
		if time.Until(pair.Leaf.NotAfter) > 24*time.Hour {
			t.Fatal("leaf validity exceeds 24 hours")
		}
		cached, err := a.Certificate(host)
		if err != nil || cached != pair {
			t.Fatal("leaf certificate was not cached")
		}
	}
	if err := os.Chmod(filepath.Join(dir, KeyFile), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("world-readable private key accepted")
	}
}

func TestConcurrentCertificateGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Certificate("concurrent.test"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
