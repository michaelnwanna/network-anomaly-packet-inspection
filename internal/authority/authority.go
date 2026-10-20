package authority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const CertFile = "traceglass-ca.crt"
const KeyFile = "traceglass-ca.key"

type Authority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func Init(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, name := range []string{CertFile, KeyFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("%s already exists; refusing to replace CA material", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	id, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: id,
		Subject:      pkix.Name{CommonName: "Traceglass Local Inspection CA"},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.AddDate(2, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, KeyFile)
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		cleanupErr := os.Remove(keyPath)
		return errors.Join(err, cleanupErr)
	}
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

func Load(dir string) (*Authority, error) {
	keyPath := filepath.Join(dir, KeyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("CA private key must not be accessible to group or other users (chmod 600)")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, CertFile), keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("expected an ECDSA certificate-signing CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("CA self-signature: %w", err)
	}
	if time.Now().Before(cert.NotBefore) || time.Until(cert.NotAfter) < time.Minute {
		return nil, errors.New("CA is not currently valid or expires in less than one minute")
	}
	return &Authority{cert: cert, key: key, cache: make(map[string]*tls.Certificate)}, nil
}

func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if pair := a.cache[host]; pair != nil && time.Until(pair.Leaf.NotAfter) > time.Minute {
		return pair, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := serial()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(24 * time.Hour)
	if a.cert.NotAfter.Before(expires) {
		expires = a.cert.NotAfter
	}
	if time.Until(expires) <= 0 {
		return nil, errors.New("inspection CA has expired")
	}
	template := &x509.Certificate{
		SerialNumber: id, Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pair := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key, Leaf: leaf}
	if len(a.cache) >= 256 {
		// Bound memory even when a wildcard scope encounters many distinct hosts.
		clear(a.cache)
	}
	a.cache[host] = pair
	return pair, nil
}
