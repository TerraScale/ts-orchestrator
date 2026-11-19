package mesh

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"time"
)

// leafLifetime bounds a node certificate; handshakes re-issue it at half life.
const leafLifetime = 24 * time.Hour

// CA is the mesh certificate authority every node derives from the shared
// Vault secret. Gateways and the public client listener trust only it.
type CA struct {
	Cert *x509.Certificate
	key  ed25519.PrivateKey
}

// DeriveCA builds the CA from the shared secret. Every input is fixed, so
// every node derives the byte-identical certificate.
func DeriveCA(secret []byte) (*CA, error) {
	if len(secret) < 32 {
		return nil, errors.New("mesh secret must hold at least 32 bytes")
	}
	seed, err := hkdf.Key(sha256.New, secret, nil, "ts-orch mesh ca v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(seed)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ts-orch mesh CA"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	// Ed25519 signatures are deterministic, so the reader is never consulted.
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: key}, nil
}

// Issue signs a fresh leaf for name, valid as TLS server and client.
func (ca *CA) Issue(name string, now time.Time) (*tls.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, public, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}, nil
}

// TLS returns a config for both ends of every mesh connection: it presents
// a leaf of name, re-issued at half life, and accepts only peers the CA signed.
func (ca *CA) TLS(name string) *tls.Config {
	var mu sync.Mutex
	var leaf *tls.Certificate
	current := func() (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if leaf == nil || now.After(leaf.Leaf.NotAfter.Add(-leafLifetime/2)) {
			next, err := ca.Issue(name, now)
			if err != nil {
				return nil, err
			}
			leaf = next
		}
		return leaf, nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetCertificate:       func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current() },
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return current() },
		ClientAuth:           tls.RequireAndVerifyClientCert,
		ClientCAs:            roots,
		// Gateways dial region DNS names and gossiped IPs; any mesh node can
		// mint any name, so trust is the CA chain, checked in VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("mesh peer presented no certificate")
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			return err
		},
	}
}
