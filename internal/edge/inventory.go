package edge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

var localEdge atomic.Pointer[Edge]

type Certificate struct {
	Names       []string  `json:"names"`
	KeyType     string    `json:"key_type"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Source      string    `json:"source"`
	Valid       bool      `json:"valid"`
	Problems    []string  `json:"problems"`
}

type Inventory struct {
	Certificates []Certificate `json:"certificates"`
	MissingNames []string      `json:"missing_names"`
	Errors       []string      `json:"errors"`
}

func (e *Edge) servedNames() []string {
	names := []string{}
	for _, table := range []map[string]int{*e.routes.Load(), *e.postgres.Load()} {
		for name := range table {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func (e *Edge) heldCertificates(ctx context.Context) ([]*tls.Certificate, []string) {
	certs := []*tls.Certificate{}
	problems := []string{}
	e.certs.cache.memory.Range(func(_, value any) bool {
		certs = append(certs, value.(cachedCertificate).cert)
		return true
	})
	entries, err := os.ReadDir(string(e.certs.cache.local))
	if err != nil && !os.IsNotExist(err) {
		problems = append(problems, "certificate directory unreadable")
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if entry.IsDir() {
			problems = append(problems, "unexpected directory in certificate cache")
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "acme_account+key") || strings.HasPrefix(name, "acme_account.key") || strings.Contains(name, "+http-01") || strings.HasSuffix(name, "+token") || strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(string(e.certs.cache.local), name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			problems = append(problems, "certificate file unreadable")
			continue
		}
		public := []byte{}
		rest := data
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				public = append(public, pem.EncodeToMemory(block)...)
			}
			rest = next
		}
		if len(public) == 0 {
			if slices.Contains(e.servedNames(), strings.TrimSuffix(name, "+rsa")) {
				problems = append(problems, "certificate file contains no certificate")
			}
			continue
		}
		cert, err := tls.X509KeyPair(public, data)
		if err != nil {
			cert.Certificate = nil
			for len(public) > 0 {
				block, next := pem.Decode(public)
				if block == nil {
					break
				}
				cert.Certificate = append(cert.Certificate, block.Bytes)
				public = next
			}
		}
		if len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
			certs = append(certs, &cert)
		}
	}
	return certs, problems
}

func (e *Edge) Inventory(ctx context.Context) Inventory {
	result := Inventory{Certificates: []Certificate{}, MissingNames: []string{}, Errors: []string{}}
	certificates, problems := e.heldCertificates(ctx)
	result.Errors = append(result.Errors, problems...)
	seen := map[string]bool{}
	validNames := map[string]bool{}
	for _, pair := range certificates {
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			result.Errors = append(result.Errors, "unreadable certificate")
			continue
		}
		digest := sha256.Sum256(leaf.Raw)
		fingerprint := hex.EncodeToString(digest[:])
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		item := Certificate{Names: leaf.DNSNames, KeyType: strings.ToLower(leaf.PublicKeyAlgorithm.String()), Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.Text(16), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: fingerprint, Source: "local", Valid: true, Problems: []string{}}
		intermediate := x509.NewCertPool()
		for _, der := range pair.Certificate[1:] {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				item.Problems = append(item.Problems, "invalid intermediate")
				continue
			}
			intermediate.AddCert(cert)
		}
		if pair.PrivateKey == nil {
			item.Problems = append(item.Problems, "private key does not match certificate")
		}
		if len(item.Names) == 0 {
			item.Problems = append(item.Problems, "certificate has no DNS names")
		}
		for _, name := range item.Names {
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Intermediates: intermediate}); err != nil {
				item.Problems = append(item.Problems, name+": "+err.Error())
			}
		}
		item.Valid = len(item.Problems) == 0
		if item.Valid {
			for _, name := range e.servedNames() {
				if leaf.VerifyHostname(name) == nil {
					validNames[name] = true
				}
			}
		}
		result.Certificates = append(result.Certificates, item)
	}
	for _, name := range e.servedNames() {
		if !validNames[name] {
			result.MissingNames = append(result.MissingNames, name)
		}
	}
	if ctx.Err() != nil {
		result.Errors = append(result.Errors, "inventory cancelled")
	}
	slices.SortFunc(result.Certificates, func(a, b Certificate) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return result
}

func ServeLocal(w http.ResponseWriter, r *http.Request) {
	e := localEdge.Load()
	if e == nil {
		if r.URL.Path == "/edge/ready" || r.URL.Path == "/edge/certificates/metrics" {
			http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(Inventory{Certificates: []Certificate{}, MissingNames: []string{}, Errors: []string{}})
		return
	}
	if r.URL.Path == "/edge/ready" {
		e.serveReady(w, r)
		return
	}
	if r.URL.Path == "/edge/certificates/metrics" {
		e.serveCertificateMetrics(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(e.Inventory(r.Context()))
}
