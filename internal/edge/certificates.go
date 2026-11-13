package edge

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type certificateManager struct {
	cache     *certificateCache
	policy    autocert.HostPolicy
	client    *acme.Client
	accountMu sync.Mutex
	names     sync.Map
}

func (m *certificateManager) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: m.GetCertificate}
}

func (m *certificateManager) load(ctx context.Context, name string) (*tls.Certificate, error) {
	data, err := m.cache.Get(ctx, name)
	if err == nil {
		return validCertificate(data, name)
	}
	data, rsaErr := m.cache.Get(ctx, name+"+rsa")
	if rsaErr == nil {
		return validCertificate(data, name)
	}
	return nil, err
}

func (m *certificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	ctx, cancel := context.WithTimeout(hello.Context(), issueBudget)
	defer cancel()
	if err := m.policy(ctx, name); err != nil {
		return nil, err
	}
	if cert, err := m.load(ctx, name); err == nil {
		return cert, nil
	}
	if err := m.ensure(ctx, name); err != nil {
		if errors.Is(err, errIssueHeld) {
			return m.wait(ctx, name)
		}
		return nil, err
	}
	return m.load(ctx, name)
}

func renewCertificate(cert *tls.Certificate) bool {
	window := min(30*24*time.Hour, cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)/3)
	return time.Until(cert.Leaf.NotAfter) <= window
}

func (m *certificateManager) account(ctx context.Context) (*acme.Client, error) {
	m.accountMu.Lock()
	defer m.accountMu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	data, err := m.cache.local.Get(ctx, "acme_account+key")
	var key crypto.Signer
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("edge: invalid ACME account key")
		}
		parsed, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		key = parsed
	} else if errors.Is(err, autocert.ErrCacheMiss) {
		generated, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return nil, genErr
		}
		key = generated
		der, marshalErr := x509.MarshalECPrivateKey(generated)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if err = m.cache.local.Put(ctx, "acme_account+key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: acme.LetsEncryptURL}
	if _, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, err
	}
	m.client = client
	return client, nil
}

func (m *certificateManager) ensure(ctx context.Context, name string) error {
	value, _ := m.names.LoadOrStore(name, new(sync.Mutex))
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	if cert, err := m.load(ctx, name); err == nil && !renewCertificate(cert) {
		return nil
	}
	issue, release, err := m.cache.lease(ctx, name)
	if err != nil {
		return err
	}
	defer release()
	if cert, err := m.load(issue, name); err == nil && !renewCertificate(cert) {
		return nil
	}
	client, err := m.account(issue)
	if err != nil {
		return err
	}
	data, err := m.issue(issue, client, name)
	if err != nil {
		return err
	}
	if err := issue.Err(); err != nil {
		return err
	}
	return m.cache.Put(issue, name, data)
}

func (m *certificateManager) issue(ctx context.Context, client *acme.Client, name string) ([]byte, error) {
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return nil, err
	}
	for _, location := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, location)
		if err != nil {
			return nil, err
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate.Type == "http-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return nil, errors.New("edge: authority offered no HTTP-01 challenge")
		}
		token, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return nil, err
		}
		m.cache.mu.Lock()
		tokens := m.cache.tokens
		m.cache.mu.Unlock()
		revision, err := tokens.Put(ctx, cacheKey(challenge.Token), []byte(token))
		if err != nil {
			return nil, err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tokens.Delete(cleanup, cacheKey(challenge.Token), jetstream.LastRevision(revision))
		}()
		if _, err = client.Accept(ctx, challenge); err != nil {
			return nil, err
		}
		if _, err = client.WaitAuthorization(ctx, location); err != nil {
			return nil, err
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return nil, err
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
	for _, cert := range chain {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})...)
	}
	if _, err := validCertificate(data, name); err != nil {
		return nil, fmt.Errorf("edge: issued certificate invalid: %w", err)
	}
	return data, nil
}

func (e *Edge) reconcileCertificates(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		names := map[string]bool{}
		for host := range *e.routes.Load() {
			names[host] = true
		}
		for host := range *e.postgres.Load() {
			names[host] = true
		}
		for name := range names {
			if ctx.Err() != nil {
				return
			}
			if err := e.certs.ensure(ctx, name); err != nil && !errors.Is(err, errIssueHeld) {
				slog.WarnContext(ctx, "edge certificate unavailable", "name", name, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-e.certRoutes:
		case <-tick.C:
		}
	}
}

func (m *certificateManager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isChallenge(r) {
			if fallback != nil {
				fallback.ServeHTTP(w, r)
				return
			}
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusFound)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := m.cache.open(r.Context()); err != nil {
			http.Error(w, "certificate store unavailable", http.StatusServiceUnavailable)
			return
		}
		m.cache.mu.Lock()
		reader := m.cache.reader
		m.cache.mu.Unlock()
		token, err := reader.GetLastMsg("KV_edge-cert-tokens", "$KV.edge-cert-tokens."+cacheKey(strings.TrimPrefix(r.URL.Path, challengePath)), nats.Context(r.Context()))
		if err != nil || token.Header.Get("KV-Operation") != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(token.Data)
	})
}

func (m *certificateManager) wait(ctx context.Context, name string) (*tls.Certificate, error) {
	m.cache.mu.Lock()
	certs := m.cache.certs
	m.cache.mu.Unlock()
	watch, err := certs.Watch(ctx, cacheKey(name))
	if err != nil {
		return nil, err
	}
	defer watch.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case entry, ok := <-watch.Updates():
			if !ok {
				return nil, errors.New("edge: certificate watch closed")
			}
			if entry != nil && entry.Operation() == jetstream.KeyValuePut {
				if cert, err := m.load(ctx, name); err == nil {
					return cert, nil
				}
			}
		}
	}
}
