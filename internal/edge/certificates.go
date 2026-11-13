package edge

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

func (m *certificateManager) load(name string) (*tls.Certificate, error) {
	for _, key := range []string{name, name + "+rsa"} {
		if value, ok := m.cache.memory.Load(key); ok {
			cert := value.(cachedCertificate).cert
			now := time.Now()
			if !now.Before(cert.Leaf.NotBefore) && now.Before(cert.Leaf.NotAfter) {
				return cert, nil
			}
		}
	}
	return nil, autocert.ErrCacheMiss
}

func (m *certificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if err := m.policy(hello.Context(), name); err != nil {
		return nil, err
	}
	for _, key := range []string{name, name + "+rsa"} {
		if value, ok := m.cache.memory.Load(key); ok {
			cert := value.(cachedCertificate).cert
			now := time.Now()
			if !now.Before(cert.Leaf.NotBefore) && now.Before(cert.Leaf.NotAfter) && hello.SupportsCertificate(cert) == nil {
				return cert, nil
			}
		}
	}
	return nil, autocert.ErrCacheMiss
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
	client := &acme.Client{Key: key, DirectoryURL: acme.LetsEncryptURL, RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 }}
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
	var result error
	for _, key := range []string{name, name + "+rsa"} {
		if err := m.ensureVariant(ctx, key); err != nil && !errors.Is(err, errIssueHeld) && !errors.Is(err, errUnsupportedCertificate) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (m *certificateManager) ensureVariant(ctx context.Context, key string) error {
	lock := m.cache.variantLock(key)
	lock.Lock()
	defer lock.Unlock()
	if err := m.cache.reconcileLocked(ctx, key); err != nil {
		return err
	}
	if value, exists := m.cache.memory.Load(key); exists {
		if !renewCertificate(value.(cachedCertificate).cert) {
			return nil
		}
	} else if _, variant := certificateVariant(key); variant == "rsa" {
		if _, required := m.cache.required.Load(key); !required {
			return nil
		}
	}
	if err := m.cache.orderEvidence(ctx, key); err != nil {
		return err
	}
	lease, err := m.cache.lease(ctx, key)
	if err != nil {
		return err
	}
	client, err := m.account(lease.ctx)
	var data []byte
	if err == nil {
		data, err = m.issue(lease.ctx, client, key)
	}
	if err != nil {
		now := time.Now()
		retry := certificateRetry{lease.reserved.Attempt, retryDeadline(lease.reserved.Attempt, now), now}
		var authority *acme.Error
		if errors.As(err, &authority) {
			header := authority.Header.Get("Retry-After")
			if seconds, parseErr := strconv.ParseInt(header, 10, 64); parseErr == nil && seconds > 0 {
				if seconds > int64(time.Until(retry.Next)/time.Second) {
					retry.Next = now.Add(time.Duration(min(seconds, int64((1<<63-1)/int64(time.Second)))) * time.Second)
				}
			} else if deadline, parseErr := http.ParseTime(header); parseErr == nil && deadline.After(retry.Next) {
				retry.Next = deadline
			}
		}
		name, variant := certificateVariant(key)
		slog.Warn("edge certificate order failed", "name", name, "variant", variant, "attempt", retry.Attempt, "next_attempt", retry.Next.UTC().Format(time.RFC3339Nano), "failed_at", now.UTC().Format(time.RFC3339Nano), "error", err)
		counter, _ := m.cache.failures.LoadOrStore(key, new(atomic.Uint64))
		counter.(*atomic.Uint64).Add(1)
		state := m.cache.state(key)
		state.Retry = retry
		diskErr := m.cache.saveRetry(context.Background(), key, retry)
		diskErr = errors.Join(diskErr, m.cache.saveState(context.Background(), key, state))
		finishErr := lease.finish(nil, retry)
		return errors.Join(err, diskErr, finishErr)
	}
	cert, err := validCertificate(data, key)
	if err != nil {
		_ = lease.finish(nil, lease.reserved)
		return err
	}
	state := m.cache.state(key)
	state.Withheld, state.Generation = certificateFingerprint(cert), lease.generation
	m.cache.states.Store(key, state)
	data = issuedData(data, state)
	saveErr := m.cache.save(context.Background(), key, data)
	metadataErr := m.cache.saveState(context.Background(), key, state)
	retry := certificateRetry{Updated: time.Now()}
	finishErr := lease.finish(data, retry)
	if finishErr != nil {
		return errors.Join(saveErr, metadataErr, finishErr)
	}
	state.Retry, state.Withheld, state.Generation = retry, "", ""
	return errors.Join(saveErr, metadataErr, m.cache.completeLocal(context.Background(), key, data, state))
}

func (m *certificateManager) issue(ctx context.Context, client *acme.Client, keyName string) ([]byte, error) {
	name, variant := certificateVariant(keyName)
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
		revision, err := storeCall(ctx, func(ctx context.Context) (uint64, error) {
			return tokens.Put(ctx, cacheKey(name+":"+challenge.Token), []byte(token))
		})
		if err != nil {
			return nil, err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tokens.Delete(cleanup, cacheKey(name+":"+challenge.Token), jetstream.LastRevision(revision))
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
	var key crypto.Signer
	if variant == "rsa" {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
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
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	for _, cert := range chain {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})...)
	}
	if _, err := validCertificate(data, keyName); err != nil {
		return nil, fmt.Errorf("edge: issued certificate invalid: %w", err)
	}
	return data, nil
}

func (e *Edge) reconcileCertificates(ctx context.Context) {
	var work sync.WaitGroup
	defer func() { work.Wait(); e.certs.cache.stopWatch() }()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		names := map[string]bool{}
		for host := range *e.routes.Load() {
			names[host] = true
		}
		for host := range *e.postgres.Load() {
			names[host] = true
		}
		if err := e.certs.cache.publishHoldings(ctx); err != nil {
			slog.WarnContext(ctx, "edge certificate inventory unavailable", "error", err)
		}
		for name := range names {
			if ctx.Err() != nil {
				return
			}
			if _, busy := e.certWork.LoadOrStore(name, true); busy {
				continue
			}
			work.Go(func() {
				defer e.certWork.Delete(name)
				if err := e.certs.ensure(ctx, name); err != nil && !errors.Is(err, errIssueHeld) {
					slog.WarnContext(ctx, "edge certificate unavailable", "name", name, "error", err)
				}
			})
		}
		select {
		case <-ctx.Done():
			return
		case <-e.certRoutes:
		case <-tick.C:
		}
	}
}

func mCacheStop(cache *certificateCache, work *sync.WaitGroup) { work.Wait(); cache.stopWatch() }

const challengeReadLimit = 16

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
		token := strings.TrimPrefix(r.URL.Path, challengePath)
		if len(token) < 22 || len(token) > 256 || strings.IndexFunc(token, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
		}) >= 0 {
			http.NotFound(w, r)
			return
		}
		host := strings.ToLower(strings.TrimSuffix(r.Host, "."))
		if name, _, err := net.SplitHostPort(host); err == nil {
			host = name
		}
		live := false
		for _, key := range []string{host, host + "+rsa"} {
			if until, exists := m.cache.live.Load(key); exists && time.Now().Before(until.(time.Time)) {
				live = true
			}
		}
		if m.cache.challengeReads.Add(1) > challengeReadLimit {
			m.cache.challengeReads.Add(-1)
			http.Error(w, "challenge capacity reached", http.StatusServiceUnavailable)
			return
		}
		defer m.cache.challengeReads.Add(-1)

		if !live {
			if err := m.policy(r.Context(), host); err != nil {
				http.NotFound(w, r)
				return
			}
			if err := m.cache.open(r.Context()); err != nil {
				http.Error(w, "challenge store unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		m.cache.mu.Lock()
		reader := m.cache.reader
		m.cache.mu.Unlock()
		value, err := storeCall(r.Context(), func(ctx context.Context) (*nats.RawStreamMsg, error) {
			return reader.GetLastMsg("KV_edge-cert-tokens", "$KV.edge-cert-tokens."+cacheKey(host+":"+token), nats.Context(ctx))
		})
		if err != nil || value.Header.Get("KV-Operation") != "" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(value.Data)
	})
}
