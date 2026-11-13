package edge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/crypto/acme/autocert"
)

const issueBudget = 5 * time.Minute
const issueTTL = 2 * issueBudget
const storeBudget = 3 * time.Second

var errIssueHeld = errors.New("edge: certificate issuance lease held")

type certificateStore interface {
	EdgeCertificateStore() (*nats.Conn, []byte, error)
}

type certificateCache struct {
	local   autocert.DirCache
	source  func() (*nats.Conn, []byte, error)
	mu      sync.Mutex
	conn    *nats.Conn
	certs   jetstream.KeyValue
	leases  jetstream.KeyValue
	tokens  jetstream.KeyValue
	seal    cipher.AEAD
	reader  nats.JetStreamContext
	opening bool
	version string
	memory  sync.Map
}

func cacheKey(name string) string { return hex.EncodeToString([]byte(name)) }

type cachedCertificate struct {
	cert *tls.Certificate
	data []byte
}

type sealedCertificate struct {
	Version string
	Data    []byte
}

func storeCall[T any](ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	bounded, cancel := context.WithTimeout(ctx, storeBudget)
	defer cancel()
	return call(bounded)
}

func openBucket(ctx context.Context, js jetstream.JetStream, config jetstream.KeyValueConfig) (jetstream.KeyValue, error) {
	bucket, err := storeCall(ctx, func(ctx context.Context) (jetstream.KeyValue, error) { return js.KeyValue(ctx, config.Bucket) })
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		return storeCall(ctx, func(ctx context.Context) (jetstream.KeyValue, error) { return js.CreateKeyValue(ctx, config) })
	}
	return bucket, err
}

func (c *certificateCache) open(ctx context.Context) error {
	conn, secret, err := c.source()
	if err != nil {
		return err
	}
	defer clear(secret)
	c.mu.Lock()
	if conn == c.conn {
		c.mu.Unlock()
		return nil
	}
	if c.opening {
		c.mu.Unlock()
		return errors.New("edge: certificate store opening")
	}
	c.opening = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.opening = false; c.mu.Unlock() }()
	key, err := hkdf.Key(sha256.New, secret, nil, "ts-orch edge certificates v1", 32)
	if err != nil {
		return err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	seal, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return err
	}
	js, err := jetstream.New(conn)
	if err != nil {
		return err
	}
	certs, err := openBucket(ctx, js, jetstream.KeyValueConfig{Bucket: "edge-certs", Replicas: 3, History: 1, MaxBytes: 16 << 20, MaxValueSize: 64 << 10})
	if err != nil {
		return err
	}
	leases, err := openBucket(ctx, js, jetstream.KeyValueConfig{Bucket: "edge-cert-leases", Replicas: 3, History: 1, TTL: issueTTL, MaxBytes: 1 << 20})
	if err != nil {
		return err
	}
	tokens, err := openBucket(ctx, js, jetstream.KeyValueConfig{Bucket: "edge-cert-tokens", Replicas: 3, History: 1, TTL: issueTTL, MaxBytes: 1 << 20})
	if err != nil {
		return err
	}
	reader, err := conn.JetStream()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fingerprint := sha256.Sum256(key)
	c.version = "v1:" + hex.EncodeToString(fingerprint[:8])
	c.reader = reader
	c.conn, c.certs, c.leases, c.tokens, c.seal = conn, certs, leases, tokens, seal
	return nil
}

func validCertificate(data []byte, name string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, err
	}
	if err = cert.Leaf.VerifyHostname(strings.TrimSuffix(name, "+rsa")); err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return nil, autocert.ErrCacheMiss
	}
	return &cert, nil
}

func (c *certificateCache) decode(data []byte, name string) ([]byte, error) {
	var value sealedCertificate
	c.mu.Lock()
	version, seal := c.version, c.seal
	c.mu.Unlock()
	if json.Unmarshal(data, &value) != nil || value.Version != version {
		return nil, autocert.ErrCacheMiss
	}
	plain, err := seal.Open(nil, nil, value.Data, []byte(name))
	if err != nil {
		return nil, autocert.ErrCacheMiss
	}
	return plain, nil
}

func (c *certificateCache) shared(ctx context.Context, name string) ([]byte, uint64, error) {
	if err := c.open(ctx); err != nil {
		return nil, 0, err
	}
	c.mu.Lock()
	reader := c.reader
	c.mu.Unlock()
	entry, err := storeCall(ctx, func(ctx context.Context) (*nats.RawStreamMsg, error) {
		return reader.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+cacheKey(name), nats.Context(ctx))
	})
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, 0, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, 0, err
	}
	if entry.Header.Get("KV-Operation") != "" {
		return nil, entry.Sequence, autocert.ErrCacheMiss
	}
	data, err := c.decode(entry.Data, name)
	return data, entry.Sequence, err
}

func (c *certificateCache) save(ctx context.Context, name string, data []byte) error {
	cert, err := validCertificate(data, name)
	if err != nil {
		return err
	}
	if current, ok := c.memory.Load(name); ok && !cert.Leaf.NotAfter.After(current.(cachedCertificate).cert.Leaf.NotAfter) {
		return nil
	}
	err = c.local.Put(ctx, name, data)
	c.memory.Store(name, cachedCertificate{cert, data})
	if err != nil {
		return err
	}
	slog.Info("edge certificate installed", "name", name, "expires", cert.Leaf.NotAfter)
	return nil
}

func (c *certificateCache) publish(ctx context.Context, name string, data []byte, revision uint64) error {
	if err := c.local.Put(ctx, name, data); err != nil {
		return err
	}
	if err := c.open(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	version, seal, certs := c.version, c.seal, c.certs
	c.mu.Unlock()
	value, err := json.Marshal(sealedCertificate{version, seal.Seal(nil, nil, data, []byte(name))})
	if err != nil {
		return err
	}
	_, err = storeCall(ctx, func(ctx context.Context) (uint64, error) {
		if revision == 0 {
			return certs.Create(ctx, cacheKey(name), value)
		}
		return certs.Update(ctx, cacheKey(name), value, revision)
	})
	return err
}

func (c *certificateCache) reconcile(ctx context.Context, name string) error {
	data, revision, err := c.shared(ctx, name)
	if err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
		return err
	}
	if err == nil {
		if cert, validErr := validCertificate(data, name); validErr == nil {
			if err := c.save(ctx, name, data); err != nil {
				return err
			}
			local, _ := c.memory.Load(name)
			if !local.(cachedCertificate).cert.Leaf.NotAfter.After(cert.Leaf.NotAfter) {
				return nil
			}
		}
	}
	if local, ok := c.memory.Load(name); ok {
		return c.publish(ctx, name, local.(cachedCertificate).data, revision)
	}
	return nil
}

func (c *certificateCache) loadDisk(ctx context.Context) error {
	if err := c.protect(); err != nil {
		return err
	}
	entries, err := os.ReadDir(string(c.local))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == "acme_account+key" {
			continue
		}
		data, err := c.local.Get(ctx, entry.Name())
		if err != nil {
			return err
		}
		if cert, err := validCertificate(data, entry.Name()); err == nil {
			c.memory.Store(entry.Name(), cachedCertificate{cert, data})
			slog.Info("edge certificate installed", "name", entry.Name(), "expires", cert.Leaf.NotAfter)
		}
	}
	return nil
}

func (c *certificateCache) lease(ctx context.Context, name string) (context.Context, func(), error) {
	begun := time.Now()
	if err := c.open(ctx); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	leases := c.leases
	c.mu.Unlock()
	revision, err := storeCall(ctx, func(ctx context.Context) (uint64, error) {
		return leases.Create(ctx, cacheKey(name), []byte("issuing"))
	})
	if errors.Is(err, jetstream.ErrKeyExists) {
		return nil, nil, errIssueHeld
	}
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, begun.Add(issueBudget))
	return ctx, func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = leases.Delete(cleanup, cacheKey(name), jetstream.LastRevision(revision))
	}, nil
}

func (c *certificateCache) protect() error {
	if err := os.MkdirAll(string(c.local), 0700); err != nil {
		return err
	}
	if err := os.Chmod(string(c.local), 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(string(c.local))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && !strings.HasPrefix(entry.Name(), ".") {
			if err := os.Chmod(filepath.Join(string(c.local), entry.Name()), 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Edge) certificateStore() (*nats.Conn, []byte, error) {
	source, ok := e.meshNode().(certificateStore)
	if !ok {
		return nil, nil, errors.New("edge: mesh certificate store unavailable")
	}
	return source.EdgeCertificateStore()
}
