package edge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
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

var errIssueHeld = errors.New("edge: certificate issuance lease held")

type certificateStore interface {
	EdgeCertificateStore() (*nats.Conn, []byte, error)
}

type certificateCache struct {
	local  autocert.DirCache
	source func() (*nats.Conn, []byte, error)
	mu     sync.Mutex
	conn   *nats.Conn
	certs  jetstream.KeyValue
	leases jetstream.KeyValue
	tokens jetstream.KeyValue
	seal   cipher.AEAD
	reader nats.JetStreamContext
}

func cacheKey(name string) string { return hex.EncodeToString([]byte(name)) }

func (c *certificateCache) open(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, secret, err := c.source()
	if err != nil {
		return err
	}
	defer clear(secret)
	if conn == c.conn {
		return nil
	}
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
	certs, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "edge-certs", Replicas: 3, History: 1, MaxBytes: 16 << 20, MaxValueSize: 64 << 10})
	if err != nil {
		return err
	}
	leases, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "edge-cert-leases", Replicas: 3, History: 1, TTL: issueTTL, MaxBytes: 1 << 20})
	if err != nil {
		return err
	}
	tokens, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "edge-cert-tokens", Replicas: 3, History: 1, TTL: issueTTL, MaxBytes: 1 << 20})
	if err != nil {
		return err
	}
	reader, err := conn.JetStream()
	if err != nil {
		return err
	}
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

func (c *certificateCache) shared(ctx context.Context, name string) ([]byte, error) {
	if err := c.open(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	reader, seal := c.reader, c.seal
	c.mu.Unlock()
	entry, err := reader.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+cacheKey(name), nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	if entry.Header.Get("KV-Operation") != "" {
		return nil, autocert.ErrCacheMiss
	}
	return seal.Open(nil, nil, entry.Data, []byte(name))
}

func (c *certificateCache) Get(ctx context.Context, name string) ([]byte, error) {
	data, err := c.shared(ctx, name)
	if err == nil {
		if _, err = validCertificate(data, name); err == nil {
			if err = c.local.Put(ctx, name, data); err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	local, localErr := c.local.Get(ctx, name)
	if localErr != nil {
		return nil, err
	}
	if _, localErr = validCertificate(local, name); localErr != nil {
		return nil, localErr
	}
	if errors.Is(err, autocert.ErrCacheMiss) {
		if err = c.adopt(ctx, name, local); err != nil {
			return nil, err
		}
		return c.shared(ctx, name)
	}
	return local, nil
}

func (c *certificateCache) adopt(ctx context.Context, name string, data []byte) error {
	if err := c.open(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	certs, seal := c.certs, c.seal
	c.mu.Unlock()
	_, err := certs.Create(ctx, cacheKey(name), seal.Seal(nil, nil, data, []byte(name)))
	if errors.Is(err, jetstream.ErrKeyExists) {
		entry, readErr := certs.Get(ctx, cacheKey(name))
		if readErr != nil {
			return readErr
		}
		current, openErr := seal.Open(nil, nil, entry.Value(), []byte(name))
		if openErr != nil {
			return openErr
		}
		if _, validErr := validCertificate(current, name); validErr == nil {
			return nil
		}
		_, err = certs.Update(ctx, cacheKey(name), seal.Seal(nil, nil, data, []byte(name)), entry.Revision())
	}
	return err
}

func (c *certificateCache) Put(ctx context.Context, name string, data []byte) error {
	if _, err := validCertificate(data, name); err != nil {
		return err
	}
	if err := c.open(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	certs, seal := c.certs, c.seal
	c.mu.Unlock()
	if _, err := certs.Put(ctx, cacheKey(name), seal.Seal(nil, nil, data, []byte(name))); err != nil {
		return err
	}
	return c.local.Put(ctx, name, data)
}

func (c *certificateCache) Delete(ctx context.Context, name string) error {
	if err := c.open(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	certs := c.certs
	c.mu.Unlock()
	return errors.Join(certs.Delete(ctx, cacheKey(name)), c.local.Delete(ctx, name))
}

func (c *certificateCache) lease(ctx context.Context, name string) (context.Context, func(), error) {
	begun := time.Now()
	if err := c.open(ctx); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	leases := c.leases
	c.mu.Unlock()
	revision, err := leases.Create(ctx, cacheKey(name), []byte("issuing"))
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
