package edge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
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
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/crypto/acme/autocert"
)

const issueBudget = 5 * time.Minute
const issueTTL = 2 * issueBudget
const storeBudget = 3 * time.Second

var errIssueHeld = errors.New("edge: certificate issuance lease held or cooling down")
var errUnsupportedCertificate = errors.New("edge: unsupported certificate envelope")
var errLeaseLost = errors.New("edge: certificate issuance lease lost")

type certificateStore interface {
	EdgeCertificateStore() (*nats.Conn, []byte, error)
}

type certificateCache struct {
	dirty          sync.Map
	local          autocert.DirCache
	source         func() (*nats.Conn, []byte, error)
	roster         func() (string, []string, error)
	inventoryMu    sync.Mutex
	pending        sync.Map
	variantLocks   sync.Map
	mu             sync.Mutex
	conn           *nats.Conn
	certs          jetstream.KeyValue
	tokens         jetstream.KeyValue
	seal           cipher.AEAD
	reader         nats.JetStreamContext
	opening        bool
	keyID          string
	watch          jetstream.KeyWatcher
	watchDone      chan struct{}
	watchCancel    context.CancelFunc
	required       sync.Map
	memory         sync.Map
	states         sync.Map
	live           sync.Map
	unsupported    sync.Map
	warned         sync.Map
	failures       sync.Map
	challengeReads atomic.Int32
}

func cacheKey(name string) string { return hex.EncodeToString([]byte(name)) }

func certificateVariant(key string) (string, string) {
	if name, rsa := strings.CutSuffix(key, "+rsa"); rsa {
		return name, "rsa"
	}
	return key, "ecdsa"
}

type cachedCertificate struct {
	cert *tls.Certificate
	data []byte
}

type certificateRetry struct {
	Attempt int
	Next    time.Time
	Updated time.Time
}

type certificateLocalState struct {
	Retry      certificateRetry
	Withheld   string
	Generation string
}

type certificateLease struct {
	Generation string
	Until      time.Time
}

type sealedCertificate struct {
	Version string
	KeyID   string
	Data    []byte
	Lease   certificateLease
	Retry   certificateRetry
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
	tokens, err := openBucket(ctx, js, jetstream.KeyValueConfig{Bucket: "edge-cert-tokens", Replicas: 3, History: 1, TTL: issueTTL, MaxBytes: 1 << 20})
	if err != nil {
		return err
	}
	reader, err := conn.JetStream()
	if err != nil {
		return err
	}
	watchCtx, watchCancel := context.WithCancel(context.Background())
	watchTimer := time.AfterFunc(storeBudget, watchCancel)
	watch, err := certs.WatchAll(watchCtx)
	watchTimer.Stop()
	if err != nil {
		watchCancel()
		return err
	}
	fingerprint := sha256.Sum256(key)
	c.stopWatch()
	c.mu.Lock()
	c.keyID = "mesh-v1:" + hex.EncodeToString(fingerprint[:8])
	c.reader = reader
	c.conn, c.certs, c.tokens, c.seal = conn, certs, tokens, seal
	c.watch, c.watchDone, c.watchCancel = watch, make(chan struct{}), watchCancel
	done := c.watchDone
	c.mu.Unlock()
	go func() {
		defer close(done)
		for entry := range watch.Updates() {
			if entry == nil {
				continue
			}
			key, err := hex.DecodeString(entry.Key())
			if err != nil {
				continue
			}
			var value sealedCertificate
			if entry.Operation() == jetstream.KeyValuePut && json.Unmarshal(entry.Value(), &value) == nil && value.Version == "v1" {
				c.live.Store(string(key), value.Lease.Until)
			} else {
				c.live.Delete(string(key))
			}
		}
	}()
	return nil
}

func (c *certificateCache) stopWatch() {
	c.mu.Lock()
	watch, done, cancel := c.watch, c.watchDone, c.watchCancel
	c.watch, c.watchDone = nil, nil
	c.mu.Unlock()
	if watch != nil {
		cancel()
		_ = watch.Stop()
		<-done
	}
}

func validCertificate(data []byte, name string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, err
	}
	host, variant := certificateVariant(name)
	if err = cert.Leaf.VerifyHostname(host); err != nil {
		return nil, err
	}
	_, rsa := cert.PrivateKey.(*rsa.PrivateKey)
	if rsa != (variant == "rsa") {
		return nil, errors.New("edge: certificate key variant mismatch")
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return nil, autocert.ErrCacheMiss
	}
	return &cert, nil
}

func certificateFingerprint(cert *tls.Certificate) string {
	digest := sha256.Sum256(cert.Leaf.Raw)
	return hex.EncodeToString(digest[:])
}

func preferredCertificate(candidate, current *tls.Certificate) bool {
	if !candidate.Leaf.NotAfter.Equal(current.Leaf.NotAfter) {
		return candidate.Leaf.NotAfter.After(current.Leaf.NotAfter)
	}
	return bytes.Compare(candidate.Leaf.Raw, current.Leaf.Raw) != 0 && certificateFingerprint(candidate) < certificateFingerprint(current)
}

func (c *certificateCache) unsupportedEntry(key string) error {
	c.unsupported.Store(key, true)
	name, variant := certificateVariant(key)
	if _, seen := c.warned.LoadOrStore(name, true); !seen {
		slog.Warn("edge certificate envelope unsupported", "name", name, "variant", variant)
	}
	return errUnsupportedCertificate
}

func (c *certificateCache) shared(ctx context.Context, key string) (sealedCertificate, uint64, error) {
	if err := c.open(ctx); err != nil {
		return sealedCertificate{}, 0, err
	}
	c.mu.Lock()
	reader, keyID := c.reader, c.keyID
	c.mu.Unlock()
	entry, err := storeCall(ctx, func(ctx context.Context) (*nats.RawStreamMsg, error) {
		return reader.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+cacheKey(key), nats.Context(ctx))
	})
	if errors.Is(err, nats.ErrMsgNotFound) {
		c.unsupported.Delete(key)
		return sealedCertificate{Version: "v1", KeyID: keyID}, 0, nil
	}
	if err != nil {
		return sealedCertificate{}, 0, err
	}
	if entry.Header.Get("KV-Operation") != "" {
		c.unsupported.Delete(key)
		return sealedCertificate{Version: "v1", KeyID: keyID}, entry.Sequence, nil
	}
	var value sealedCertificate
	if json.Unmarshal(entry.Data, &value) != nil || value.Version != "v1" || value.KeyID != keyID {
		return value, entry.Sequence, c.unsupportedEntry(key)
	}
	c.unsupported.Delete(key)
	return value, entry.Sequence, nil
}

func (c *certificateCache) decode(value sealedCertificate, key string) ([]byte, error) {
	if len(value.Data) == 0 {
		return nil, autocert.ErrCacheMiss
	}
	c.mu.Lock()
	seal := c.seal
	c.mu.Unlock()
	plain, err := seal.Open(nil, nil, value.Data, []byte(key))
	if err != nil {
		return nil, c.unsupportedEntry(key)
	}
	if _, err = validCertificate(plain, key); err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
		return nil, c.unsupportedEntry(key)
	}
	return plain, err
}

func (c *certificateCache) write(ctx context.Context, key string, value sealedCertificate, revision uint64) (uint64, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	certs := c.certs
	c.mu.Unlock()
	return storeCall(ctx, func(ctx context.Context) (uint64, error) {
		if revision == 0 {
			return certs.Create(ctx, cacheKey(key), data)
		}
		return certs.Update(ctx, cacheKey(key), data, revision)
	})
}

func (c *certificateCache) state(key string) certificateLocalState {
	if value, ok := c.states.Load(key); ok {
		return value.(certificateLocalState)
	}
	return certificateLocalState{}
}

func (c *certificateCache) saveState(ctx context.Context, key string, state certificateLocalState) error {
	c.states.Store(key, state)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	err = c.local.Put(ctx, ".state-"+key, data)
	if err != nil {
		c.dirty.Store(key, true)
	} else {
		c.dirty.Delete(key)
	}
	return err
}

func (c *certificateCache) save(ctx context.Context, key string, data []byte) error {
	cert, err := validCertificate(data, key)
	if err != nil {
		return err
	}
	if current, ok := c.memory.Load(key); ok && !preferredCertificate(cert, current.(cachedCertificate).cert) {
		return nil
	}
	err = c.local.Put(ctx, key, data)
	c.memory.Store(key, cachedCertificate{cert, data})
	if err != nil {
		return err
	}
	slog.Info("edge certificate installed", "name", key, "expires", cert.Leaf.NotAfter)
	return nil
}

func (c *certificateCache) variantLock(key string) *sync.Mutex {
	value, _ := c.variantLocks.LoadOrStore(key, new(sync.Mutex))
	return value.(*sync.Mutex)
}

func (c *certificateCache) reconcile(ctx context.Context, key string) error {
	lock := c.variantLock(key)
	lock.Lock()
	defer lock.Unlock()
	return c.reconcileLocked(ctx, key)
}

func (c *certificateCache) reconcileLocked(ctx context.Context, key string) error {
	if err := c.publishRetry(ctx, key); err != nil {
		return err
	}
	if _, dirty := c.dirty.Load(key); dirty {
		if err := c.saveState(ctx, key, c.state(key)); err != nil {
			return err
		}
	}
	value, revision, err := c.shared(ctx, key)
	if err != nil {
		return err
	}
	state := c.state(key)
	if value.Retry.Next.After(state.Retry.Next) || value.Retry.Updated.After(state.Retry.Updated) {
		state.Retry = value.Retry
		if err := c.saveState(ctx, key, state); err != nil {
			return err
		}
	}
	data, err := c.decode(value, key)
	if len(data) != 0 {
		c.required.Store(key, true)
	}
	if err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
		return err
	}
	if err == nil {
		if err := c.save(ctx, key, data); err != nil {
			return err
		}
	}
	local, exists := c.memory.Load(key)
	if !exists {
		return nil
	}
	candidate := local.(cachedCertificate)
	if state.Withheld == certificateFingerprint(candidate.cert) {
		if err == nil {
			shared, _ := validCertificate(data, key)
			if certificateFingerprint(shared) == state.Withheld {
				state.Withheld, state.Generation = "", ""
				return c.completeLocal(ctx, key, candidate.data, state)
			}
		}
		if state.Generation == "" || value.Lease.Generation != state.Generation || !time.Now().Before(value.Lease.Until) {
			return nil
		}
		c.mu.Lock()
		seal := c.seal
		c.mu.Unlock()
		value.Data = seal.Seal(nil, nil, stripIssuedState(candidate.data), []byte(key))
		value.Lease = certificateLease{}
		value.Retry = certificateRetry{Updated: time.Now()}
		if _, err := c.write(ctx, key, value, revision); err != nil {
			return err
		}
		state.Withheld, state.Generation, state.Retry = "", "", value.Retry
		return c.completeLocal(ctx, key, candidate.data, state)
	}
	if err == nil {
		shared, _ := validCertificate(data, key)
		if !preferredCertificate(candidate.cert, shared) {
			return nil
		}
	}
	if value.Lease.Generation != "" && time.Now().Before(value.Lease.Until) {
		return nil
	}
	c.mu.Lock()
	seal := c.seal
	c.mu.Unlock()
	value.Data = seal.Seal(nil, nil, stripIssuedState(candidate.data), []byte(key))
	_, err = c.write(ctx, key, value, revision)
	return err
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
		if !entry.Type().IsRegular() || entry.Name() == "acme_account+key" {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".retry-") {
			data, err := c.local.Get(ctx, entry.Name())
			if err != nil {
				return err
			}
			var retry certificateRetry
			if err := json.Unmarshal(data, &retry); err != nil {
				return err
			}
			c.pending.Store(strings.TrimPrefix(entry.Name(), ".retry-"), retry)
			continue
		}
		if strings.HasPrefix(entry.Name(), ".state-") {
			data, err := c.local.Get(ctx, entry.Name())
			if err != nil {
				return err
			}
			var state certificateLocalState
			if err := json.Unmarshal(data, &state); err != nil {
				return err
			}
			c.states.Store(strings.TrimPrefix(entry.Name(), ".state-"), state)
			continue
		}
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		data, err := c.local.Get(ctx, entry.Name())
		if err != nil {
			return err
		}
		if parsed, err := tls.X509KeyPair(data, data); err == nil && parsed.Leaf.VerifyHostname(strings.TrimSuffix(entry.Name(), "+rsa")) == nil {
			c.required.Store(entry.Name(), true)
		}
		if cert, err := validCertificate(data, entry.Name()); err == nil {
			c.memory.Store(entry.Name(), cachedCertificate{cert, data})
			slog.Info("edge certificate installed", "name", entry.Name(), "expires", cert.Leaf.NotAfter)
		}
	}
	c.memory.Range(func(key, value any) bool {
		if state, ok := issuedState(value.(cachedCertificate).data); ok {
			c.states.Store(key, state)
		}
		return true
	})
	return nil
}

type issuanceLease struct {
	generation string
	reserved   certificateRetry
	cache      *certificateCache
	key        string
	mu         sync.Mutex
	value      sealedCertificate
	revision   uint64
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
}

func retryDeadline(attempt int, now time.Time) time.Time {
	return now.Add(min(30*time.Minute*time.Duration(1<<min(max(attempt-1, 0), 6)), 24*time.Hour))
}

func (c *certificateCache) lease(ctx context.Context, key string) (*issuanceLease, error) {
	if time.Now().Before(c.state(key).Retry.Next) {
		return nil, errIssueHeld
	}
	value, revision, err := c.shared(ctx, key)
	if err != nil {
		return nil, err
	}
	if data, decodeErr := c.decode(value, key); decodeErr == nil {
		cert, _ := validCertificate(data, key)
		if !renewCertificate(cert) {
			return nil, errIssueHeld
		}
	} else if !errors.Is(decodeErr, autocert.ErrCacheMiss) {
		return nil, decodeErr
	}
	now := time.Now()
	if now.Before(value.Lease.Until) || now.Before(value.Retry.Next) {
		return nil, errIssueHeld
	}
	state := c.state(key)
	attempt := max(state.Retry.Attempt, value.Retry.Attempt) + 1
	value.Lease = certificateLease{rand.Text(), now.Add(issueTTL)}
	value.Retry = certificateRetry{attempt, retryDeadline(attempt, now.Add(issueBudget)), now}
	revision, err = c.write(ctx, key, value, revision)
	if errors.Is(err, jetstream.ErrKeyExists) {
		return nil, errIssueHeld
	}
	if err != nil {
		return nil, err
	}
	state.Retry = value.Retry
	if err := c.saveState(ctx, key, state); err != nil {
		return nil, err
	}
	issue, cancel := context.WithDeadline(ctx, now.Add(issueBudget))
	lease := &issuanceLease{generation: value.Lease.Generation, reserved: value.Retry, cache: c, key: key, value: value, revision: revision, ctx: issue, cancel: cancel, done: make(chan struct{})}
	c.live.Store(key, value.Lease.Until)
	go lease.renew()
	return lease, nil
}

func (l *issuanceLease) renew() {
	defer close(l.done)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-tick.C:
			l.mu.Lock()
			if !time.Now().Before(l.value.Lease.Until) {
				l.cancel()
				l.mu.Unlock()
				return
			}
			value := l.value
			value.Lease.Until = time.Now().Add(issueTTL)
			revision, err := l.cache.write(l.ctx, l.key, value, l.revision)
			if err != nil {
				l.cancel()
				l.mu.Unlock()
				return
			}
			l.value, l.revision = value, revision
			l.mu.Unlock()
		}
	}
}

func (l *issuanceLease) finish(data []byte, retry certificateRetry) error {
	l.cancel()
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	if !time.Now().Before(l.value.Lease.Until) {
		return errLeaseLost
	}
	value := l.value
	if len(data) != 0 {
		l.cache.mu.Lock()
		seal := l.cache.seal
		l.cache.mu.Unlock()
		value.Data = seal.Seal(nil, nil, stripIssuedState(data), []byte(l.key))
	}
	value.Lease = certificateLease{}
	value.Retry = retry
	ctx, cancel := context.WithTimeout(context.Background(), storeBudget)
	defer cancel()
	_, err := l.cache.write(ctx, l.key, value, l.revision)
	return err
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
		if entry.Type().IsRegular() {
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
