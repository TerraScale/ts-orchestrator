package observability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	SessionCookieName = "ts_orch_session"
	// SessionBucket contains only hashes and token generations, with no TTL.
	SessionBucket       = "TS_DASHBOARD_SESSIONS"
	maxLoginFormSize    = 8 << 10
	sessionStoreTimeout = 5 * time.Second
	// Never evict a live session. At capacity, reuse the browser's session,
	// sign out elsewhere, or rotate the token to reclaim abandoned sessions.
	maxSessions = 1024
)

var errSessionCapacity = errors.New("dashboard session capacity reached")

// SessionStore persists sessions in the regional bootstrap store. Scope keeps
// the NetBird token separate from an independently configured local listener.
type SessionStore struct {
	kv     jetstream.KeyValue
	leader nats.JetStreamContext
	scope  string
	stream jetstream.Stream
}

func OpenSessionStore(ctx context.Context, js jetstream.JetStream, replicas int, scope string) (*SessionStore, error) {
	if js == nil || replicas < 1 || replicas > 5 || scope == "" {
		return nil, errors.New("dashboard sessions require JetStream, replicas and a listener scope")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: SessionBucket, Description: "Hashed dashboard sessions and token generations",
		History: 1, Storage: jetstream.FileStorage, Replicas: replicas,
		MaxValueSize: 1024, MaxBytes: 16 << 20,
	})
	if err != nil {
		return nil, err
	}
	leader, err := js.Conn().JetStream()
	if err != nil {
		return nil, err
	}
	stream, err := js.Stream(ctx, "KV_"+SessionBucket)
	if err != nil {
		return nil, err
	}
	return &SessionStore{kv: kv, leader: leader, scope: sessionHash(scope), stream: stream}, nil
}

func sessionHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// get reads the leader, since a follower could still accept a revoked session.
func (store *SessionStore) get(ctx context.Context, key string) (*nats.RawStreamMsg, error) {
	msg, err := store.leader.GetLastMsg("KV_"+SessionBucket, "$KV."+SessionBucket+"."+key, nats.Context(ctx))
	if err != nil {
		return nil, err
	}
	if msg.Header.Get("KV-Operation") != "" {
		return nil, jetstream.ErrKeyNotFound
	}
	return msg, nil
}

type sessions struct {
	secure    bool
	binding   atomic.Pointer[sessionBinding]
	reclaim   atomic.Pointer[sessionBinding]
	mu        sync.Mutex
	rollbacks map[string]sessionRollback
	// Hosts have no controller KV grant; keep their existing process-local login.
	local map[string]struct{}
}

type sessionRollback struct {
	store    *SessionStore
	key      string
	revision uint64
	hash     string
}

type sessionBinding struct {
	store      *SessionStore
	tokenHash  string
	generation uint64
}

// TokenVersion orders versions within a Vault secret and reference changes
// across signed cell specs. Source is the secret's OCID, never its value.
type TokenVersion struct {
	Source         string `json:"source"`
	Number         int64  `json:"number"`
	SpecGeneration uint64 `json:"spec_generation"`
}

type sessionToken struct {
	Hash       string       `json:"hash"`
	Version    TokenVersion `json:"version"`
	Generation uint64       `json:"generation"`
}

func readSessionToken(data []byte) (sessionToken, error) {
	// Accept the hash-only metadata written before authoritative versions.
	if len(data) == 64 {
		if _, err := hex.DecodeString(string(data)); err == nil {
			return sessionToken{Hash: string(data)}, nil
		}
	}
	var token sessionToken
	err := json.Unmarshal(data, &token)
	return token, err
}

func (token *sessionToken) advance(previous sessionToken) (bool, error) {
	if previous.Version != (TokenVersion{}) {
		switch {
		case token.Version == (TokenVersion{}):
			return false, errors.New("dashboard token registration has no authoritative version")
		case token.Version.Source != previous.Version.Source:
			if token.Version.SpecGeneration <= previous.Version.SpecGeneration {
				return false, errors.New("dashboard token reference is stale")
			}
		case token.Version.Number < previous.Version.Number:
			return false, errors.New("dashboard token version is stale")
		case token.Version.Number == previous.Version.Number:
			if token.Hash != previous.Hash {
				return false, errors.New("dashboard token version has conflicting values")
			}
			token.Version.SpecGeneration = max(token.Version.SpecGeneration, previous.Version.SpecGeneration)
		default:
			// A current Vault version can be read by an older adopted spec,
			// but must not lower the fence against obsolete reference changes.
			token.Version.SpecGeneration = max(token.Version.SpecGeneration, previous.Version.SpecGeneration)
		}
	}
	return token.Hash != previous.Hash || token.Version != previous.Version, nil
}

// SetSessionStore enables browser login once the controller's NATS is ready.
// CAS orders rotations and Vault/spec versions refuse stale registrations.
// Restoring an old value in a new Vault version cannot resurrect sessions.
func (server *Server) SetSessionStore(ctx context.Context, store *SessionStore) error {
	if store == nil || server.token == nil {
		return errors.New("dashboard sessions require a store and a token")
	}
	hash := sessionHash(string(server.token))
	want := sessionToken{Hash: hash, Version: server.deps.TokenVersion, Generation: 1}
	if want.Version != (TokenVersion{}) && (want.Version.Source == "" || want.Version.Number <= 0 || want.Version.SpecGeneration == 0) {
		return errors.New("dashboard token requires a Vault version and signed spec generation")
	}
	key := "token." + store.scope
	for attempts := 0; attempts < 8; attempts++ {
		entry, err := store.get(ctx, key)
		var generation uint64
		data, marshalErr := json.Marshal(want)
		if marshalErr != nil {
			return marshalErr
		}
		switch {
		case errors.Is(err, nats.ErrMsgNotFound), errors.Is(err, jetstream.ErrKeyNotFound):
			_, err = store.kv.Create(ctx, key, data)
			generation = want.Generation
		case err != nil:
			return err
		default:
			previous, readErr := readSessionToken(entry.Data)
			if readErr != nil {
				return readErr
			}
			if previous.Generation == 0 {
				previous.Generation = entry.Sequence
			}
			changed, advanceErr := want.advance(previous)
			if advanceErr != nil {
				return advanceErr
			}
			if !changed {
				generation = previous.Generation
				break
			}
			want.Generation = previous.Generation
			if want.Hash != previous.Hash || want.Version.Source != previous.Version.Source || want.Version.Number != previous.Version.Number {
				// The KV sequence orders rotations; spec-only checkpoint updates
				// retain the session generation so existing browsers stay logged in.
				want.Generation = entry.Sequence + 1
			}
			data, err = json.Marshal(want)
			if err != nil {
				return err
			}
			// Failed rotation must preserve active sessions. Reclaim records
			// only after the generation's CAS commits their revocation.
			_, err = store.kv.Update(ctx, key, data, entry.Sequence)
			generation = want.Generation
		}
		if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			continue
		}
		if err != nil {
			return err
		}
		binding := &sessionBinding{store: store, tokenHash: hash, generation: generation}
		server.sessions.binding.Store(binding)
		// Reclamation failure cannot undo a committed, usable registration.
		if err := binding.collect(ctx); err != nil {
			server.sessions.reclaim.Store(binding)
			if !errors.Is(err, context.Canceled) {
				slog.Warn("dashboard session reclamation deferred", ComponentKey, "dashboard", "error", err)
			}
		}
		return nil
	}
	return errors.New("dashboard token changed concurrently")
}

// The listener owns collection and rollback retries, independently of requests.
func (manager *sessions) retryCleanup(ctx context.Context) {
	delay := 100 * time.Millisecond
	var lastError string
	var nextWarning time.Time
	for {
		timer := time.NewTimer(delay + time.Duration(mathrand.Int64N(int64(delay)/5+1)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		pending := manager.reclaim.Load()
		manager.mu.Lock()
		rollbackCount := len(manager.rollbacks)
		manager.mu.Unlock()
		if pending == nil && rollbackCount == 0 {
			delay = 5 * time.Second
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, sessionStoreTimeout)
		err := manager.retryRollbacks(attempt)
		if err == nil && pending != nil {
			binding, readErr := manager.binding.Load().latest(attempt)
			if readErr != nil {
				err = readErr
			} else if binding == nil {
				err = errors.New("dashboard token metadata unavailable for reclamation")
			} else {
				err = binding.collect(attempt)
			}
		}
		cancel()
		if err == nil {
			// A concurrent failed registration must retain its own retry request.
			manager.reclaim.CompareAndSwap(pending, nil)
		} else if ctx.Err() == nil && (err.Error() != lastError || time.Now().After(nextWarning)) {
			slog.Warn("dashboard session reclamation retry failed", ComponentKey, "dashboard", "error", err)
			lastError, nextWarning = err.Error(), time.Now().Add(time.Minute)
		}
		delay = min(2*delay, 5*time.Second)
	}
}

func (manager *sessions) rollback(ctx context.Context, allocation sessionRollback) error {
	// Rejected allocations must be removed even after the browser disconnects.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionStoreTimeout)
	defer cancel()
	err := allocation.purge(cleanup)
	if err != nil {
		manager.mu.Lock()
		if manager.rollbacks == nil {
			manager.rollbacks = make(map[string]sessionRollback)
		}
		id := allocation.id()
		if previous, exists := manager.rollbacks[id]; !exists || previous.revision < allocation.revision {
			// One revision cutoff also covers older failed allocations at this key.
			manager.rollbacks[id] = allocation
		}
		manager.mu.Unlock()
	}
	return err
}

func (allocation sessionRollback) id() string {
	if allocation.hash != "" {
		// Lost acknowledgments at a reused slot retain independent ownership checks.
		return allocation.key + "." + allocation.hash
	}
	return allocation.key
}

func (allocation sessionRollback) purge(ctx context.Context) error {
	if allocation.revision == 0 {
		entry, err := allocation.store.get(ctx, allocation.key)
		if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(entry.Data, []byte(allocation.hash)) != 1 {
			return nil
		}
		allocation.revision = entry.Sequence
	}
	return allocation.store.purgeThrough(ctx, allocation.key, allocation.revision)
}

func (manager *sessions) retryRollbacks(ctx context.Context) error {
	manager.mu.Lock()
	allocations := make([]sessionRollback, 0, len(manager.rollbacks))
	for _, allocation := range manager.rollbacks {
		allocations = append(allocations, allocation)
	}
	manager.mu.Unlock()
	for _, allocation := range allocations {
		if err := allocation.purge(ctx); err != nil {
			return err
		}
		manager.mu.Lock()
		if manager.rollbacks[allocation.id()] == allocation {
			delete(manager.rollbacks, allocation.id())
		}
		manager.mu.Unlock()
	}
	return nil
}

func (binding *sessionBinding) current(ctx context.Context) (bool, error) {
	latest, err := binding.latest(ctx)
	return latest != nil && latest.tokenHash == binding.tokenHash && latest.generation == binding.generation, err
}

func (binding *sessionBinding) latest(ctx context.Context) (*sessionBinding, error) {
	entry, err := binding.store.get(ctx, "token."+binding.store.scope)
	if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	token, err := readSessionToken(entry.Data)
	if err != nil {
		return nil, err
	}
	if token.Generation == 0 {
		token.Generation = entry.Sequence
	}
	if token.Hash == binding.tokenHash && token.Generation == binding.generation {
		return binding, nil
	}
	return &sessionBinding{store: binding.store, tokenHash: token.Hash, generation: token.Generation}, nil
}

func (manager *sessions) reconcile(ctx context.Context, binding *sessionBinding) (*sessionBinding, error) {
	latest, err := binding.latest(ctx)
	if latest != nil && latest.tokenHash != binding.tokenHash {
		return nil, nil
	}
	if latest != nil && latest != binding {
		manager.binding.CompareAndSwap(binding, latest)
	}
	return latest, err
}

func (binding *sessionBinding) key(value string) string {
	slot, _ := sessionSlot(value)
	return "session." + binding.store.scope + "." + strconv.FormatUint(binding.generation, 10) + "." + slot
}

// collect deletes immutable records from older generations without KV purge
// markers. A stale controller never deletes a newer generation's sessions.
func (binding *sessionBinding) collect(ctx context.Context) error {
	watcher, err := binding.store.kv.Watch(ctx, "session."+binding.store.scope+".>", jetstream.MetaOnly())
	if err != nil {
		return err
	}
	defer watcher.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, ok := <-watcher.Updates():
			if !ok {
				if err := ctx.Err(); err != nil {
					return err
				}
				return errors.New("dashboard session enumeration interrupted")
			}
			if entry == nil {
				return nil
			}
			parts := strings.Split(entry.Key(), ".")
			if len(parts) != 4 {
				continue
			}
			generation, err := strconv.ParseUint(parts[2], 10, 64)
			if err != nil {
				return err
			}
			if generation < binding.generation || entry.Operation() != jetstream.KeyValuePut {
				if err := binding.store.purgeThrough(ctx, entry.Key(), entry.Revision()); err != nil {
					return err
				}
			}
		}
	}
}

// A sequence cutoff preserves a slot reused concurrently after logout or
// enumeration, while removing retired records and their purge markers.
func (store *SessionStore) purgeThrough(ctx context.Context, key string, revision uint64) error {
	return store.stream.Purge(ctx, jetstream.WithPurgeSubject("$KV."+SessionBucket+"."+key), jetstream.WithPurgeSequence(revision+1))
}

// A busy scope needs one metadata snapshot, not a leader RPC per occupied
// slot. Purge markers are reusable; CAS resolves allocations after the snapshot.
func (binding *sessionBinding) occupied(ctx context.Context) ([maxSessions]bool, error) {
	var occupied [maxSessions]bool
	prefix := "session." + binding.store.scope + "." + strconv.FormatUint(binding.generation, 10) + "."
	watcher, err := binding.store.kv.Watch(ctx, prefix+"*", jetstream.MetaOnly())
	if err != nil {
		return occupied, err
	}
	defer watcher.Stop()
	for {
		select {
		case <-ctx.Done():
			return occupied, ctx.Err()
		case entry, ok := <-watcher.Updates():
			if !ok {
				return occupied, errors.New("dashboard session enumeration interrupted")
			}
			if entry == nil {
				return occupied, nil
			}
			if entry.Operation() != jetstream.KeyValuePut {
				continue
			}
			slot, err := strconv.Atoi(strings.TrimPrefix(entry.Key(), prefix))
			if err != nil || slot < 0 || slot >= maxSessions {
				return occupied, errors.New("invalid dashboard session slot")
			}
			occupied[slot] = true
		}
	}
}

func (manager *sessions) issue(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sessionStoreTimeout)
	defer cancel()
	binding := manager.binding.Load()
	if binding == nil && manager.local == nil {
		return "", errors.New("dashboard session store unavailable")
	}
	if binding != nil {
		var err error
		binding, err = manager.reconcile(ctx, binding)
		if err != nil {
			return "", err
		}
		if binding == nil {
			return "", errors.New("dashboard token retired")
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw[:])
	if binding == nil {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if len(manager.local) >= maxSessions {
			return "", errSessionCapacity
		}
		value := "v3.0." + encoded
		manager.local[sessionHash(value)] = struct{}{}
		return value, nil
	}
	// Fixed CAS-allocated slots enforce capacity across all controllers,
	// including simultaneous logins. Only the cookie's digest is stored.
	start := (int(raw[0])<<8 | int(raw[1])) % maxSessions
	const probes = 8
	var occupied [maxSessions]bool
	for offset := range maxSessions + probes {
		if offset == probes {
			var err error
			occupied, err = binding.occupied(ctx)
			if err != nil {
				return "", err
			}
		}
		slot := (start + offset) % maxSessions
		if occupied[slot] {
			continue
		}
		value := "v3." + strconv.Itoa(slot) + "." + encoded
		revision, err := binding.store.kv.Create(ctx, binding.key(value), []byte(sessionHash(value)))
		if errors.Is(err, jetstream.ErrKeyExists) {
			occupied[slot] = true
			continue
		}
		if err != nil {
			return "", errors.Join(err, manager.rollback(ctx, sessionRollback{store: binding.store, key: binding.key(value), hash: sessionHash(value)}))
		}
		// Rotation can finish cleanup before this in-flight allocation commits.
		current, err := binding.current(ctx)
		if err != nil || !current {
			if err == nil {
				err = errors.New("dashboard token retired")
			}
			return "", errors.Join(err, manager.rollback(ctx, sessionRollback{store: binding.store, key: binding.key(value), revision: revision}))
		}
		return value, nil
	}
	return "", errSessionCapacity
}

func sessionSlot(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "v3" {
		return "", false
	}
	slot, err := strconv.Atoi(parts[1])
	if err != nil || slot < 0 || slot >= maxSessions || strconv.Itoa(slot) != parts[1] {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != parts[2] {
		return "", false
	}
	return parts[1], true
}

func validSessionValue(value string) bool {
	_, ok := sessionSlot(value)
	return ok
}

func (manager *sessions) valid(ctx context.Context, value string) (bool, error) {
	if !validSessionValue(value) {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, sessionStoreTimeout)
	defer cancel()
	binding := manager.binding.Load()
	if binding == nil {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if manager.local == nil {
			return false, errors.New("dashboard session store unavailable")
		}
		_, ok := manager.local[sessionHash(value)]
		return ok, nil
	}
	// Uncached leader reads prevent stale grants after another controller's
	// logout or token rotation; outages must not authorize cached sessions.
	entry, err := binding.store.get(ctx, binding.key(value))
	if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, jetstream.ErrKeyNotFound) ||
		err == nil && subtle.ConstantTimeCompare(entry.Data, []byte(sessionHash(value))) != 1 {
		// Only a miss needs reconciliation; successful reads keep the final fence.
		latest, reconcileErr := manager.reconcile(ctx, binding)
		if reconcileErr != nil || latest == nil || latest == binding {
			return false, reconcileErr
		}
		binding = latest
		entry, err = binding.store.get(ctx, binding.key(value))
	}
	if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, jetstream.ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(entry.Data, []byte(sessionHash(value))) != 1 {
		return false, nil
	}
	// Rotation can commit while the session read is in flight, before cleanup.
	return binding.current(ctx)
}

func (manager *sessions) revoke(ctx context.Context, value string) error {
	if !validSessionValue(value) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, sessionStoreTimeout)
	defer cancel()
	binding := manager.binding.Load()
	if binding == nil {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if manager.local == nil {
			return errors.New("dashboard session store unavailable")
		}
		delete(manager.local, sessionHash(value))
		return nil
	}
	var err error
	// Logout proves cookie possession even on a listener with a retired token.
	binding, err = binding.latest(ctx)
	if err != nil || binding == nil {
		return err
	}
	entry, err := binding.store.get(ctx, binding.key(value))
	if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(entry.Data, []byte(sessionHash(value))) != 1 {
		return nil
	}
	key := binding.key(value)
	err = binding.store.kv.Purge(ctx, key, jetstream.LastRevision(entry.Sequence))
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return nil
	}
	if err != nil {
		return err
	}
	marker, err := binding.store.leader.GetLastMsg("KV_"+SessionBucket, "$KV."+SessionBucket+"."+key, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if marker.Header.Get("KV-Operation") == "PURGE" {
		return binding.store.purgeThrough(ctx, key, marker.Sequence)
	}
	return nil
}

func (manager *sessions) cookie(value string) *http.Cookie {
	cookie := &http.Cookie{Name: SessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: manager.secure, SameSite: http.SameSiteStrictMode}
	if value == "" {
		cookie.MaxAge = -1
	} else {
		// Browsers cap persistent cookies (Chromium: 400 days). Refresh on
		// authenticated requests; the server-side session never expires.
		cookie.MaxAge = 1<<31 - 1
		cookie.Expires = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	}
	return cookie
}

func (manager *sessions) authenticated(request *http.Request) (bool, error) {
	cookie, err := request.Cookie(SessionCookieName)
	if err != nil {
		return false, nil
	}
	return manager.valid(request.Context(), cookie.Value)
}

// HandleLogin mounts the browser login routes of the dashboard. page renders
// GET /login; POST /login exchanges the bearer token for a session cookie and
// POST /logout clears it. Without HandleLogin, or on a tokenless loopback
// listener, browsers have no session path and only the bearer header works.
func (server *Server) HandleLogin(page http.Handler) {
	server.loginMounted.Store(true)
	server.mux.Handle("GET /login", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.token == nil {
			http.Redirect(writer, request, LocalRedirectPath(request.URL.Query().Get("next")), http.StatusSeeOther)
			return
		}
		authenticated, err := server.sessions.authenticated(request)
		if err != nil {
			writePlain(writer, http.StatusServiceUnavailable, "session storage unavailable\n")
			return
		}
		if authenticated {
			http.Redirect(writer, request, LocalRedirectPath(request.URL.Query().Get("next")), http.StatusSeeOther)
			return
		}
		page.ServeHTTP(writer, request)
	}))
	server.mux.HandleFunc("POST /login", server.login)
	server.mux.HandleFunc("POST /logout", func(writer http.ResponseWriter, request *http.Request) {
		if !sameOriginForm(request) {
			writePlain(writer, http.StatusForbidden, "cross-site request refused\n")
			return
		}
		// Revoke the session itself, not only this browser's cookie: a
		// copied cookie stops working too.
		if cookie, err := request.Cookie(SessionCookieName); err == nil {
			if err := server.sessions.revoke(request.Context(), cookie.Value); err != nil {
				writePlain(writer, http.StatusServiceUnavailable, "session revocation unavailable\n")
				return
			}
		}
		http.SetCookie(writer, server.sessions.cookie(""))
		http.Redirect(writer, request, "/login", http.StatusSeeOther)
	})
}

func (server *Server) login(writer http.ResponseWriter, request *http.Request) {
	if server.token == nil {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if !sameOriginForm(request) {
		writePlain(writer, http.StatusForbidden, "cross-site request refused\n")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxLoginFormSize)
	if err := request.ParseForm(); err != nil {
		writePlain(writer, http.StatusBadRequest, "invalid login form\n")
		return
	}
	next := LocalRedirectPath(request.PostForm.Get("next"))
	presented := strings.TrimSpace(request.PostForm.Get("token"))
	if subtle.ConstantTimeCompare([]byte(presented), server.token) != 1 {
		http.Redirect(writer, request, "/login?failed=1&next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), sessionStoreTimeout)
	defer cancel()
	if cookie, err := request.Cookie(SessionCookieName); err == nil {
		valid, err := server.sessions.valid(ctx, cookie.Value)
		if err != nil {
			writePlain(writer, http.StatusServiceUnavailable, "session storage unavailable\n")
			return
		}
		if valid {
			http.SetCookie(writer, server.sessions.cookie(cookie.Value))
			http.Redirect(writer, request, next, http.StatusSeeOther)
			return
		}
	}
	value, err := server.sessions.issue(ctx)
	if err != nil {
		if errors.Is(err, errSessionCapacity) {
			writePlain(writer, http.StatusServiceUnavailable, "dashboard session limit reached; sign out in another browser or rotate the dashboard token\n")
			return
		}
		writePlain(writer, http.StatusServiceUnavailable, "session storage unavailable\n")
		return
	}
	http.SetCookie(writer, server.sessions.cookie(value))
	http.Redirect(writer, request, next, http.StatusSeeOther)
}

// sameOriginForm refuses a form post another site's page submitted. Browsers
// send Sec-Fetch-Site, and Origin on every POST; a non-browser client that
// sends neither is not a cross-site request.
func sameOriginForm(request *http.Request) bool {
	switch request.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := request.Header.Get("Origin")
	if origin == "null" {
		return request.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return err == nil && parsed.Host == request.Host && parsed.Scheme == scheme &&
		parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

// LocalRedirectPath returns raw when it is a path on this listener, and "/"
// otherwise, so a login link cannot redirect a browser to another site.
func LocalRedirectPath(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") ||
		strings.ContainsAny(raw, "\\\r\n\t") || len(raw) > 512 {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return "/"
	}
	return raw
}

// wantsLoginPage reports a browser navigation that should be sent to the
// login form instead of receiving a bare 401.
func wantsLoginPage(request *http.Request) bool {
	return request.Method == http.MethodGet && request.Header.Get("Datastar-Request") == "" && request.Header.Get("Authorization") == "" &&
		strings.Contains(request.Header.Get("Accept"), "text/html")
}
