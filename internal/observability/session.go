package observability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	SessionCookieName = "ts_orch_session"
	// SessionBucket contains only hashes and token generations, with no TTL.
	SessionBucket    = "TS_DASHBOARD_SESSIONS"
	maxLoginFormSize = 8 << 10
)

// SessionStore persists sessions in the regional bootstrap store. Scope keeps
// the NetBird token separate from an independently configured local listener.
type SessionStore struct {
	kv     jetstream.KeyValue
	leader nats.JetStreamContext
	scope  string
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
	return &SessionStore{kv: kv, leader: leader, scope: sessionHash(scope)}, nil
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
	secure  bool
	binding atomic.Pointer[sessionBinding]
}

type sessionBinding struct {
	store      *SessionStore
	tokenHash  string
	generation uint64
}

// SetSessionStore enables browser login once the controller's NATS is ready.
// CAS makes a changed token advance the generation once across controllers;
// restoring an old token cannot resurrect its previous sessions.
func (server *Server) SetSessionStore(ctx context.Context, store *SessionStore) error {
	if store == nil || server.token == nil {
		return errors.New("dashboard sessions require a store and a token")
	}
	hash := sessionHash(string(server.token))
	key := "token." + store.scope
	for attempts := 0; attempts < 8; attempts++ {
		entry, err := store.get(ctx, key)
		var revision uint64
		switch {
		case errors.Is(err, nats.ErrMsgNotFound), errors.Is(err, jetstream.ErrKeyNotFound):
			revision, err = store.kv.Create(ctx, key, []byte(hash))
		case err != nil:
			return err
		case string(entry.Data) == hash:
			revision = entry.Sequence
		default:
			revision, err = store.kv.Update(ctx, key, []byte(hash), entry.Sequence)
		}
		if errors.Is(err, jetstream.ErrKeyExists) {
			continue
		}
		if err != nil {
			return err
		}
		server.sessions.binding.Store(&sessionBinding{store: store, tokenHash: hash, generation: revision})
		return nil
	}
	return errors.New("dashboard token changed concurrently")
}

func (binding *sessionBinding) current(ctx context.Context) bool {
	entry, err := binding.store.get(ctx, "token."+binding.store.scope)
	return err == nil && entry.Sequence == binding.generation && string(entry.Data) == binding.tokenHash
}

func (binding *sessionBinding) key(value string) string {
	return "session." + binding.store.scope + "." + sessionHash(value)
}

func (manager *sessions) issue(ctx context.Context) (string, error) {
	binding := manager.binding.Load()
	if binding == nil || !binding.current(ctx) {
		return "", errors.New("dashboard session store unavailable or token retired")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw[:])
	_, err := binding.store.kv.Create(ctx, binding.key(value), []byte(strconv.FormatUint(binding.generation, 10)))
	if err != nil {
		return "", err
	}
	return value, nil
}

func (manager *sessions) valid(ctx context.Context, value string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return false
	}
	binding := manager.binding.Load()
	if binding == nil || !binding.current(ctx) {
		return false
	}
	entry, err := binding.store.get(ctx, binding.key(value))
	return err == nil && string(entry.Data) == strconv.FormatUint(binding.generation, 10)
}

func (manager *sessions) revoke(ctx context.Context, value string) error {
	binding := manager.binding.Load()
	if binding == nil {
		return errors.New("dashboard session store unavailable")
	}
	return binding.store.kv.Purge(ctx, binding.key(value))
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

func (manager *sessions) authenticated(request *http.Request) bool {
	cookie, err := request.Cookie(SessionCookieName)
	return err == nil && manager.valid(request.Context(), cookie.Value)
}

// HandleLogin mounts the browser login routes of the dashboard. page renders
// GET /login; POST /login exchanges the bearer token for a session cookie and
// POST /logout clears it. Without HandleLogin, or on a tokenless loopback
// listener, browsers have no session path and only the bearer header works.
func (server *Server) HandleLogin(page http.Handler) {
	server.loginMounted.Store(true)
	server.mux.Handle("GET /login", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.token == nil || server.sessions.authenticated(request) {
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
	value, err := server.sessions.issue(request.Context())
	if err != nil {
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
