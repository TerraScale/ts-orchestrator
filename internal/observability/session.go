package observability

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SessionCookieName carries a browser session on a token-protected
	// listener with the dashboard enabled.
	SessionCookieName = "ts_orch_session"
	// SessionTTL bounds one browser session. Sessions are not persisted: a
	// process restart signs every browser out.
	SessionTTL = 12 * time.Hour

	sessionVersion   = "v2"
	maxLoginFormSize = 8 << 10
	// maxRevoked bounds the signed-out sessions remembered until they
	// expire; past it the process key rotates, which signs everyone out.
	maxRevoked = 4096
)

// sessions issues and verifies browser session cookies. A cookie proves only
// that its holder presented the listener's bearer token within SessionTTL to
// this process: the MAC key is random per process and never leaves memory,
// so a cookie grants exactly the read-only access the token grants.
type sessions struct {
	mu  sync.Mutex
	key [32]byte
	// generation counts key rotations. A cookie verified against one key
	// is accepted only while that key is still current, so a rotation that
	// clears revoked cannot resurrect a revoked cookie mid-verification.
	generation uint64
	secure     bool
	now        func() time.Time
	// revoked holds the IDs of signed-out sessions until they expire, so
	// signing out ends the session for every copy of the cookie.
	revoked map[string]time.Time
}

func newSessions(secure bool) (*sessions, error) {
	manager := &sessions{secure: secure, now: time.Now, revoked: map[string]time.Time{}}
	if _, err := rand.Read(manager.key[:]); err != nil {
		return nil, err
	}
	return manager, nil
}

// currentKey returns the signing key and its rotation generation.
func (manager *sessions) currentKey() ([32]byte, uint64) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.key, manager.generation
}

func sessionMAC(key [32]byte, payload string) []byte {
	digest := hmac.New(sha256.New, key[:])
	digest.Write([]byte("ts-orch dashboard session\x00" + payload))
	return digest.Sum(nil)
}

// issue returns a cookie value "v2.<expiry unix>.<session id>.<mac>". The
// random session ID makes every login distinct and revocable.
func (manager *sessions) issue() (string, time.Time) {
	expires := manager.now().Add(SessionTTL).Truncate(time.Second)
	var id [16]byte
	_, _ = rand.Read(id[:])
	payload := sessionVersion + "." + strconv.FormatInt(expires.Unix(), 10) + "." +
		base64.RawURLEncoding.EncodeToString(id[:])
	key, _ := manager.currentKey()
	return payload + "." + base64.RawURLEncoding.EncodeToString(sessionMAC(key, payload)), expires
}

// parse verifies a cookie value and returns its session ID, expiry and the
// key generation that verified it. Callers must recheck the generation under
// mu before trusting the result.
func (manager *sessions) parse(value string) (string, time.Time, uint64, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != sessionVersion {
		return "", time.Time{}, 0, false
	}
	expiry, id, encoded := parts[1], parts[2], parts[3]
	seconds, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != expiry {
		return "", time.Time{}, 0, false
	}
	if raw, err := base64.RawURLEncoding.DecodeString(id); err != nil || len(raw) != 16 {
		return "", time.Time{}, 0, false
	}
	key, generation := manager.currentKey()
	presented, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || !hmac.Equal(presented, sessionMAC(key, parts[0]+"."+expiry+"."+id)) {
		return "", time.Time{}, 0, false
	}
	// A cookie claiming a lifetime longer than SessionTTL was not issued
	// by this process, whatever its MAC says.
	now := manager.now()
	expires := time.Unix(seconds, 0)
	if !now.Before(expires) || expires.After(now.Add(SessionTTL)) {
		return "", time.Time{}, 0, false
	}
	return id, expires, generation, true
}

func (manager *sessions) valid(value string) bool {
	id, _, generation, ok := manager.parse(value)
	return ok && manager.accept(id, generation)
}

// accept reports whether a session verified under key generation is still
// live. The generation check and the revocation lookup share one lock, so a
// concurrent rotation cannot slip between them.
func (manager *sessions) accept(id string, generation uint64) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if generation != manager.generation {
		// The key rotated after the MAC check: the cookie was signed
		// with a retired key, and revoked no longer remembers it.
		return false
	}
	_, revoked := manager.revoked[id]
	return !revoked
}

// revoke ends a session for every copy of its cookie until it expires.
func (manager *sessions) revoke(value string) {
	id, expires, generation, ok := manager.parse(value)
	if !ok {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if generation != manager.generation {
		// Already invalid: the key that signed it is retired.
		return
	}
	now := manager.now()
	for other, until := range manager.revoked {
		if !now.Before(until) {
			delete(manager.revoked, other)
		}
	}
	if len(manager.revoked) >= maxRevoked {
		// Too many live sign-outs to remember: a new key ends every
		// session instead, which is the safe direction.
		_, _ = rand.Read(manager.key[:])
		manager.generation++
		clear(manager.revoked)
		return
	}
	manager.revoked[id] = expires
}

func (manager *sessions) cookie(value string, expires time.Time) *http.Cookie {
	cookie := &http.Cookie{Name: SessionCookieName, Value: value, Path: "/", HttpOnly: true,
		Secure: manager.secure, SameSite: http.SameSiteStrictMode}
	if value == "" {
		cookie.MaxAge = -1
	} else {
		cookie.Expires = expires
	}
	return cookie
}

func (manager *sessions) authenticated(request *http.Request) bool {
	cookie, err := request.Cookie(SessionCookieName)
	return err == nil && manager.valid(cookie.Value)
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
			server.sessions.revoke(cookie.Value)
		}
		http.SetCookie(writer, server.sessions.cookie("", time.Time{}))
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
	value, expires := server.sessions.issue()
	http.SetCookie(writer, server.sessions.cookie(value, expires))
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
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host == request.Host && (parsed.Scheme == "http" || parsed.Scheme == "https")
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
	return request.Method == http.MethodGet && request.Header.Get("Datastar-Request") == "" &&
		strings.Contains(request.Header.Get("Accept"), "text/html")
}
