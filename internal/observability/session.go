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
	"time"
)

const (
	// SessionCookieName carries a browser session on a token-protected
	// listener with the dashboard enabled.
	SessionCookieName = "ts_orch_session"
	// SessionTTL bounds one browser session. Sessions are not persisted: a
	// process restart signs every browser out.
	SessionTTL = 12 * time.Hour

	sessionVersion   = "v1"
	maxLoginFormSize = 8 << 10
)

// sessions issues and verifies browser session cookies. A cookie proves only
// that its holder presented the listener's bearer token within SessionTTL to
// this process: the MAC key is random per process and never leaves memory,
// so a cookie grants exactly the read-only access the token grants.
type sessions struct {
	key    [32]byte
	secure bool
	now    func() time.Time
}

func newSessions(secure bool) (*sessions, error) {
	manager := &sessions{secure: secure, now: time.Now}
	if _, err := rand.Read(manager.key[:]); err != nil {
		return nil, err
	}
	return manager, nil
}

func (manager *sessions) mac(payload string) []byte {
	digest := hmac.New(sha256.New, manager.key[:])
	digest.Write([]byte("ts-orch dashboard session\x00" + payload))
	return digest.Sum(nil)
}

// issue returns a cookie value "v1.<expiry unix>.<mac>".
func (manager *sessions) issue() (string, time.Time) {
	expires := manager.now().Add(SessionTTL).Truncate(time.Second)
	payload := sessionVersion + "." + strconv.FormatInt(expires.Unix(), 10)
	return payload + "." + base64.RawURLEncoding.EncodeToString(manager.mac(payload)), expires
}

func (manager *sessions) valid(value string) bool {
	version, rest, found := strings.Cut(value, ".")
	if !found || version != sessionVersion {
		return false
	}
	expiry, encoded, found := strings.Cut(rest, ".")
	if !found {
		return false
	}
	seconds, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != expiry {
		return false
	}
	presented, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || !hmac.Equal(presented, manager.mac(version+"."+expiry)) {
		return false
	}
	// A cookie claiming a lifetime longer than SessionTTL was not issued
	// by this process, whatever its MAC says.
	now := manager.now()
	expires := time.Unix(seconds, 0)
	return now.Before(expires) && !expires.After(now.Add(SessionTTL))
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
	server.loginMounted = true
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
