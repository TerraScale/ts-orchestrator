package observability

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newLoginServer(t *testing.T) (*Server, string) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("s", 48)
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile, Dashboard: true},
		ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	server.HandleLogin(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("login form"))
	}))
	server.Handle("GET /{$}", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("dashboard"))
	}))
	return server, token
}

func postLogin(server *Server, form url.Values, headers ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	return recorder
}

func TestLoginExchangesTokenForSessionCookie(t *testing.T) {
	t.Parallel()
	server, token := newLoginServer(t)

	browse := httptest.NewRequest(http.MethodGet, "/?tab=1", nil)
	browse.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, browse)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/login?next=%2F%3Ftab%3D1" {
		t.Fatalf("unauthenticated browser = %d %q", recorder.Code, recorder.Header().Get("Location"))
	}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API client = %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "login form" {
		t.Fatalf("GET /login = %d %q", recorder.Code, recorder.Body.String())
	}

	failed := postLogin(server, url.Values{"token": {"wrong"}, "next": {"/nats"}})
	if failed.Code != http.StatusSeeOther || !strings.HasPrefix(failed.Header().Get("Location"), "/login?failed=1") ||
		len(failed.Result().Cookies()) != 0 {
		t.Fatalf("wrong token login = %d %q", failed.Code, failed.Header().Get("Location"))
	}
	crossSite := postLogin(server, url.Values{"token": {token}}, "Sec-Fetch-Site", "cross-site")
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site login = %d", crossSite.Code)
	}
	foreignOrigin := postLogin(server, url.Values{"token": {token}}, "Origin", "https://evil.example")
	if foreignOrigin.Code != http.StatusForbidden {
		t.Fatalf("foreign origin login = %d", foreignOrigin.Code)
	}

	ok := postLogin(server, url.Values{"token": {token}, "next": {"/nats"}}, "Origin", "http://example.com",
		"Sec-Fetch-Site", "same-origin")
	cookies := ok.Result().Cookies()
	if ok.Code != http.StatusSeeOther || ok.Header().Get("Location") != "/nats" || len(cookies) != 1 {
		t.Fatalf("login = %d %q cookies=%d", ok.Code, ok.Header().Get("Location"), len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure || cookie.Path != "/" {
		t.Fatalf("session cookie attributes = %+v", cookie)
	}
	authed := httptest.NewRequest(http.MethodGet, "/", nil)
	authed.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, authed)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "dashboard" {
		t.Fatalf("session request = %d %q", recorder.Code, recorder.Body.String())
	}
	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie.Value[:len(cookie.Value)-2] + "AA"})
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, tampered)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("tampered cookie = %d", recorder.Code)
	}

	logout := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logout.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, logout)
	if recorder.Code != http.StatusSeeOther || len(recorder.Result().Cookies()) != 1 ||
		recorder.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout = %d %+v", recorder.Code, recorder.Result().Cookies())
	}
	// A copy of the signed-out cookie no longer authenticates.
	copied := httptest.NewRequest(http.MethodGet, "/", nil)
	copied.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, copied)
	if recorder.Code == http.StatusOK {
		t.Fatalf("a signed-out session still authenticates: %d", recorder.Code)
	}
}

func TestSessionCookieIsBoundToProcessKeyAndLifetime(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	manager, err := newSessions(true)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	value, expires := manager.issue()
	if !manager.valid(value) || !expires.Equal(now.Add(SessionTTL)) {
		t.Fatalf("fresh session invalid: %q", value)
	}
	if cookie := manager.cookie(value, expires); !cookie.Secure {
		t.Fatal("TLS listener session cookie is not Secure")
	}
	other, err := newSessions(true)
	if err != nil {
		t.Fatal(err)
	}
	other.now = manager.now
	if other.valid(value) {
		t.Fatal("a session from another process key was accepted")
	}
	manager.now = func() time.Time { return now.Add(SessionTTL + time.Second) }
	if manager.valid(value) {
		t.Fatal("an expired session was accepted")
	}
	// A correctly signed payload claiming a longer lifetime is refused.
	manager.now = func() time.Time { return now }
	payload := sessionVersion + "." + strconv.FormatInt(now.Add(2*SessionTTL).Unix(), 10) + "." + base64URL(make([]byte, 16))
	forged := payload + "." + base64URL(manager.mac(payload))
	if manager.valid(forged) {
		t.Fatal("an over-long session was accepted")
	}
	for _, value := range []string{"", "v1", "v1.1", "v2.1.AA", "v1.+1.AA", "v1.01." + strings.Repeat("A", 43),
		"v2.1.AA.AA", value + ".x"} {
		if manager.valid(value) {
			t.Fatalf("malformed session %q accepted", value)
		}
	}
}

func TestSessionCookieIgnoredWithoutDashboardLogin(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("s", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile},
		ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	value, _ := server.sessions.issue()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Accept", "text/html")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie without dashboard login = %d", recorder.Code)
	}
}

func TestLocalRedirectPath(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"":                       "/",
		"/nats?x=1":              "/nats?x=1",
		"//evil.example":         "/",
		"https://evil.example/":  "/",
		"/\\evil.example":        "/",
		"nats":                   "/",
		"/ok\r\nSet-Cookie: a=b": "/",
	} {
		if got := LocalRedirectPath(raw); got != want {
			t.Errorf("LocalRedirectPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

func base64URL(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func TestSignOutRevokesEveryCopyOfTheSession(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	manager, err := newSessions(false)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	first, _ := manager.issue()
	second, _ := manager.issue()
	if first == second {
		t.Fatal("two logins in the same second share a session")
	}
	manager.revoke(first)
	if manager.valid(first) || !manager.valid(second) {
		t.Fatal("revoking one session did not end exactly that session")
	}
	// Expired revocations are forgotten, and a flood rotates the key.
	manager.now = func() time.Time { return now.Add(SessionTTL + time.Second) }
	third, _ := manager.issue()
	manager.revoke(third)
	if len(manager.revoked) != 1 {
		t.Fatalf("revoked = %d, want the expired entry pruned", len(manager.revoked))
	}
	fourth, _ := manager.issue()
	for range maxRevoked {
		value, _ := manager.issue()
		manager.revoke(value)
	}
	if manager.valid(fourth) {
		t.Fatal("past the revocation bound the key did not rotate")
	}
}
