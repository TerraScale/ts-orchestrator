package observability

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
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
		ServerDeps{Registry: NewRegistry(false), Health: new(Health), Sessions: newTestSessionStore(t)})
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
	if len(recorder.Result().Cookies()) != 1 || recorder.Result().Cookies()[0].Value != cookie.Value {
		t.Fatal("authenticated request did not refresh the persistent cookie")
	}
	authed.Header.Set("Authorization", "Bearer invalid")
	authed.Header.Set("Accept", "text/html")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, authed)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatal("invalid bearer bypassed by browser cookie")
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
	value := strings.Repeat("A", 43)
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

// The Server documents mounting routes before or after Start; mounting the
// login after the listener serves must not race with requests reading the
// flag (run with -race).
func TestHandleLoginAfterServingDoesNotRace(t *testing.T) {
	t.Parallel()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("s", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile, Dashboard: true},
		ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			request.Header.Set("Accept", "text/html")
			server.ServeHTTP(httptest.NewRecorder(), request)
		}
	}()
	server.HandleLogin(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	<-done
}

func newTestSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSessionStore(t.Context(), js, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSessionsPersistAndTokenRotationRevokesPermanently(t *testing.T) {
	t.Parallel()
	store := newTestSessionStore(t)
	token := strings.Repeat("a", 48)
	build := func(token string) *Server {
		t.Helper()
		server, err := NewTokenServer(Config{Dashboard: true}, token, ServerDeps{
			Registry: NewRegistry(false), Health: new(Health), Sessions: store})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	first := build(token)
	value, err := first.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second := build(token)
	if !sessionValid(t, second.sessions, t.Context(), value) {
		t.Fatal("restart lost the session")
	}
	binding := second.sessions.binding.Load()
	entry, err := store.get(t.Context(), binding.key(value))
	if err != nil || strings.Contains(string(entry.Data), value) || strings.Contains(binding.key(value), value) {
		t.Fatal("store must contain the session hash, never its raw value")
	}
	info, err := store.kv.Status(t.Context())
	if err != nil || info.TTL() != 0 {
		t.Fatal("session store has an expiry")
	}
	cookie := second.sessions.cookie(value)
	if !cookie.HttpOnly || cookie.MaxAge < 1<<30 || cookie.Expires.Year() != 9999 {
		t.Fatal("session cookie is not persistent")
	}
	for _, invalid := range []string{"", "v2.123.x.y", value + "x", strings.Repeat("A", 43)} {
		if sessionValid(t, second.sessions, t.Context(), invalid) {
			t.Fatal("invalid session accepted")
		}
	}
	other, err := second.sessions.issue(t.Context())
	if err != nil || other == value {
		t.Fatal("login did not create a unique session")
	}
	if err := second.sessions.revoke(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if sessionValid(t, first.sessions, t.Context(), value) || !sessionValid(t, first.sessions, t.Context(), other) {
		t.Fatal("logout did not revoke exactly the copied session")
	}
	rotated := build(strings.Repeat("b", 48))
	if sessionValid(t, first.sessions, t.Context(), other) || sessionValid(t, rotated.sessions, t.Context(), other) {
		t.Fatal("token rotation did not revoke sessions on every controller")
	}
	restored := build(token)
	if sessionValid(t, restored.sessions, t.Context(), other) {
		t.Fatal("restored token resurrected a session")
	}
	if _, err := rotated.sessions.issue(t.Context()); err == nil {
		t.Fatal("retired token issued a session")
	}
}

func TestSameOriginForms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		origin, site string
		want         bool
	}{
		{"null", "same-origin", true}, {"null", "cross-site", false},
		{"null", "same-site", false}, {"null", "none", false}, {"null", "", false},
		{"http://example.com", "same-origin", true}, {"http://example.com", "", true},
		{"https://example.com", "same-origin", false}, {"http://example.com:99", "same-origin", false},
		{"http://evil.example", "same-origin", false}, {"http://example.com", "cross-site", false},
		{"http://example.com", "same-site", false}, {"", "cross-site", false}, {"", "same-origin", true},
		{"", "", true}, {"http://user@example.com", "same-origin", false},
	} {
		request := httptest.NewRequest(http.MethodPost, "http://example.com/login", nil)
		request.Header.Set("Origin", tc.origin)
		request.Header.Set("Sec-Fetch-Site", tc.site)
		if got := sameOriginForm(request); got != tc.want {
			t.Errorf("origin=%q site=%q: got %v want %v", tc.origin, tc.site, got, tc.want)
		}
	}
	server, token := newLoginServer(t)
	response := postLogin(server, url.Values{"token": {token}}, "Origin", "null", "Sec-Fetch-Site", "same-origin")
	if response.Code != http.StatusSeeOther {
		t.Fatalf("opaque same-origin login = %d", response.Code)
	}
	cookie := response.Result().Cookies()[0]
	for _, site := range []string{"cross-site", "same-site", "same-origin"} {
		request := httptest.NewRequest(http.MethodPost, "/logout", nil)
		request.Header.Set("Origin", "null")
		request.Header.Set("Sec-Fetch-Site", site)
		request.AddCookie(cookie)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		want := http.StatusForbidden
		if site == "same-origin" {
			want = http.StatusSeeOther
		}
		if recorder.Code != want {
			t.Fatalf("logout site=%q: %d", site, recorder.Code)
		}
	}
}

func TestGuardedPagesRedirectBrowsersButNotBearerOrStreams(t *testing.T) {
	t.Parallel()
	server, _ := newLoginServer(t)
	for _, path := range []string{"/", "/metrics"} {
		for _, tc := range []struct {
			bearer, stream string
			want           int
		}{
			{"", "", http.StatusSeeOther}, {"Bearer invalid", "", http.StatusUnauthorized},
			{"", "true", http.StatusUnauthorized},
		} {
			request := httptest.NewRequest(http.MethodGet, path+"?tab=1", nil)
			request.Header.Set("Accept", "text/html")
			request.Header.Set("Authorization", tc.bearer)
			request.Header.Set("Datastar-Request", tc.stream)
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("%s auth=%q stream=%q: %d", path, tc.bearer, tc.stream, recorder.Code)
			}
			if tc.want == http.StatusSeeOther && recorder.Header().Get("Location") != "/login?next="+url.QueryEscape(path+"?tab=1") {
				t.Fatal("redirect lost the requested path")
			}
		}
	}
}

func TestSessionStorageFailuresFailClosed(t *testing.T) {
	t.Parallel()
	server, token := newLoginServer(t)
	response := postLogin(server, url.Values{"token": {token}})
	cookie := response.Result().Cookies()[0]
	// Use an unbound manager to model unavailable startup without a panic.
	server.sessions.binding.Store(nil)
	response = postLogin(server, url.Values{"token": {token}})
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
		t.Fatal("unavailable storage issued a cookie")
	}
	if valid, err := server.sessions.valid(context.Background(), cookie.Value); valid || err == nil {
		t.Fatal("unavailable storage did not report an authentication error")
	}
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || len(recorder.Result().Cookies()) != 0 {
		t.Fatal("failed revocation reported success")
	}
}

func TestSessionsSurviveBrokerRestart(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	token := strings.Repeat("a", 48)
	start := func() (*natsserver.Server, *nats.Conn, *Server) {
		t.Helper()
		broker, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: directory, NoLog: true, NoSigs: true})
		if err != nil {
			t.Fatal(err)
		}
		go broker.Start()
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("NATS did not start")
		}
		conn, err := nats.Connect(broker.ClientURL())
		if err != nil {
			t.Fatal(err)
		}
		js, err := jetstream.New(conn)
		if err != nil {
			t.Fatal(err)
		}
		store, err := OpenSessionStore(t.Context(), js, 1, "restart")
		if err != nil {
			t.Fatal(err)
		}
		listener, err := NewTokenServer(Config{Dashboard: true}, token, ServerDeps{Registry: NewRegistry(false), Health: new(Health), Sessions: store})
		if err != nil {
			t.Fatal(err)
		}
		return broker, conn, listener
	}
	broker, conn, first := start()
	value, err := first.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := first.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.sessions.revoke(t.Context(), revoked); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	broker.Shutdown()
	broker.WaitForShutdown()
	broker, conn, second := start()
	defer func() { conn.Close(); broker.Shutdown(); broker.WaitForShutdown() }()
	if !sessionValid(t, second.sessions, t.Context(), value) {
		t.Fatal("broker/controller restart lost session")
	}
	if sessionValid(t, second.sessions, t.Context(), revoked) {
		t.Fatal("restart resurrected logged-out session")
	}
	conn.Close()
	if valid, err := second.sessions.valid(t.Context(), value); valid || err == nil {
		t.Fatal("NATS outage did not report an authentication error")
	}
	if _, err := second.sessions.issue(t.Context()); err == nil {
		t.Fatal("NATS outage issued a session")
	}
	if err := second.sessions.revoke(t.Context(), value); err == nil {
		t.Fatal("NATS outage reported successful revocation")
	}
}

func TestLogoutUnknownCookiesNeverWritesAndReusedSlotsRemainValid(t *testing.T) {
	t.Parallel()
	server, token := newLoginServer(t)
	response := postLogin(server, url.Values{"token": {token}})
	cookie := response.Result().Cookies()[0]
	binding := server.sessions.binding.Load()
	before, err := binding.store.kv.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 64 {
		unknown := "v3." + strconv.Itoa(i) + "." + base64.RawURLEncoding.EncodeToString(bytesOf(2))
		request := httptest.NewRequest(http.MethodPost, "/logout", nil)
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: unknown})
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusSeeOther {
			t.Fatal("unknown cookie logout failed")
		}
	}
	for _, malformed := range []string{"garbage", "v3.-1.AA", "v3.1024.AA", "v3.01." + base64.RawURLEncoding.EncodeToString(bytesOf(1))} {
		if err := server.sessions.revoke(t.Context(), malformed); err != nil {
			t.Fatal(err)
		}
	}
	after, err := binding.store.kv.Status(t.Context())
	if err != nil || after.Values() != before.Values() || after.Bytes() != before.Bytes() {
		t.Fatal("unauthenticated logout grew or changed the bucket")
	}
	if !sessionValid(t, server.sessions, t.Context(), cookie.Value) {
		t.Fatal("unknown cookie revoked a legitimate session")
	}
	entry, err := binding.store.get(t.Context(), binding.key(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.sessions.revoke(t.Context(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	// Reuse that exact slot, as a simultaneous login can do after its purge.
	parts := strings.Split(cookie.Value, ".")
	replacement := "v3." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytesOf(3))
	if _, err := binding.store.kv.Create(t.Context(), binding.key(replacement), []byte(sessionHash(replacement))); err != nil {
		t.Fatal(err)
	}
	if err := binding.store.purgeThrough(t.Context(), binding.key(cookie.Value), entry.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := server.sessions.revoke(t.Context(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	if !sessionValid(t, server.sessions, t.Context(), replacement) {
		t.Fatal("stale logout or compaction deleted a reused slot")
	}
	if err := server.sessions.revoke(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	status, err := binding.store.kv.Status(t.Context())
	if err != nil || status.Values() != 1 {
		t.Fatal("logout retained a purge marker")
	}
}

func bytesOf(value byte) []byte {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = value
	}
	return raw
}

func TestSessionCapacityIsSharedAndRotationReclaimsIt(t *testing.T) {
	t.Parallel()
	store := newTestSessionStore(t)
	build := func(token string) *Server {
		t.Helper()
		server, err := NewTokenServer(Config{Dashboard: true}, token, ServerDeps{Registry: NewRegistry(false), Health: new(Health), Sessions: store})
		if err != nil {
			t.Fatal(err)
		}
		server.HandleLogin(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		return server
	}
	token := strings.Repeat("a", 48)
	first, second := build(token), build(token)
	binding := first.sessions.binding.Load()
	for i := range maxSessions - 1 {
		cookie := "v3." + strconv.Itoa(i) + "." + base64.RawURLEncoding.EncodeToString(bytesOf(1))
		if _, err := store.kv.Create(t.Context(), binding.key(cookie), []byte(sessionHash(cookie))); err != nil {
			t.Fatal(err)
		}
	}
	// Model an interrupted logout: its retained marker is still a free slot.
	last := "v3." + strconv.Itoa(maxSessions-1) + "." + base64.RawURLEncoding.EncodeToString(bytesOf(1))
	if _, err := store.kv.Create(t.Context(), binding.key(last), []byte(sessionHash(last))); err != nil {
		t.Fatal(err)
	}
	if err := store.kv.Purge(t.Context(), binding.key(last)); err != nil {
		t.Fatal(err)
	}
	// Occupied slots must not each cost a network round trip. At 5 ms per
	// probe, a serial scan can consume the complete session deadline.
	latency := &slowSessionCreates{KeyValue: store.kv}
	store.kv = latency
	var wg sync.WaitGroup
	results := make(chan error, 2)
	values := make(chan string, 2)
	for _, server := range []*Server{first, second} {
		wg.Go(func() {
			value, err := server.sessions.issue(t.Context())
			results <- err
			if err == nil {
				values <- value
			}
		})
	}
	wg.Wait()
	close(results)
	close(values)
	accepted, rejected := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, errSessionCapacity) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatal("concurrent controllers exceeded the session capacity")
	}
	if latency.creates.Load() > 20 {
		t.Fatal("near-capacity allocation probed occupied slots serially")
	}
	value := <-values
	response := postLogin(first, url.Values{"token": {token}})
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "session limit reached") {
		t.Fatal("full store did not explain how to recover")
	}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
	recorder := httptest.NewRecorder()
	first.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Result().Cookies()[0].Value != value {
		t.Fatal("login failed to reuse an existing session at capacity")
	}
	rotated := build(strings.Repeat("b", 48))
	status, err := store.kv.Status(t.Context())
	if err != nil || status.Values() != 1 {
		t.Fatal("rotation retained abandoned sessions or markers")
	}
	fresh, err := rotated.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !sessionValid(t, rotated.sessions, t.Context(), fresh) {
		t.Fatal("stale controller collected a newer generation")
	}
}

func sessionValid(t *testing.T, manager *sessions, ctx context.Context, value string) bool {
	t.Helper()
	valid, err := manager.valid(ctx, value)
	if err != nil {
		t.Fatal(err)
	}
	return valid
}

type sessionReadFault struct {
	nats.JetStreamContext
	read func(string, string, ...nats.JSOpt) (*nats.RawStreamMsg, error)
}

func (fault sessionReadFault) GetLastMsg(stream, subject string, opts ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	return fault.read(stream, subject, opts...)
}

func TestSessionReadOutagesReturn503WithoutLosingTheCookie(t *testing.T) {
	t.Parallel()
	server, token := newLoginServer(t)
	response := postLogin(server, url.Values{"token": {token}})
	cookie := response.Result().Cookies()[0]
	store := server.sessions.binding.Load().store
	leader := store.leader
	for _, key := range []string{"token", "session"} {
		t.Run(key, func(t *testing.T) {
			store.leader = sessionReadFault{JetStreamContext: leader, read: func(stream, subject string, opts ...nats.JSOpt) (*nats.RawStreamMsg, error) {
				if key == "session" && strings.Contains(subject, ".token.") {
					return leader.GetLastMsg(stream, subject, opts...)
				}
				for _, opt := range opts {
					if ctx, ok := opt.(nats.ContextOpt); ok {
						if deadline, bounded := ctx.Deadline(); bounded && time.Until(deadline) <= sessionStoreTimeout {
							return nil, nats.ErrTimeout
						}
					}
				}
				t.Fatal("session leader read has no bounded deadline")
				return nil, nats.ErrTimeout
			}}
			for _, route := range []struct{ method, path string }{{"GET", "/"}, {"GET", "/login"}, {"POST", "/login"}, {"POST", "/logout"}} {
				request := httptest.NewRequest(route.method, route.path, strings.NewReader(url.Values{"token": {token}}.Encode()))
				request.Header.Set("Accept", "text/html")
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookie)
				recorder := httptest.NewRecorder()
				server.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Location") != "" || len(recorder.Result().Cookies()) != 0 {
					t.Fatalf("%s %s hid an outage or changed the cookie: status=%d", route.method, route.path, recorder.Code)
				}
			}
			for _, bearer := range []struct {
				token string
				code  int
			}{{token, http.StatusOK}, {"wrong", http.StatusUnauthorized}} {
				request := httptest.NewRequest(http.MethodGet, "/", nil)
				request.Header.Set("Authorization", "Bearer "+bearer.token)
				request.AddCookie(cookie)
				recorder := httptest.NewRecorder()
				server.ServeHTTP(recorder, request)
				if recorder.Code != bearer.code {
					t.Fatal("store outage affected bearer authentication")
				}
			}
			if key == "token" {
				if _, err := server.sessions.issue(t.Context()); err == nil {
					t.Fatal("outage issued a session")
				}
			}
		})
	}
	store.leader = leader
	if !sessionValid(t, server.sessions, t.Context(), cookie.Value) {
		t.Fatal("store recovery lost the existing session")
	}
}

func TestSessionReadsHonorRequestCancellation(t *testing.T) {
	t.Parallel()
	server, token := newLoginServer(t)
	response := postLogin(server, url.Values{"token": {token}})
	value := response.Result().Cookies()[0].Value
	store := server.sessions.binding.Load().store
	store.leader = sessionReadFault{JetStreamContext: store.leader, read: func(_, _ string, opts ...nats.JSOpt) (*nats.RawStreamMsg, error) {
		for _, opt := range opts {
			if ctx, ok := opt.(nats.ContextOpt); ok {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("missing request context")
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if valid, err := server.sessions.valid(ctx, value); valid || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stalled leader did not honor the request deadline")
	}
	if time.Since(started) > time.Second {
		t.Fatal("request cancellation waited for the full session timeout")
	}
}

type noSessionEnumeration struct{ jetstream.KeyValue }

func (noSessionEnumeration) Watch(context.Context, string, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return nil, errors.New("session enumeration unavailable")
}

func TestUncontendedLoginDoesNotEnumerateSessions(t *testing.T) {
	t.Parallel()
	server, token := newLoginServer(t)
	store := server.sessions.binding.Load().store
	store.kv = noSessionEnumeration{store.kv}
	for range 3 {
		response := postLogin(server, url.Values{"token": {token}})
		if response.Code != http.StatusSeeOther || len(response.Result().Cookies()) != 1 {
			t.Fatal("login attempted session enumeration")
		}
	}
}

type slowSessionCreates struct {
	jetstream.KeyValue
	creates atomic.Int32
}

func (store *slowSessionCreates) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	store.creates.Add(1)
	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return store.KeyValue.Create(ctx, key, value, opts...)
	}
}

type sessionUpdateFault struct{ jetstream.KeyValue }

func (sessionUpdateFault) Update(context.Context, string, []byte, uint64) (uint64, error) {
	return 0, context.DeadlineExceeded
}

func TestFailedTokenRotationPreservesActiveSessions(t *testing.T) {
	t.Parallel()
	server, _ := newLoginServer(t)
	store := server.sessions.binding.Load().store
	value, err := server.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.kv.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewTokenServer(Config{Dashboard: true}, strings.Repeat("b", 48), ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	kv := store.kv
	store.kv = sessionUpdateFault{kv}
	if err := rotated.SetSessionStore(t.Context(), store); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("rotation did not report the failed metadata update")
	}
	if !sessionValid(t, server.sessions, t.Context(), value) {
		t.Fatal("failed rotation deleted an active session")
	}
	after, err := store.kv.Status(t.Context())
	if err != nil || after.Values() != before.Values() || after.Bytes() != before.Bytes() {
		t.Fatal("failed rotation changed persisted sessions")
	}
	store.kv = kv
	if err := rotated.SetSessionStore(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if sessionValid(t, server.sessions, t.Context(), value) {
		t.Fatal("successful rotation preserved a revoked session")
	}
}

func TestCommittedRotationRevokesBeforeCleanupAndRetriesCollection(t *testing.T) {
	t.Parallel()
	server, _ := newLoginServer(t)
	store := server.sessions.binding.Load().store
	value, err := server.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewTokenServer(Config{Dashboard: true}, strings.Repeat("b", 48), ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	kv := store.kv
	store.kv = noSessionEnumeration{kv}
	if err := rotated.SetSessionStore(t.Context(), store); err == nil {
		t.Fatal("rotation did not report the failed cleanup")
	}
	if sessionValid(t, server.sessions, t.Context(), value) {
		t.Fatal("cleanup failure resurrected a committed rotation")
	}
	store.kv = kv
	if err := rotated.SetSessionStore(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	status, err := store.kv.Status(t.Context())
	if err != nil || status.Values() != 1 {
		t.Fatal("retry did not collect the retired generation")
	}
}

func TestTokenRotationBetweenSessionReadsRejectsOldGeneration(t *testing.T) {
	t.Parallel()
	server, _ := newLoginServer(t)
	value, err := server.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	binding := server.sessions.binding.Load()
	store := binding.store
	leader := store.leader
	rotated, err := NewTokenServer(Config{Dashboard: true}, strings.Repeat("b", 48), ServerDeps{Registry: NewRegistry(false), Health: new(Health)})
	if err != nil {
		t.Fatal(err)
	}
	rotationStore := *store
	rotationStore.kv = noSessionEnumeration{store.kv}
	rotatedDuringRead := false
	store.leader = sessionReadFault{JetStreamContext: leader, read: func(stream, subject string, opts ...nats.JSOpt) (*nats.RawStreamMsg, error) {
		if subject == "$KV."+SessionBucket+"."+binding.key(value) {
			// Commit rotation after the initial generation check while retaining
			// the old record, as when cleanup is unavailable on another controller.
			if err := rotated.SetSessionStore(t.Context(), &rotationStore); err == nil {
				t.Fatal("rotation unexpectedly collected the old session")
			}
			rotatedDuringRead = true
		}
		return leader.GetLastMsg(stream, subject, opts...)
	}}
	if valid, err := server.sessions.valid(t.Context(), value); err != nil || valid {
		t.Fatal("authentication accepted a generation retired during its reads")
	}
	if !rotatedDuringRead || rotated.sessions.binding.Load() == nil {
		t.Fatal("test did not commit rotation between the generation and session reads")
	}
	if _, err := rotationStore.get(t.Context(), binding.key(value)); err != nil {
		t.Fatal("test failed to retain the old session record")
	}
}

func TestFinalGenerationReadOutageFailsClosed(t *testing.T) {
	t.Parallel()
	server, _ := newLoginServer(t)
	value, err := server.sessions.issue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	store := server.sessions.binding.Load().store
	leader := store.leader
	tokenReads := 0
	store.leader = sessionReadFault{JetStreamContext: leader, read: func(stream, subject string, opts ...nats.JSOpt) (*nats.RawStreamMsg, error) {
		if strings.Contains(subject, ".token.") {
			tokenReads++
			if tokenReads == 2 {
				return nil, nats.ErrTimeout
			}
		}
		return leader.GetLastMsg(stream, subject, opts...)
	}}
	if valid, err := server.sessions.valid(t.Context(), value); valid || !errors.Is(err, nats.ErrTimeout) {
		t.Fatal("final generation read outage authorized a session or hid the error")
	}
}

func TestAuthoritativeTokenVersionsRejectStaleControllersAndReconcileBindings(t *testing.T) {
	t.Parallel()
	store := newTestSessionStore(t)
	create := func(token string, version TokenVersion) (*Server, error) {
		return NewTokenServer(Config{Dashboard: true}, token, ServerDeps{Registry: NewRegistry(false), Health: new(Health), Sessions: store, TokenVersion: version})
	}
	build := func(token string, version TokenVersion) *Server {
		t.Helper()
		server, err := create(token, version)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	issue := func(server *Server) string {
		t.Helper()
		value, err := server.sessions.issue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	a, b, c := strings.Repeat("a", 48), strings.Repeat("b", 48), strings.Repeat("c", 48)
	version := TokenVersion{Source: "vault-secret-one", Number: 1, SpecGeneration: 10}
	first := build(a, version)
	staleLogout := build(a, version)
	oldCookie := issue(first)
	version.Number = 2
	second := build(b, version)
	currentCookie := issue(second)
	before, err := store.kv.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, stale := range []TokenVersion{
		{Source: version.Source, Number: 1, SpecGeneration: 11},
		{Source: version.Source, Number: 2, SpecGeneration: 10}, // conflicting hash
		{Source: "obsolete-reference", Number: 9, SpecGeneration: 9},
		{Source: "obsolete-reference", Number: 9, SpecGeneration: 10},
		{}, // an unversioned registration cannot overwrite a versioned scope
	} {
		if _, err := create(c, stale); err == nil {
			t.Fatal("stale or conflicting registration changed the shared token")
		}
	}
	if err := first.SetSessionStore(t.Context(), store); err == nil {
		t.Fatal("cached old token rolled back the shared scope")
	}
	after, err := store.kv.Status(t.Context())
	if err != nil || before.Bytes() != after.Bytes() || before.Values() != after.Values() || !sessionValid(t, second.sessions, t.Context(), currentCookie) {
		t.Fatal("stale registration invalidated the current controller's sessions")
	}
	// An unrelated signed-spec change advances the reference fence without
	// revoking sessions or stranding the controller's existing binding.
	version.SpecGeneration = 11
	build(b, version)
	if !sessionValid(t, second.sessions, t.Context(), currentCookie) {
		t.Fatal("spec checkpoint expired an existing session")
	}
	if _, err := create(c, TokenVersion{Source: "obsolete-reference", Number: 1, SpecGeneration: 10}); err == nil {
		t.Fatal("old reference bypassed the new signed-spec checkpoint")
	}
	// Legitimate A-to-B-to-A rotation has a newer Vault version. The already
	// running A controller can create fresh sessions without reviving its old one.
	version.Number = 3
	restored := build(a, version)
	if sessionValid(t, first.sessions, t.Context(), oldCookie) {
		t.Fatal("binding reconciliation resurrected an old A cookie")
	}
	fresh := issue(first)
	if !sessionValid(t, restored.sessions, t.Context(), fresh) {
		t.Fatal("matching-token controller remained bound to the retired generation")
	}
	logoutCookie := issue(restored)
	if err := staleLogout.sessions.revoke(t.Context(), logoutCookie); err != nil || sessionValid(t, restored.sessions, t.Context(), logoutCookie) {
		t.Fatal("logout on a matching-token stale binding failed to revoke a copied cookie")
	}
	version.Number = 4
	build(a, version)
	if sessionValid(t, first.sessions, t.Context(), fresh) {
		t.Fatal("same-value Vault rotation failed to revoke its preceding sessions")
	}
	other := TokenVersion{Source: "vault-secret-two", Number: 1, SpecGeneration: 12}
	build(c, other)
	if _, err := create(a, version); err == nil {
		t.Fatal("old signed reference rolled back the new secret")
	}
	other.Number, other.SpecGeneration = 2, 1
	latest := build(b, other)
	entry, err := store.get(t.Context(), "token."+store.scope)
	if err != nil {
		t.Fatal(err)
	}
	record, err := readSessionToken(entry.Data)
	if err != nil || record.Version.SpecGeneration != 12 || !sessionValid(t, latest.sessions, t.Context(), issue(latest)) {
		t.Fatal("a current Vault version lowered the signed-reference fence")
	}
}
