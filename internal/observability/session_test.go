package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func newLoginServer(t *testing.T) (*Server, string) {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("s", 48)
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{ListenAddress: "10.0.0.4:9464", BearerTokenFile: tokenFile},
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
	// Flip the first random character: that always changes the digest. A
	// fixed suffix can equal the token's own last characters and leave the
	// cookie unchanged.
	random := strings.LastIndexByte(cookie.Value, '.') + 1
	flipped := "A"
	if cookie.Value[random] == 'A' {
		flipped = "B"
	}
	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie.Value[:random] + flipped + cookie.Value[random+1:]})
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
		server, err := NewTokenServer(Config{}, token, ServerDeps{
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
	server, token := newLoginServer(t)
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
		response := postLogin(server, url.Values{"token": {token}}, "Origin", tc.origin, "Sec-Fetch-Site", tc.site)
		want := http.StatusForbidden
		if tc.want {
			want = http.StatusSeeOther
		}
		if response.Code != want {
			t.Errorf("origin=%q site=%q: status %d want %d", tc.origin, tc.site, response.Code, want)
		}
	}

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
		listener, err := NewTokenServer(Config{}, token, ServerDeps{Registry: NewRegistry(false), Health: new(Health), Sessions: store})
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

func sessionValid(t *testing.T, manager *sessions, ctx context.Context, value string) bool {
	t.Helper()
	valid, err := manager.valid(ctx, value)
	if err != nil {
		t.Fatal(err)
	}
	return valid
}

func TestAuthoritativeTokenVersionsRejectStaleControllersAndReconcileBindings(t *testing.T) {
	t.Parallel()
	store := newTestSessionStore(t)
	create := func(token string, version TokenVersion) (*Server, error) {
		return NewTokenServer(Config{}, token, ServerDeps{Registry: NewRegistry(false), Health: new(Health), Sessions: store, TokenVersion: version})
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
	logoutCookie = issue(restored)
	if err := second.sessions.revoke(t.Context(), logoutCookie); err != nil || sessionValid(t, restored.sessions, t.Context(), logoutCookie) {
		t.Fatal("logout on a retired-token listener failed to revoke the current cookie")
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
