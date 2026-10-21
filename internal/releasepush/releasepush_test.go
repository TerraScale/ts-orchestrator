package releasepush

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

// issuer is a fake GitHub: an RSA key served as JWKS under a kid.
type issuer struct {
	mu   sync.Mutex
	kid  string
	key  *rsa.PrivateKey
	hits int
	srv  *httptest.Server
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	i := &issuer{kid: "k1", key: rsaKey(t)}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.hits++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": i.kid,
			"n": base64.RawURLEncoding.EncodeToString(i.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i.key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (i *issuer) verifier(now time.Time) *Verifier {
	return &Verifier{JWKSURL: i.srv.URL, Client: i.srv.Client(), Now: func() time.Time { return now }}
}

func goodClaims(now time.Time) map[string]any {
	return map[string]any{"iss": githubIssuer, "aud": Audience, "exp": now.Add(5 * time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(),
		"repository": orchRepository, "repository_owner": owner, "ref": mainRef, "sha": testSHA, "run_id": "100"}
}

func (i *issuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	i.mu.Lock()
	kid, key := i.kid, i.key
	i.mu.Unlock()
	return signWith(t, kid, key, claims)
}

func signWith(t *testing.T, kid string, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	segment := func(v any) string {
		data, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signed := segment(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}) + "." + segment(claims)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func with(claims map[string]any, key string, value any) map[string]any {
	claims[key] = value
	return claims
}

func TestVerify(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	cases := map[string]struct {
		token string
		ok    bool
	}{
		"good":          {i.sign(t, goodClaims(now)), true},
		"audience list": {i.sign(t, with(goodClaims(now), "aud", []string{Audience})), true},
		"wrong aud":     {i.sign(t, with(goodClaims(now), "aud", "sts.amazonaws.com")), false},
		"wrong owner":   {i.sign(t, with(goodClaims(now), "repository_owner", "Evil")), false},
		"wrong repo":    {i.sign(t, with(goodClaims(now), "repository", "Evil/ts-orchestrator")), false},
		"branch":        {i.sign(t, with(goodClaims(now), "ref", "refs/heads/feature")), false},
		"wrong issuer":  {i.sign(t, with(goodClaims(now), "iss", "https://evil.example")), false},
		"expired":       {i.sign(t, with(goodClaims(now), "exp", now.Add(-2*time.Minute).Unix())), false},
		"skewed exp":    {i.sign(t, with(goodClaims(now), "exp", now.Add(-30*time.Second).Unix())), true},
		"not yet":       {i.sign(t, with(goodClaims(now), "nbf", now.Add(2*time.Minute).Unix())), false},
		"bad sig":       {signWith(t, "k1", rsaKey(t), goodClaims(now)), false},
		"garbage":       {"a.b.c", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := i.verifier(now).Verify(context.Background(), c.token)
			if (err == nil) != c.ok {
				t.Fatalf("Verify err = %v, want ok %t", err, c.ok)
			}
		})
	}
}

func TestVerifyRefetchesUnknownKid(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	v := i.verifier(now)
	if _, err := v.Verify(context.Background(), i.sign(t, goodClaims(now))); err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	i.kid, i.key = "k2", rsaKey(t)
	i.mu.Unlock()
	rotated := i.sign(t, goodClaims(now))
	// Inside the refetch interval an unknown kid does not reach GitHub.
	if _, err := v.Verify(context.Background(), rotated); err == nil || i.hits != 1 {
		t.Fatalf("err = %v hits = %d, want refused without refetch", err, i.hits)
	}
	v.Now = func() time.Time { return now.Add(refetchEvery) }
	if _, err := v.Verify(context.Background(), rotated); err != nil || i.hits != 2 {
		t.Fatalf("err = %v hits = %d, want refetched", err, i.hits)
	}
}

func startServer(t *testing.T, v *Verifier) (*server.Server, *Auth, string) {
	t.Helper()
	auth := &Auth{verifier: v, local: "local-secret"}
	opts, err := Options(t.TempDir(), auth)
	if err != nil {
		t.Fatal(err)
	}
	opts.Host, opts.Port = "127.0.0.1", -1
	srv, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("server not ready")
	}
	return srv, auth, srv.ClientURL()
}

func dialCI(url, token string, errs chan<- error) (*nats.Conn, error) {
	return nats.Connect(url, nats.Secure(&tls.Config{InsecureSkipVerify: true}), nats.Token(token), nats.MaxReconnects(0),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
}

func TestAuthPermissions(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	srv, auth, url := startServer(t, i.verifier(now))
	local, err := auth.Connect(srv)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	h := &Handler{Verifier: i.verifier(now), Revision: testSHA, Installed: make(chan struct{}, 1)}
	if err := h.Serve(local); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 4)
	ci, err := dialCI(url, i.sign(t, goodClaims(now)), errs)
	if err != nil {
		t.Fatal(err)
	}
	defer ci.Close()
	reply, err := request(context.Background(), ci, SubjectVersion, nil, 2*time.Second)
	if err != nil || reply.Version != testSHA {
		t.Fatalf("version = %+v, %v", reply, err)
	}
	if _, err := ci.SubscribeSync("ts.release.>"); err != nil {
		t.Fatal(err)
	}
	if err := ci.Publish("ts.other", nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-errs:
			if !errors.Is(err, nats.ErrPermissionViolation) {
				t.Fatalf("async err = %v, want permissions violation", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("CI subscribe/publish outside its permissions was not refused")
		}
	}
	for name, token := range map[string]string{"no token": "", "bad token": "x.y.z", "local token over TCP": "local-secret",
		"wrong aud": i.sign(t, with(goodClaims(now), "aud", "other"))} {
		if conn, err := dialCI(url, token, errs); err == nil {
			conn.Close()
			t.Fatalf("%s: connected", name)
		}
	}
}

// rewrite sends every request to the test server, standing in for github.com.
type rewrite struct{ target string }

func (r rewrite) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme, clone.URL.Host = "http", strings.TrimPrefix(r.target, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func testHandler(t *testing.T, i *issuer, now time.Time, body []byte) (*Handler, string) {
	t.Helper()
	assets := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(assets.Close)
	dir := t.TempDir()
	binary := filepath.Join(dir, "terrascale-orchestrator")
	if err := os.WriteFile(binary, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Handler{Verifier: i.verifier(now), Revision: strings.Repeat("f", 40), Binary: binary,
		RunIDFile: filepath.Join(dir, "run-id"), Client: &http.Client{Transport: rewrite{assets.URL}},
		Installed: make(chan struct{}, 1)}, binary
}

func orchRequest(t *testing.T, token string, body []byte, mutate func(*OrchRelease)) []byte {
	t.Helper()
	sum := sha256.Sum256(body)
	release := OrchRelease{SHA: testSHA, Token: token, Binaries: map[string]Binary{runtime.GOARCH: {
		URL: downloadPrefix + "ci-" + testSHA + "-run-100/" + assetPrefix + runtime.GOARCH, SHA256: hex.EncodeToString(sum[:])}}}
	if mutate != nil {
		mutate(&release)
	}
	data, _ := json.Marshal(release)
	return data
}

func TestOrchValidation(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	h, binary := testHandler(t, i, now, []byte("new"))
	good := i.sign(t, goodClaims(now))
	other := "amd64"
	if runtime.GOARCH == "amd64" {
		other = "arm64"
	}
	cases := map[string]func(*OrchRelease){
		"short sha": func(r *OrchRelease) { r.SHA = "abc" },
		"no arch":   func(r *OrchRelease) { r.Binaries = map[string]Binary{other: r.Binaries[runtime.GOARCH]} },
		"foreign url": func(r *OrchRelease) {
			b := r.Binaries[runtime.GOARCH]
			b.URL = "https://evil.example/x"
			r.Binaries[runtime.GOARCH] = b
		},
		"wrong asset": func(r *OrchRelease) { b := r.Binaries[runtime.GOARCH]; b.URL += "x"; r.Binaries[runtime.GOARCH] = b },
		"path escape": func(r *OrchRelease) {
			b := r.Binaries[runtime.GOARCH]
			b.URL = downloadPrefix + "../" + assetPrefix + runtime.GOARCH
			r.Binaries[runtime.GOARCH] = b
		},
		"bad sha256": func(r *OrchRelease) { b := r.Binaries[runtime.GOARCH]; b.SHA256 = "00"; r.Binaries[runtime.GOARCH] = b },
		"token sha":  func(r *OrchRelease) { r.Token = i.sign(t, with(goodClaims(now), "sha", strings.Repeat("a", 40))) },
		"token repo": func(r *OrchRelease) { r.Token = i.sign(t, with(goodClaims(now), "repository", owner+"/terrabase")) },
		"no token":   func(r *OrchRelease) { r.Token = "" },
		"digest wrong": func(r *OrchRelease) {
			b := r.Binaries[runtime.GOARCH]
			b.SHA256 = strings.Repeat("0", 64)
			r.Binaries[runtime.GOARCH] = b
		},
	}
	for name, mutate := range cases {
		if reply := h.orch(context.Background(), orchRequest(t, good, []byte("new"), mutate)); reply.State != "rejected" {
			t.Fatalf("%s: reply = %+v, want rejected", name, reply)
		}
	}
	if data, _ := os.ReadFile(binary); string(data) != "old" {
		t.Fatalf("binary = %q after rejected releases", data)
	}
	if reply := h.orch(context.Background(), []byte(`{"sha":"`+testSHA+`","extra":1}`)); reply.State != "rejected" {
		t.Fatalf("unknown field reply = %+v", reply)
	}
}

func TestOrchInstall(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	h, binary := testHandler(t, i, now, []byte("new"))
	token := i.sign(t, goodClaims(now))
	if reply := h.orch(context.Background(), orchRequest(t, token, []byte("new"), nil)); reply.State != "installed" {
		t.Fatalf("reply = %+v", reply)
	}
	current, _ := os.ReadFile(binary)
	prev, _ := os.ReadFile(binary + ".prev")
	info, err := os.Stat(binary)
	if string(current) != "new" || string(prev) != "old" || err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("binary %q prev %q mode %v err %v", current, prev, info.Mode(), err)
	}
	if _, err := os.Stat(binary + ".next"); !os.IsNotExist(err) {
		t.Fatalf(".next left behind: %v", err)
	}
	if reply := h.orch(context.Background(), orchRequest(t, token, []byte("new"), nil)); reply.State != "installed" {
		t.Fatalf("repeat reply = %+v", reply)
	}
	// After the restart: same sha is current, an older run is stale.
	h2 := &Handler{Verifier: h.Verifier, Revision: testSHA, Binary: binary, RunIDFile: h.RunIDFile, Client: h.Client}
	if reply := h2.orch(context.Background(), orchRequest(t, token, []byte("new"), nil)); reply.State != "current" {
		t.Fatalf("current reply = %+v", reply)
	}
	older := strings.Repeat("b", 40)
	h2.Revision = strings.Repeat("c", 40)
	stale := i.sign(t, with(with(goodClaims(now), "sha", older), "run_id", "99"))
	if reply := h2.orch(context.Background(), orchRequest(t, stale, []byte("new"), func(r *OrchRelease) { r.SHA = older })); reply.State != "stale" {
		t.Fatalf("older run reply = %+v", reply)
	}
}

func TestAppValidation(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	h := &Handler{Verifier: i.verifier(now)}
	image := "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("a", 64)
	terrabase := i.sign(t, with(goodClaims(now), "repository", owner+"/TerraBase"))
	if err := h.validateApp(context.Background(), AppRelease{Service: "terrabase", Image: image, Token: terrabase}); err != nil {
		t.Fatal(err)
	}
	for name, release := range map[string]AppRelease{
		"other repo":  {Service: "terrabase", Image: image, Token: i.sign(t, goodClaims(now))},
		"tag":         {Service: "terrabase", Image: "ghcr.io/terrascale/terrabase:latest", Token: terrabase},
		"other owner": {Service: "terrabase", Image: "ghcr.io/evil/terrabase@sha256:" + strings.Repeat("a", 64), Token: terrabase},
	} {
		if err := h.validateApp(context.Background(), release); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	data, _ := json.Marshal(AppRelease{Service: "terrabase", Image: image, Token: terrabase})
	if reply := h.app(context.Background(), data); reply.State != "rejected" || !bytes.Contains([]byte(reply.Error), []byte("not wired")) {
		t.Fatalf("unwired app reply = %+v", reply)
	}
}
