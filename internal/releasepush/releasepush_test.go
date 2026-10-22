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
	gate chan struct{} // when set, each JWKS response waits for it to close
	srv  *httptest.Server
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	i := &issuer{kid: "k1", key: rsaKey(t)}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		gate := i.gate
		i.mu.Unlock()
		if gate != nil {
			<-gate
		}
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
		"repository": orchRepository, "repository_owner": owner, "ref": mainRef, "sha": testSHA, "run_id": "100",
		"event_name": "push", "job_workflow_ref": orchRepository + "/.github/workflows/ci.yml@" + mainRef}
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
		"good":                        {i.sign(t, goodClaims(now)), true},
		"audience list":               {i.sign(t, with(goodClaims(now), "aud", []string{Audience})), true},
		"wrong aud":                   {i.sign(t, with(goodClaims(now), "aud", "sts.amazonaws.com")), false},
		"wrong owner":                 {i.sign(t, with(goodClaims(now), "repository_owner", "Evil")), false},
		"wrong repo":                  {i.sign(t, with(goodClaims(now), "repository", "Evil/ts-orchestrator")), false},
		"branch":                      {i.sign(t, with(goodClaims(now), "ref", "refs/heads/feature")), false},
		"wrong issuer":                {i.sign(t, with(goodClaims(now), "iss", "https://evil.example")), false},
		"expired":                     {i.sign(t, with(goodClaims(now), "exp", now.Add(-2*time.Minute).Unix())), false},
		"skewed exp":                  {i.sign(t, with(goodClaims(now), "exp", now.Add(-30*time.Second).Unix())), true},
		"not yet":                     {i.sign(t, with(goodClaims(now), "nbf", now.Add(2*time.Minute).Unix())), false},
		"bad sig":                     {signWith(t, "k1", rsaKey(t), goodClaims(now)), false},
		"garbage":                     {"a.b.c", false},
		"pull request":                {i.sign(t, with(goodClaims(now), "event_name", "pull_request")), false},
		"other workflow":              {i.sign(t, with(goodClaims(now), "job_workflow_ref", orchRepository+"/.github/workflows/image.yml@"+mainRef)), false},
		"workflow on branch":          {i.sign(t, with(goodClaims(now), "job_workflow_ref", orchRepository+"/.github/workflows/ci.yml@refs/heads/x")), false},
		"other repo, listed workflow": {i.sign(t, with(goodClaims(now), "repository", owner+"/terrabase")), false},
		"run_id not a number":         {i.sign(t, with(goodClaims(now), "run_id", "1.2")), false},
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

// Concurrent unknown kids share one JWKS fetch, and no caller holds the
// lock while it runs.
func TestVerifySingleFetch(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	release := make(chan struct{})
	i.mu.Lock()
	i.gate = release
	i.mu.Unlock()
	v := i.verifier(now)
	token := i.sign(t, goodClaims(now))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, err := v.Verify(context.Background(), token); errs <- err })
	}
	// A cancelled caller returns while the fetch is still running.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for v.inflightNow() == nil {
		time.Sleep(time.Millisecond)
	}
	if _, err := v.Verify(ctx, i.sign(t, with(goodClaims(now), "sha", strings.Repeat("e", 40)))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller err = %v", err)
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.hits != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", i.hits)
	}
}

func (v *Verifier) inflightNow() chan struct{} {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.inflight
}

func startServer(t *testing.T, v *Verifier) (*server.Server, *Auth, string) {
	t.Helper()
	srv, auth, url, _ := startServerIn(t, v, t.TempDir())
	return srv, auth, url
}

func startServerIn(t *testing.T, v *Verifier, state string) (*server.Server, *Auth, string, string) {
	t.Helper()
	auth := &Auth{verifier: v, local: "local-secret"}
	opts, err := Options(state, auth)
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
	pin, err := SPKIPin(opts.TLSConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return srv, auth, srv.ClientURL(), pin
}

func dialCI(url, token string, errs chan<- error) (*nats.Conn, error) {
	return nats.Connect(url, nats.Secure(&tls.Config{InsecureSkipVerify: true}), nats.Token(token), nats.MaxReconnects(0), //nolint:gosec // test listener
		nats.CustomInboxPrefix(Inbox("100")),
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
	// Another run's inbox, the release subjects and other subjects are refused.
	for _, subject := range []string{"_INBOX.>", Inbox("101") + ".>", "ts.release.>"} {
		if _, err := ci.SubscribeSync(subject); err != nil {
			t.Fatal(err)
		}
	}
	if err := ci.Publish("ts.other", nil); err != nil {
		t.Fatal(err)
	}
	for range 4 {
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
		URL: ReleaseURL(testSHA, "100", runtime.GOARCH), SHA256: hex.EncodeToString(sum[:])}}}
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
		// H3: the URL must name the signed run's own release.
		"other run's release": func(r *OrchRelease) {
			b := r.Binaries[runtime.GOARCH]
			b.URL = ReleaseURL(testSHA, "99", runtime.GOARCH)
			r.Binaries[runtime.GOARCH] = b
		},
		"other sha's release": func(r *OrchRelease) {
			b := r.Binaries[runtime.GOARCH]
			b.URL = ReleaseURL(strings.Repeat("d", 40), "100", runtime.GOARCH)
			r.Binaries[runtime.GOARCH] = b
		},
		"other arch": func(r *OrchRelease) {
			b := r.Binaries[runtime.GOARCH]
			b.URL = ReleaseURL(testSHA, "100", other)
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
	if reply := h2.orch(context.Background(), orchRequest(t, stale, []byte("new"), func(r *OrchRelease) {
		r.SHA = older
		b := r.Binaries[runtime.GOARCH]
		b.URL = ReleaseURL(older, "99", runtime.GOARCH)
		r.Binaries[runtime.GOARCH] = b
	})); reply.State != "stale" {
		t.Fatalf("older run reply = %+v", reply)
	}
}

func TestAppValidation(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	h := &Handler{Verifier: i.verifier(now)}
	workflow := owner + "/terrascale/.github/workflows/ci.yml@" + mainRef
	terrascale := i.sign(t, with(with(goodClaims(now), "repository", owner+"/terrascale"), "job_workflow_ref", workflow))
	image := func(name string) string { return "ghcr.io/terrascale/" + name + "@sha256:" + strings.Repeat("a", 64) }
	for _, service := range []string{"terrabase", "ts-auth"} {
		if err := h.validateApp(context.Background(), AppRelease{Service: service, Image: image(service), Token: terrascale}); err != nil {
			t.Fatal(err)
		}
	}
	for name, release := range map[string]AppRelease{
		"orch workflow":     {Service: "terrabase", Image: image("terrabase"), Token: i.sign(t, goodClaims(now))},
		"not allowlisted":   {Service: "ts-dashboard", Image: image("ts-dashboard"), Token: terrascale},
		"image not service": {Service: "terrabase", Image: image("ts-auth"), Token: terrascale},
		"tag":               {Service: "terrabase", Image: "ghcr.io/terrascale/terrabase:latest", Token: terrascale},
		"other owner":       {Service: "terrabase", Image: "ghcr.io/evil/terrabase@sha256:" + strings.Repeat("a", 64), Token: terrascale},
	} {
		if err := h.validateApp(context.Background(), release); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// The retired images-ghcr.yml identity no longer releases.
	retired := i.sign(t, with(with(goodClaims(now), "repository", owner+"/terrascale"), "job_workflow_ref", owner+"/terrascale/.github/workflows/images-ghcr.yml@"+mainRef))
	if err := h.validateApp(context.Background(), AppRelease{Service: "terrabase", Image: image("terrabase"), Token: retired}); err == nil {
		t.Fatal("retired workflow released terrabase")
	}
	// An app workflow's token cannot push a ts-orch release even for this repository.
	canary := i.sign(t, with(goodClaims(now), "job_workflow_ref", orchRepository+"/.github/workflows/app-canary.yml@"+mainRef))
	if _, _, err := h.validateOrch(context.Background(), OrchRelease{SHA: strings.Repeat("a", 40),
		Binaries: map[string]Binary{runtime.GOARCH: {SHA256: strings.Repeat("b", 64)}}, Token: canary}); err == nil {
		t.Fatal("app workflow token pushed a ts-orch release")
	}
	data, _ := json.Marshal(AppRelease{Service: "terrabase", Image: image("terrabase"), Token: terrascale})
	if reply := h.app(context.Background(), data); reply.State != "rejected" {
		t.Fatalf("app reply without a mesh = %+v", reply)
	}
	var got string
	h.App = func(_ context.Context, service, image string) (json.RawMessage, error) {
		got = service + " " + image
		return json.RawMessage(`[{"region":"gru"}]`), errors.New("rolled back")
	}
	if reply := h.app(context.Background(), data); reply.State != "failed" || string(reply.Result) != `[{"region":"gru"}]` || got != "terrabase "+image("terrabase") {
		t.Fatalf("failed app reply = %+v, App got %q", reply, got)
	}
}

// H4: the listener certificate persists, and CI trusts exactly the pinned key.
func TestListenerPin(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	state := t.TempDir()
	srv, _, url, pin := startServerIn(t, i.verifier(now), state)
	var printed bytes.Buffer
	if err := Pin([]string{"--state", state}, &printed); err != nil || strings.TrimSpace(printed.String()) != pin {
		t.Fatalf("pin printed %q, err %v, want %s", printed.String(), err, pin)
	}
	srv.Shutdown()
	// A restart (or upgrade) keeps the key.
	if _, _, _, again := startServerIn(t, i.verifier(now), state); again != pin {
		t.Fatalf("pin changed across restart: %s -> %s", pin, again)
	}
	_, _, url, _ = startServerIn(t, i.verifier(now), state)
	raw, _ := hex.DecodeString(pin)
	token := i.sign(t, goodClaims(now))
	for name, c := range map[string]struct {
		pin string
		ok  bool
	}{
		"hex pin":    {pin, true},
		"base64 pin": {base64.StdEncoding.EncodeToString(raw), true},
		"wrong pin":  {strings.Repeat("0", 64), false},
		"empty pin":  {"", false},
	} {
		config, err := pinnedTLS(c.pin)
		if err == nil {
			var conn *nats.Conn
			if conn, err = nats.Connect(url, nats.Secure(config), nats.Token(token), nats.MaxReconnects(0)); err == nil {
				conn.Close()
			}
		}
		if (err == nil) != c.ok {
			t.Fatalf("%s: err = %v, want ok %t", name, err, c.ok)
		}
	}
	// A half-written pair is refused, never replaced by a new key.
	if err := os.Remove(filepath.Join(state, "nats", "tls.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := listenerCertificate(filepath.Join(state, "nats")); err == nil {
		t.Fatal("regenerated a certificate while the key was present")
	}
}

// One region without a pin fails alone and is reported.
func TestPushRegionWithoutPin(t *testing.T) {
	result := pushRegion(context.Background(), Region{Region: "new", NATS: "tls://127.0.0.1:1"}, OrchRelease{})
	if result.Region != "new" || !strings.Contains(result.Error, "spki_sha256") {
		t.Fatalf("result = %+v", result)
	}
}

// TestCommittedRegionsArePinned keeps every deploy/m1/regions.json line
// pushable: a region without a valid pin fails every main release push.
func TestCommittedRegionsArePinned(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "m1", "regions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var regions []Region
	if err := json.Unmarshal(data, &regions); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, region := range regions {
		if region.Region == "" || seen[region.Region] || !strings.HasPrefix(region.NATS, "tls://") {
			t.Errorf("bad region entry %+v", region)
		}
		seen[region.Region] = true
		if _, err := pinnedTLS(region.SPKISHA256); err != nil {
			t.Errorf("%s: %v", region.Region, err)
		}
	}
	if len(regions) == 0 {
		t.Fatal("no regions")
	}
}

func meshClaims(now time.Time) map[string]any {
	return with(with(goodClaims(now), "event_name", "schedule"), "job_workflow_ref", meshWorkflow)
}

// The multi-region workflow may only use the mesh bridge; release workflows may not.
func TestMeshBridge(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	v := i.verifier(now)
	for name, c := range map[string]struct {
		claims map[string]any
		ok     bool
	}{
		"schedule":        {meshClaims(now), true},
		"dispatch":        {with(meshClaims(now), "event_name", "workflow_dispatch"), true},
		"branch":          {with(meshClaims(now), "ref", "refs/heads/x"), false},
		"other repo":      {with(meshClaims(now), "repository", owner+"/terrabase"), false},
		"release ci.yml":  {goodClaims(now), false},
		"workflow branch": {with(meshClaims(now), "job_workflow_ref", orchRepository+"/.github/workflows/multi-region.yml@refs/heads/x"), false},
	} {
		if _, err := v.VerifyMesh(context.Background(), i.sign(t, c.claims)); (err == nil) != c.ok {
			t.Fatalf("%s: VerifyMesh err = %v, want ok %t", name, err, c.ok)
		}
	}
	// The app-digests workflow may only read state, on a schedule too.
	digests := i.sign(t, with(meshClaims(now), "job_workflow_ref", digestsWorkflow))
	h := &Handler{Verifier: v, Mesh: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"whoami":"x"}`), nil
	}}
	for op, want := range map[string]string{"state": "done", "apply": "rejected", "rm": "rejected", "ping": "rejected"} {
		data, _ := json.Marshal(MeshRequest{Token: digests})
		if reply := h.mesh(context.Background(), op, data); reply.State != want {
			t.Fatalf("app-digests %s = %+v, want %s", op, reply, want)
		}
	}
	if _, err := v.Verify(context.Background(), i.sign(t, meshClaims(now))); err == nil {
		t.Fatal("a multi-region token verified as a release token")
	}

	srv, auth, url := startServer(t, v)
	local, err := auth.Connect(srv)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	h = &Handler{Verifier: v, Revision: testSHA, Installed: make(chan struct{}, 1),
		Mesh: func(_ context.Context, op string, spec json.RawMessage) (json.RawMessage, error) {
			if op == "apply" && string(spec) != `{"name":"x"}` {
				return nil, errors.New("spec not forwarded")
			}
			return json.RawMessage(`["` + op + `"]`), nil
		}}
	if err := h.Serve(local); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 4)
	token := i.sign(t, meshClaims(now))
	ci, err := dialCI(url, token, errs)
	if err != nil {
		t.Fatal(err)
	}
	defer ci.Close()
	for subject, spec := range map[string]string{SubjectPing: "", SubjectApply: `{"name":"x"}`} {
		data, _ := json.Marshal(MeshRequest{Token: token, Spec: json.RawMessage(spec)})
		reply, err := request(context.Background(), ci, subject, data, 2*time.Second)
		if err != nil || reply.State != "done" || !strings.Contains(string(reply.Result), strings.TrimPrefix(subject, "ts.release.mesh.")) {
			t.Fatalf("%s = %+v, %v", subject, reply, err)
		}
	}
	// A release token is refused by the bridge.
	data, _ := json.Marshal(MeshRequest{Token: i.sign(t, goodClaims(now))})
	if reply, err := request(context.Background(), ci, SubjectPing, data, 2*time.Second); err != nil || reply.State != "rejected" {
		t.Fatalf("release token ping = %+v, %v", reply, err)
	}
	// The workflow may not publish release subjects.
	if err := ci.Publish(SubjectVersion, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, nats.ErrPermissionViolation) {
			t.Fatalf("async err = %v, want permissions violation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("multi-region token published a release subject")
	}
}
