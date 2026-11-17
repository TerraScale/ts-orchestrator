package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	repositoryPath = "/repos/TerraScale/ts-orchestrator"
	downloadPath   = "/TerraScale/ts-orchestrator/releases/download/"
	bundleAsset    = "provenance.sigstore.json"
)

type githubAsset struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Digest string `json:"digest"`
}

type githubRelease struct {
	Tag        string        `json:"tag_name"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

type fakeGitHub struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	mu        sync.Mutex
	releases  []githubRelease
	files     map[string][]byte
	compare   map[string]comparison
	compared  map[string]int
	replied   map[string]int
	version   int
	token     string
	listed    map[string][]time.Time
	unchanged int
}

func newGitHub() *fakeGitHub {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	g := &fakeGitHub{key: key, files: map[string][]byte{}, compare: map[string]comparison{},
		compared: map[string]int{}, replied: map[string]int{}, listed: map[string][]time.Time{}}
	g.server = httptest.NewServer(http.HandlerFunc(g.serve))
	return g
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case r.URL.Path == "/jwks":
		must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "kid": "e2e", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(g.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(g.key.E)).Bytes()),
		}}}))
	case r.URL.Path == "/token":
		must(json.NewEncoder(w).Encode(map[string]string{"value": g.token}))
	case r.URL.Path == repositoryPath+"/releases":
		who := r.Header.Get(callerHeader)
		g.listed[who] = append(g.listed[who], time.Now())
		etag := fmt.Sprintf(`"%d"`, g.version)
		w.Header().Set("X-RateLimit-Remaining", "59")
		if r.Header.Get("If-None-Match") == etag {
			g.unchanged++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		must(json.NewEncoder(w).Encode(g.releases))
	case strings.HasPrefix(r.URL.Path, repositoryPath+"/compare/"):
		key := strings.TrimPrefix(r.URL.Path, repositoryPath+"/compare/")
		found, ok := g.compare[key]
		if !ok || r.URL.Query().Get("per_page") != "1" || r.URL.Query().Has("page") {
			http.NotFound(w, r)
			return
		}
		body, err := json.Marshal(found.reply(r.URL.String()))
		must(err)
		g.compared[key]++
		g.replied[key] = len(body)
		_, _ = w.Write(body)
	default:
		data, ok := g.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}
}

type comparison struct {
	status    string
	aheadBy   int
	behindBy  int
	base      string
	mergeBase string
}

type changedFile struct {
	Name   string `json:"filename"`
	Status string `json:"status"`
	Patch  string `json:"patch"`
}

type compareReply struct {
	URL       string              `json:"url"`
	Base      map[string]string   `json:"base_commit"`
	MergeBase map[string]string   `json:"merge_base_commit"`
	Status    string              `json:"status"`
	AheadBy   int                 `json:"ahead_by"`
	BehindBy  int                 `json:"behind_by"`
	Total     int                 `json:"total_commits"`
	Commits   []map[string]string `json:"commits"`
	Files     []changedFile       `json:"files"`
}

func (c comparison) reply(url string) compareReply {
	files := make([]changedFile, 300)
	for i := range files {
		files[i] = changedFile{Name: fmt.Sprintf("internal/large/file%03d.go", i), Status: "modified", Patch: strings.Repeat("+\tlarge release line\n", 240)}
	}
	return compareReply{URL: url, Base: map[string]string{"sha": c.base}, MergeBase: map[string]string{"sha": c.mergeBase},
		Status: c.status, AheadBy: c.aheadBy, BehindBy: c.behindBy, Total: c.aheadBy, Commits: []map[string]string{}, Files: files}
}

func (g *fakeGitHub) listingGaps() (int, int, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	count, shortest := 0, time.Duration(0)
	for _, times := range g.listed {
		count += len(times)
		for i := 1; i < len(times); i++ {
			if gap := times[i].Sub(times[i-1]); shortest == 0 || gap < shortest {
				shortest = gap
			}
		}
	}
	return count, g.unchanged, shortest
}

type published struct {
	tag    string
	sha    string
	run    string
	digest string
}

func (g *fakeGitHub) publish(sha, run, asset string, attested, served, bundle []byte) published {
	g.mu.Lock()
	defer g.mu.Unlock()
	tag := "ci-" + sha + "-run-" + run
	sum := sha256.Sum256(attested)
	digest := fmt.Sprintf("%x", sum)
	release := githubRelease{Tag: tag, Prerelease: true, Assets: []githubAsset{{Name: asset, State: "uploaded", Digest: "sha256:" + digest}}}
	g.files[downloadPath+tag+"/"+asset] = served
	if bundle != nil {
		g.files[downloadPath+tag+"/"+bundleAsset] = bundle
	}
	release.Assets = append(release.Assets, githubAsset{Name: bundleAsset, State: "uploaded"})
	g.releases = append([]githubRelease{release}, g.releases...)
	g.version++
	return published{tag: tag, sha: sha, run: run, digest: digest}
}

func (g *fakeGitHub) mint(sha, run string) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"e2e"}`))
	claims, err := json.Marshal(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch", "exp": time.Now().Add(time.Hour).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": sha, "run_id": run, "run_attempt": "1", "event_name": "push",
		"workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
	})
	must(err)
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, digest[:])
	must(err)
	g.mu.Lock()
	g.token = unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	g.mu.Unlock()
}

const callerHeader = "X-E2E-Caller"

type rewrite struct {
	base   *url.URL
	caller string
}

func (r rewrite) RoundTrip(request *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(request.URL.Hostname(), "github.com") {
		return http.DefaultTransport.RoundTrip(request)
	}
	clone := request.Clone(request.Context())
	clone.URL.Scheme, clone.URL.Host, clone.Host = r.base.Scheme, r.base.Host, r.base.Host
	clone.Header.Set(callerHeader, r.caller)
	return http.DefaultTransport.RoundTrip(clone)
}

func githubClient(base, caller string) *http.Client {
	parsed, err := url.Parse(base)
	must(err)
	return &http.Client{Transport: rewrite{parsed, caller}, Timeout: 30 * time.Second}
}
