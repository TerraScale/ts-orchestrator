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
	"strconv"
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

	mu       sync.Mutex
	releases []githubRelease
	files    map[string][]byte
	compare  map[string]comparison
	version  int
	token    string
	listings int
}

func newGitHub() *fakeGitHub {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	g := &fakeGitHub{key: key, files: map[string][]byte{}, compare: map[string]comparison{}}
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
		g.listings++
		etag := fmt.Sprintf(`"%d"`, g.version)
		w.Header().Set("X-RateLimit-Remaining", "59")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		must(json.NewEncoder(w).Encode(g.releases))
	case strings.HasPrefix(r.URL.Path, repositoryPath+"/compare/"):
		found, ok := g.compare[strings.TrimPrefix(r.URL.Path, repositoryPath+"/compare/")]
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if !ok || err != nil || r.URL.Query().Get("per_page") != "1" || page < 1 || page > max(1, len(found.commits)) {
			http.NotFound(w, r)
			return
		}
		commits := []map[string]string{}
		if len(found.commits) != 0 {
			commits = append(commits, map[string]string{"sha": found.commits[page-1]})
		}
		must(json.NewEncoder(w).Encode(map[string]any{"status": found.status, "ahead_by": len(found.commits),
			"base_commit": map[string]string{"sha": found.base}, "merge_base_commit": map[string]string{"sha": found.mergeBase}, "commits": commits}))
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
	base      string
	mergeBase string
	commits   []string
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

type rewrite struct{ base *url.URL }

func (r rewrite) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme, clone.URL.Host, clone.Host = r.base.Scheme, r.base.Host, r.base.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func githubClient(base string) *http.Client {
	parsed, err := url.Parse(base)
	must(err)
	return &http.Client{Transport: rewrite{parsed}, Timeout: 30 * time.Second}
}
