package delivery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestReleaseAssetsUsesAuthenticatedCustomName(t *testing.T) {
	request, _, _, _ := testRelease(t, nil)
	request.Artifact.Name = "sdk-package.tgz"
	release := &forgejoRelease{Assets: []forgejoAsset{{Name: "terrabase-linux-arm64", BrowserDownloadURL: "wrong"}, {Name: "terrabase-linux-arm64.sig", BrowserDownloadURL: "wrong-sig"}, {Name: "sdk-package.tgz", BrowserDownloadURL: "exact"}, {Name: "sdk-package.tgz.sig", BrowserDownloadURL: "exact-sig"}}}
	artifact, signature, err := releaseAssets(release, request)
	if err != nil || artifact.BrowserDownloadURL != "exact" || signature.BrowserDownloadURL != "exact-sig" {
		t.Fatalf("assets=%+v,%+v err=%v", artifact, signature, err)
	}
	for _, name := range []string{"", "..", "../x", `..\\x`} {
		request.Artifact.Name = name
		if _, _, err := releaseAssets(release, request); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
}

func TestForgejoFetcherRejectsUntrustedAssetOrigin(t *testing.T) {
	var attackerHits int
	var attackerAuthorization string
	var attackerMu sync.Mutex
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerMu.Lock()
		attackerHits++
		attackerAuthorization = r.Header.Get("Authorization")
		attackerMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	var forgejo *httptest.Server
	forgejo = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/repos/terrabase/releases" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"target_commitish": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
			"assets": []map[string]any{
				{"name": "terrabase-linux-arm64", "browser_download_url": attacker.URL + "/download/terrabase-linux-arm64"},
				{"name": "terrabase-linux-arm64.sig", "browser_download_url": attacker.URL + "/download/terrabase-linux-arm64.sig"},
			},
		}})
	}))
	defer forgejo.Close()

	request, _, _, _ := testRelease(t, nil)
	fetcher := &ForgejoArtifactFetcher{
		BaseURL: forgejo.URL,
		Token:   func() string { return "forgejo-secret" },
		Client:  forgejo.Client(),
	}
	if _, _, err := fetcher.Fetch(context.Background(), request); err == nil {
		t.Fatal("an asset URL on another origin must be rejected")
	}

	attackerMu.Lock()
	defer attackerMu.Unlock()
	if attackerHits != 0 || attackerAuthorization != "" {
		t.Fatalf("untrusted asset received a request or token: hits=%d authorization=%q", attackerHits, attackerAuthorization)
	}
}

func TestForgejoFetcherDoesNotForwardTokenAcrossRedirect(t *testing.T) {
	var attackerHits int
	var attackerAuthorization string
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		attackerAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	var forgejo *httptest.Server
	forgejo = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/repos/terrabase/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"target_commitish": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
				"assets": []map[string]any{
					{"name": "terrabase-linux-arm64", "browser_download_url": forgejo.URL + "/download/terrabase-linux-arm64"},
					{"name": "terrabase-linux-arm64.sig", "browser_download_url": forgejo.URL + "/download/terrabase-linux-arm64.sig"},
				},
			}})
		case "/download/terrabase-linux-arm64":
			w.Header().Set("Location", attacker.URL+"/stolen")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer forgejo.Close()

	request, _, _, _ := testRelease(t, nil)
	fetcher := &ForgejoArtifactFetcher{
		BaseURL: forgejo.URL,
		Token:   func() string { return "forgejo-secret" },
		// The fetcher must replace the default redirect-following behavior.
		Client: forgejo.Client(),
	}
	if _, _, err := fetcher.Fetch(context.Background(), request); err == nil {
		t.Fatal("a release asset redirect must be rejected")
	}
	if attackerHits != 0 || attackerAuthorization != "" {
		t.Fatalf("redirect target received a request or token: hits=%d authorization=%q", attackerHits, attackerAuthorization)
	}
}

func TestForgejoFetcherRefusesBearerTokenOnHTTP(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher := &ForgejoArtifactFetcher{
		BaseURL: server.URL,
		Token:   func() string { return "must-not-leave-process" },
	}
	if _, err := fetcher.downloadAsset(context.Background(), server.URL+"/download/asset", 1024, "asset"); err == nil {
		t.Fatal("a bearer token must not be used with an HTTP Forgejo origin")
	}
	if hits != 0 {
		t.Fatalf("HTTP endpoint received a request despite bearer-token refusal: %d", hits)
	}
}

func TestForgejoFetcherRejectsUnsafeAssetPaths(t *testing.T) {
	base := &ForgejoArtifactFetcher{BaseURL: "https://forgejo.example"}
	for _, path := range []string{
		"http://forgejo.example/download/terrabase-linux-arm64",
		"https://user:password@forgejo.example/download/terrabase-linux-arm64",
		"https://forgejo.example/api/v1/repos/terrabase/contents/terrabase-linux-arm64",
		"https://forgejo.example/terrabase/releases/download/v1/other",
		"https://forgejo.example/terrabase/releases/download/v1/../terrabase-linux-arm64",
		"https://forgejo.example/" + strings.Repeat("a", forgejoPathLimit) + "/download/terrabase-linux-arm64",
	} {
		if _, err := base.downloadAsset(context.Background(), path, MaxArtifactBytes, "terrabase-linux-arm64"); err == nil {
			t.Errorf("unsafe release asset path %q was accepted", path)
		}
	}
	nonLocalHTTP := &ForgejoArtifactFetcher{BaseURL: "http://forgejo.example"}
	if _, err := nonLocalHTTP.downloadAsset(context.Background(), "http://forgejo.example/download/terrabase-linux-arm64", MaxArtifactBytes, "terrabase-linux-arm64"); err == nil {
		t.Fatal("non-local HTTP Forgejo origins must be rejected")
	}
}

func TestForgejoFetcherRejectsDeclaredOversizeBeforeRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "11")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer server.Close()

	fetcher := &ForgejoArtifactFetcher{BaseURL: server.URL}
	if _, err := fetcher.downloadAsset(context.Background(), server.URL+"/download/asset", 10, "asset"); err == nil {
		t.Fatal("a declared response larger than the bound must be rejected")
	}
}
