package delivery

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testRelease builds one signed release pair: a request naming the artifact
// digest, a fetcher serving the artifact and its detached signature.
func testRelease(t *testing.T, mutate func(*Request)) (*Request, ArtifactFetcher, *TrustSet, []byte) {
	t.Helper()
	body := []byte("terrabase-release-bytes")
	digest := SHA256Digest(body)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	request, err := ParseRequest(golden(t, goldenRequestPath))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Artifact.Digest = digest
	request.Artifact.ManifestDigest = SHA256Digest([]byte("manifest"))
	if mutate != nil {
		mutate(request)
	}
	fetcher := &staticFetcher{body: body, signature: signature}
	trust, err := NewTrustSet(map[string]ed25519.PublicKey{"release-2026-08": public})
	if err != nil {
		t.Fatalf("build trust set: %v", err)
	}
	return request, fetcher, trust, body
}

type staticFetcher struct {
	body      []byte
	signature string
	err       error
}

func (f *staticFetcher) Fetch(context.Context, *Request) ([]byte, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	return f.body, f.signature, nil
}

func TestTrustSetFailsClosed(t *testing.T) {
	message := []byte("artifact")
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature := ed25519.Sign(private, message)

	if (&TrustSet{}).VerifySignature(message, signature) {
		t.Fatal("an empty trust set must never verify")
	}
	var nilTrust *TrustSet
	if nilTrust.VerifySignature(message, signature) {
		t.Fatal("a nil trust set must never verify")
	}
	public := private.Public().(ed25519.PublicKey)
	trust, err := NewTrustSet(map[string]ed25519.PublicKey{"k1": public})
	if err != nil {
		t.Fatalf("build trust set: %v", err)
	}
	if !trust.VerifySignature(message, signature) {
		t.Fatal("the correct key must verify")
	}
	if trust.VerifySignature([]byte("tampered"), signature) {
		t.Fatal("a tampered body must fail verification")
	}
	if trust.VerifySignature(message, append([]byte{}, signature[:63]...)) {
		t.Fatal("a truncated signature must fail verification")
	}

	// Two-key overlap: the previous key keeps verifying after rotation adds
	// the next one (D-70).
	previousPublic := public
	_, nextPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate next key: %v", err)
	}
	overlap, err := NewTrustSet(map[string]ed25519.PublicKey{
		"k1": previousPublic,
		"k2": nextPrivate.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("build overlap trust set: %v", err)
	}
	if !overlap.VerifySignature(message, signature) {
		t.Fatal("the previous key must still verify during overlap")
	}
	if !overlap.VerifySignature(message, ed25519.Sign(nextPrivate, message)) {
		t.Fatal("the next key must verify during overlap")
	}
	if _, err := NewTrustSet(map[string]ed25519.PublicKey{}); err == nil {
		t.Fatal("an empty trust set must be refused at construction")
	}
}

func TestVerifyArtifactFailsClosed(t *testing.T) {
	ctx := context.Background()

	request, fetcher, trust, _ := testRelease(t, nil)
	artifact, err := verifyArtifact(ctx, fetcher, trust, request)
	if err != nil {
		t.Fatalf("happy path verify: %v", err)
	}
	if !SameDigest(artifact.Digest, request.Artifact.Digest) {
		t.Fatalf("digest %s does not match the request", artifact.Digest)
	}

	// sha256 mismatch: the fetched bytes do not match the request identity.
	tampered := &staticFetcher{body: []byte("different-bytes"), signature: fetcher.(*staticFetcher).signature}
	if _, err := verifyArtifact(ctx, tampered, trust, request); err == nil {
		t.Fatal("a digest mismatch must fail closed")
	}

	// signature not under trust: a random signer is rejected.
	_, stranger, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate stranger key: %v", err)
	}
	strangerFetcher := &staticFetcher{body: fetcher.(*staticFetcher).body,
		signature: base64.StdEncoding.EncodeToString(ed25519.Sign(stranger, fetcher.(*staticFetcher).body))}
	if _, err := verifyArtifact(ctx, strangerFetcher, trust, request); err == nil {
		t.Fatal("an untrusted signature must fail closed")
	}

	// malformed signature text and fetch failure both fail closed.
	if _, err := verifyArtifact(ctx, &staticFetcher{body: fetcher.(*staticFetcher).body, signature: "not-base64!!!"}, trust, request); err == nil {
		t.Fatal("a malformed signature must fail closed")
	}
	if _, err := verifyArtifact(ctx, &staticFetcher{err: fmt.Errorf("forgejo down")}, trust, request); err == nil {
		t.Fatal("a fetch failure must fail closed")
	}
}

// TestForgejoFetcherDownloadsReleasePair exercises the real fetcher against
// a fake Forgejo: release listing by commit, asset pair download.
func TestForgejoFetcherDownloadsReleasePair(t *testing.T) {
	body := []byte("release-bytes")
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch incoming.URL.Path {
		case "/api/v1/repos/terrabase/releases":
			_ = json.NewEncoder(writer).Encode([]map[string]any{{
				"target_commitish": "0000000000000000000000000000000000000000",
				"assets":           []map[string]any{},
			}, {
				"target_commitish": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
				"assets": []map[string]any{
					{"name": "terrabase-linux-arm64", "browser_download_url": serverURL(incoming) + "/download/terrabase-linux-arm64"},
					{"name": "terrabase-linux-arm64.sig", "browser_download_url": serverURL(incoming) + "/download/terrabase-linux-arm64.sig"},
				},
			}})
		case "/download/terrabase-linux-arm64":
			_, _ = writer.Write(body)
		case "/download/terrabase-linux-arm64.sig":
			_, _ = writer.Write([]byte(signature))
		default:
			http.NotFound(writer, incoming)
		}
	}))
	defer server.Close()

	request, _, _, _ := testRelease(t, nil)
	fetcher := &ForgejoArtifactFetcher{BaseURL: server.URL}
	fetchedBody, fetchedSignature, err := fetcher.Fetch(context.Background(), request)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(fetchedBody) != string(body) || fetchedSignature != signature {
		t.Fatal("fetch returned the wrong asset pair")
	}

	noRelease := &ForgejoArtifactFetcher{BaseURL: server.URL}
	missing, err := ParseRequest(golden(t, goldenRequestPath))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	missing.Source.Commit = strings.Repeat("9", 40)
	if _, _, err := noRelease.Fetch(context.Background(), missing); err == nil {
		t.Fatal("an unknown commit must fail closed")
	}
}

func serverURL(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host
}
