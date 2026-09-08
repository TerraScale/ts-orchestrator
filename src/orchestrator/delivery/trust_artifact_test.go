package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
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
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(private, body)
	request, err := ParseRequest(golden(t, goldenRequestPath))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Artifact.Digest = digest
	request.Artifact.SignatureDigest = SHA256Digest(signature)
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
	signature []byte
	err       error
}

func (f *staticFetcher) Fetch(context.Context, *Request) ([]byte, []byte, error) {
	if f.err != nil {
		return nil, nil, f.err
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
		signature: ed25519.Sign(stranger, fetcher.(*staticFetcher).body)}
	if _, err := verifyArtifact(ctx, strangerFetcher, trust, request); err == nil {
		t.Fatal("an untrusted signature must fail closed")
	}

	// malformed signature bytes and fetch failure both fail closed.
	if _, err := verifyArtifact(ctx, &staticFetcher{body: fetcher.(*staticFetcher).body, signature: []byte("not-a-raw-signature")}, trust, request); err == nil {
		t.Fatal("a malformed signature must fail closed")
	}
	if _, err := verifyArtifact(ctx, &staticFetcher{err: fmt.Errorf("forgejo down")}, trust, request); err == nil {
		t.Fatal("a fetch failure must fail closed")
	}
}

func TestVerifyArtifactCarriesSignedSnippetIdentityIntoRollout(t *testing.T) {
	request, fetcher, trust, _ := testRelease(t, func(request *Request) {
		request.Artifact.Snippet = &SnippetArtifact{
			Kind: "cloudflare-snippet", Name: "ts-gate", SourcePath: "snippet/snippet.ts",
			MainModule: "snippet.ts", ContentType: "application/javascript",
			Digest: SHA256Digest([]byte("snippet")), Bytes: len("snippet"),
		}
	})
	artifact, err := verifyArtifact(t.Context(), fetcher, trust, request)
	if err != nil {
		t.Fatalf("verify artifact: %v", err)
	}
	if artifact.Snippet == nil || artifact.Snippet.Digest != request.Artifact.Snippet.Digest {
		t.Fatalf("verified Snippet identity = %+v, want %+v", artifact.Snippet, request.Artifact.Snippet)
	}
	request.Artifact.Snippet.Digest = SHA256Digest([]byte("changed"))
	if artifact.Snippet.Digest == request.Artifact.Snippet.Digest {
		t.Fatal("verified Snippet identity aliases the mutable request")
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
	signature := ed25519.Sign(private, body)
	manifest := []byte(`{"schemaVersion":1,"repository":"terrabase","kind":"service","commit":"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3","artifacts":[{"name":"terrabase-linux-arm64","path":"terrabase-linux-arm64","architecture":"linux/arm64","digest":"` + SHA256Digest(body) + `","signatureDigest":"` + SHA256Digest(signature) + `","bytes":13}]}`)
	manifestSignature := ed25519.Sign(private, manifest)
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
					{"name": "release-manifest.json", "browser_download_url": serverURL(incoming) + "/download/release-manifest.json"},
					{"name": "release-manifest.json.sig", "browser_download_url": serverURL(incoming) + "/download/release-manifest.json.sig"},
				},
			}})
		case "/download/terrabase-linux-arm64":
			_, _ = writer.Write(body)
		case "/download/terrabase-linux-arm64.sig":
			_, _ = writer.Write(signature)
		case "/download/release-manifest.json":
			_, _ = writer.Write(manifest)
		case "/download/release-manifest.json.sig":
			_, _ = writer.Write(manifestSignature)
		default:
			http.NotFound(writer, incoming)
		}
	}))
	defer server.Close()

	request, _, _, _ := testRelease(t, nil)
	request.Artifact.ManifestName = "release-manifest.json"
	request.Artifact.ManifestDigest = SHA256Digest(manifest)
	request.Artifact.ManifestSignatureDigest = SHA256Digest(manifestSignature)
	fetcher := &ForgejoArtifactFetcher{BaseURL: server.URL}
	fetchedBody, fetchedSignature, err := fetcher.Fetch(context.Background(), request)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(fetchedBody) != string(body) || !bytes.Equal(fetchedSignature, signature) {
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

func TestDetachedArtifactSignaturesAreRawEd25519Only(t *testing.T) {
	body := []byte("terrabase-release-bytes")
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, body)
	trust, err := NewTrustSet(map[string]ed25519.PublicKey{"release": public})
	if err != nil {
		t.Fatal(err)
	}
	request, err := ParseRequest(golden(t, goldenRequestPath))
	if err != nil {
		t.Fatal(err)
	}
	request.Artifact.Digest = SHA256Digest(body)
	request.Artifact.SignatureDigest = SHA256Digest(signature)
	request.Artifact.ManifestName = "release-manifest.json"
	manifest := []byte(`{"schemaVersion":1,"repository":"terrabase","kind":"service","commit":"` + request.Source.Commit + `","artifacts":[{"name":"` + request.Artifact.Name + `","path":"` + request.Artifact.Name + `","architecture":"` + request.Artifact.Architecture + `","digest":"` + request.Artifact.Digest + `","signatureDigest":"` + SHA256Digest(signature) + `","bytes":` + fmt.Sprint(len(body)) + `}]}`)
	request.Artifact.ManifestDigest = SHA256Digest(manifest)
	request.Artifact.ManifestSignatureDigest = SHA256Digest(ed25519.Sign(private, manifest))
	variants := []struct {
		name      string
		signature []byte
		valid     bool
	}{
		{name: "raw64", signature: signature, valid: true},
		{name: "base64", signature: []byte(base64.StdEncoding.EncodeToString(signature))},
		{name: "unpadded-base64", signature: []byte(base64.RawStdEncoding.EncodeToString(signature))},
		{name: "hex", signature: []byte(hex.EncodeToString(signature))},
		{name: "raw-with-newline", signature: append(append([]byte(nil), signature...), '\n')},
		{name: "truncated", signature: signature[:63]},
		{name: "empty"},
		{name: "invalid-raw64", signature: make([]byte, ed25519.SignatureSize)},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/repos/terrabase/releases":
					_ = json.NewEncoder(w).Encode([]map[string]any{{
						"target_commitish": request.Source.Commit,
						"assets": []map[string]any{
							{"name": "terrabase-linux-arm64", "browser_download_url": serverURL(r) + "/download/terrabase-linux-arm64"},
							{"name": "terrabase-linux-arm64.sig", "browser_download_url": serverURL(r) + "/download/terrabase-linux-arm64.sig"},
							{"name": "release-manifest.json", "browser_download_url": serverURL(r) + "/download/release-manifest.json"},
							{"name": "release-manifest.json.sig", "browser_download_url": serverURL(r) + "/download/release-manifest.json.sig"},
						},
					}})
				case "/download/terrabase-linux-arm64":
					_, _ = w.Write(body)
				case "/download/terrabase-linux-arm64.sig":
					w.Header().Set("Content-Type", "application/octet-stream")
					_, _ = w.Write(variant.signature)
				case "/download/release-manifest.json":
					variantManifest := []byte(`{"schemaVersion":1,"repository":"terrabase","kind":"service","commit":"` + request.Source.Commit + `","artifacts":[{"name":"` + request.Artifact.Name + `","path":"` + request.Artifact.Name + `","architecture":"` + request.Artifact.Architecture + `","digest":"` + request.Artifact.Digest + `","signatureDigest":"` + SHA256Digest(variant.signature) + `","bytes":` + fmt.Sprint(len(body)) + `}]}`)
					_, _ = w.Write(variantManifest)
				case "/download/release-manifest.json.sig":
					variantManifest := []byte(`{"schemaVersion":1,"repository":"terrabase","kind":"service","commit":"` + request.Source.Commit + `","artifacts":[{"name":"` + request.Artifact.Name + `","path":"` + request.Artifact.Name + `","architecture":"` + request.Artifact.Architecture + `","digest":"` + request.Artifact.Digest + `","signatureDigest":"` + SHA256Digest(variant.signature) + `","bytes":` + fmt.Sprint(len(body)) + `}]}`)
					_, _ = w.Write(ed25519.Sign(private, variantManifest))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			_, err := verifyArtifact(t.Context(), &ForgejoArtifactFetcher{BaseURL: server.URL}, trust, request)
			if (err == nil) != variant.valid {
				t.Fatalf("HTTP release verification valid=%t, err=%v", variant.valid, err)
			}
			_, err = verifyArtifact(t.Context(), &staticFetcher{body: body, signature: variant.signature}, trust, request)
			if (err == nil) != variant.valid {
				t.Fatalf("direct release verification valid=%t, err=%v", variant.valid, err)
			}
		})
	}
}

func TestRawSignatureBytesAreNeverWhitespaceTrimmed(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	var body, signature []byte
	for i := 0; i < 256; i++ {
		body = []byte(fmt.Sprintf("raw-signature-%d", i))
		signature = ed25519.Sign(private, body)
		if signature[len(signature)-1] == '\n' {
			break
		}
	}
	if signature[len(signature)-1] != '\n' {
		t.Fatal("test fixture needs a signature ending in a newline byte")
	}
	request, _, _, _ := testRelease(t, nil)
	request.Artifact.Digest = SHA256Digest(body)
	request.Artifact.SignatureDigest = SHA256Digest(signature)
	trust, err := NewTrustSet(map[string]ed25519.PublicKey{"raw-key": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArtifact(t.Context(), &staticFetcher{body: body, signature: signature}, trust, request); err != nil {
		t.Fatalf("valid raw signature was altered: %v", err)
	}
}
