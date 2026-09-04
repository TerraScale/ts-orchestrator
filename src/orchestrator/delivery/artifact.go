package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ReleaseArtifact is one fetched, verified release candidate: the exact
// bytes named by a DeliveryRequest, their computed digest, and the detached
// signature that verified them.
type ReleaseArtifact struct {
	Service      string
	Digest       string // "sha256:<hex>" as named by the request
	Body         []byte
	SignatureKey string // the trust-set key ID that verified the signature
}

// ArtifactFetcher retrieves the artifact bytes and detached signature named
// by one request. Implementations must fail closed: no bytes, no delivery.
type ArtifactFetcher interface {
	Fetch(ctx context.Context, request *Request) (body []byte, signature string, err error)
}

// ForgejoArtifactFetcher downloads release artifacts from the Forgejo
// package registry the way ts-deploy publishes them (D-68): find the release
// of the request's source commit, download the service asset and its .sig
// sidecar. A Forgejo outage therefore blocks a NEW deploy; the per-Region
// mirrors (D-71) are what keep an in-flight one from being stranded.
type ForgejoArtifactFetcher struct {
	// BaseURL is the Forgejo instance root (for example https://forgejo.terrascale.tech).
	BaseURL string
	// Token returns the registry read token; optional for public releases.
	Token func() string
	// Client is the HTTP client; defaults to a 10-minute client with bounded bodies.
	Client *http.Client
}

// forgejoRelease is the subset of the Forgejo release document used.
type forgejoRelease struct {
	TargetCommitish string         `json:"target_commitish"`
	Assets          []forgejoAsset `json:"assets"`
}

type forgejoAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func (f *ForgejoArtifactFetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// Fetch resolves the release for the request's commit and downloads the
// artifact and signature assets.
func (f *ForgejoArtifactFetcher) Fetch(ctx context.Context, request *Request) ([]byte, string, error) {
	if f == nil || strings.TrimSpace(f.BaseURL) == "" {
		return nil, "", errors.New("delivery: artifact fetcher is not configured")
	}
	if request == nil || request.Source == nil || request.Artifact == nil {
		return nil, "", errors.New("delivery: artifact fetch requires source and artifact identity")
	}
	release, err := f.releaseForCommit(ctx, request)
	if err != nil {
		return nil, "", err
	}
	asset, signatureAsset, err := releaseAssets(release, request)
	if err != nil {
		return nil, "", err
	}
	body, err := f.download(ctx, asset.BrowserDownloadURL, MaxArtifactBytes)
	if err != nil {
		return nil, "", err
	}
	signature, err := f.download(ctx, signatureAsset.BrowserDownloadURL, MaxDocumentBytes)
	if err != nil {
		return nil, "", err
	}
	return body, string(signature), nil
}

func (f *ForgejoArtifactFetcher) releaseForCommit(ctx context.Context, request *Request) (*forgejoRelease, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/releases?limit=50", url.PathEscape(request.Source.Repository))
	body, err := f.download(ctx, strings.TrimSuffix(f.BaseURL, "/")+path, MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("delivery: release listing for %s failed: %w", request.Source.Repository, err)
	}
	var releases []forgejoRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, errors.New("delivery: release listing is not valid JSON")
	}
	for i := range releases {
		if strings.EqualFold(strings.TrimSpace(releases[i].TargetCommitish), request.Source.Commit) {
			return &releases[i], nil
		}
	}
	return nil, fmt.Errorf("delivery: no release of %s at commit %s", request.Source.Repository, request.Source.Commit)
}

// releaseAssets picks the artifact asset by the ts-deploy naming convention
// (<service>-linux-<arch>) plus its <name>.sig sidecar.
func releaseAssets(release *forgejoRelease, request *Request) (forgejoAsset, forgejoAsset, error) {
	arch := strings.TrimPrefix(request.Artifact.Architecture, "linux/")
	if arch == "multi" {
		arch = "arm64"
	}
	artifactName := fmt.Sprintf("%s-linux-%s", request.Target.Service, arch)
	var artifact, signature forgejoAsset
	for _, asset := range release.Assets {
		switch asset.Name {
		case artifactName:
			artifact = asset
		case artifactName + ".sig":
			signature = asset
		}
	}
	if artifact.BrowserDownloadURL == "" || signature.BrowserDownloadURL == "" {
		return forgejoAsset{}, forgejoAsset{}, fmt.Errorf("delivery: release has no verified %s asset pair", artifactName)
	}
	return artifact, signature, nil
}

func (f *ForgejoArtifactFetcher) download(ctx context.Context, target string, limit int64) ([]byte, error) {
	parsed, err := url.Parse(target)
	if err != nil || !parsed.IsAbs() || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("delivery: artifact download URL is invalid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if f.Token != nil {
		if token := f.Token(); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	response, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("delivery: artifact download returned status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("delivery: artifact download exceeds the size bound")
	}
	return body, nil
}

// SHA256Digest computes the contract digest form of a byte slice.
func SHA256Digest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// verifyArtifact fetches and verifies one release candidate against its
// request: size bound, exact sha256 match, and a detached ed25519 signature
// that verifies under the active trust set. Any mismatch is a typed,
// fail-closed rejection; the rollout never starts without this passing.
func verifyArtifact(ctx context.Context, fetcher ArtifactFetcher, trust *TrustSet, request *Request) (*ReleaseArtifact, error) {
	if request.Artifact == nil {
		return nil, errors.New("delivery: request carries no artifact identity")
	}
	body, signatureText, err := fetcher.Fetch(ctx, request)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > MaxArtifactBytes || len(body) == 0 {
		return nil, errors.New("delivery: artifact size is outside the admitted bound")
	}
	computed := SHA256Digest(body)
	if !SameDigest(computed, request.Artifact.Digest) {
		return nil, errors.New("delivery: artifact sha256 does not match the request")
	}
	signature, err := DecodeSignature(signatureText)
	if err != nil {
		return nil, err
	}
	if !trust.VerifySignature(body, signature) {
		return nil, errors.New("delivery: artifact signature failed verification against the release trust set")
	}
	keyID := trust.verifyingKey(body, signature)
	return &ReleaseArtifact{
		Service:      request.Target.Service,
		Digest:       computed,
		Body:         body,
		SignatureKey: keyID,
	}, nil
}
