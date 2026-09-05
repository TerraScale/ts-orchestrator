package delivery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	Architecture string // linux/arm64 or linux/amd64; empty means legacy arm64
	Body         []byte
	Signature    []byte // verified raw detached signature
	SignatureKey string // the trust-set key ID that verified the signature
}

// ArtifactFetcher retrieves the artifact bytes and detached signature named
// by one request. Signatures are raw 64-byte Ed25519 sidecars, with no text
// decoding or whitespace normalization. Implementations must fail closed.
type ArtifactFetcher interface {
	Fetch(ctx context.Context, request *Request) (body []byte, signature []byte, err error)
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

const (
	// forgejoDownloadTimeout is the maximum time allowed for any one Forgejo
	// request, including clients supplied by callers without a timeout.
	forgejoDownloadTimeout = 10 * time.Minute
	// forgejoPathLimit keeps release metadata from turning into an unbounded
	// request target while leaving ample room for an owner/repository/tag.
	forgejoPathLimit = 2048
)

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
	var client http.Client
	if f.Client == nil {
		client.Timeout = forgejoDownloadTimeout
	} else {
		// Do not mutate a client owned by the caller. In particular, replacing
		// CheckRedirect here is what makes the bearer-token boundary invariant
		// even when a caller supplied the default (redirect-following) client.
		client = *f.Client
		if client.Timeout <= 0 || client.Timeout > forgejoDownloadTimeout {
			client.Timeout = forgejoDownloadTimeout
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("delivery: artifact download redirects are not allowed")
	}
	return &client
}

// Fetch resolves the release for the request's commit and downloads the
// artifact and signature assets.
func (f *ForgejoArtifactFetcher) Fetch(ctx context.Context, request *Request) ([]byte, []byte, error) {
	if f == nil || strings.TrimSpace(f.BaseURL) == "" {
		return nil, nil, errors.New("delivery: artifact fetcher is not configured")
	}
	if ctx == nil {
		return nil, nil, errors.New("delivery: artifact fetch requires a context")
	}
	if request == nil || request.Source == nil || request.Artifact == nil {
		return nil, nil, errors.New("delivery: artifact fetch requires source and artifact identity")
	}
	release, err := f.releaseForCommit(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	asset, signatureAsset, err := releaseAssets(release, request)
	if err != nil {
		return nil, nil, err
	}
	body, err := f.downloadAsset(ctx, asset.BrowserDownloadURL, MaxArtifactBytes, asset.Name)
	if err != nil {
		return nil, nil, err
	}
	signature, err := f.downloadAsset(ctx, signatureAsset.BrowserDownloadURL, ed25519.SignatureSize, signatureAsset.Name)
	if err != nil {
		return nil, nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, errors.New("delivery: detached artifact signature must be exactly 64 raw Ed25519 bytes")
	}
	return body, signature, nil
}

func (f *ForgejoArtifactFetcher) releaseForCommit(ctx context.Context, request *Request) (*forgejoRelease, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/releases?limit=50", url.PathEscape(request.Source.Repository))
	origin, err := f.origin()
	if err != nil {
		return nil, err
	}
	body, err := f.download(ctx, origin.String()+path, MaxDocumentBytes)
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
	if release == nil || request == nil || request.Artifact == nil || request.Target == nil {
		return forgejoAsset{}, forgejoAsset{}, errors.New("delivery: release asset lookup requires a complete request")
	}
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
	return f.downloadAsset(ctx, target, limit, "")
}

// origin parses the configured Forgejo instance root. The origin is treated
// as the trust boundary for all URLs returned by Forgejo. Production config
// uses HTTPS; retaining the configured scheme here also keeps local HTTP test
// fixtures useful while still rejecting any scheme change in metadata.
func (f *ForgejoArtifactFetcher) origin() (*url.URL, error) {
	if f == nil {
		return nil, errors.New("delivery: artifact fetcher is not configured")
	}
	parsed, err := url.Parse(strings.TrimSpace(f.BaseURL))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("delivery: Forgejo origin is invalid")
	}
	if !isHTTPOrHTTPS(parsed.Scheme) {
		return nil, errors.New("delivery: Forgejo origin must use HTTP or HTTPS")
	}
	if strings.EqualFold(parsed.Scheme, "http") && !isLoopbackHostname(parsed.Hostname()) {
		return nil, errors.New("delivery: Forgejo HTTP origin is limited to local/test hosts")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("delivery: Forgejo origin must not contain a path")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed, nil
}

func sameOrigin(left, right *url.URL) bool {
	if !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	leftPort, rightPort := left.Port(), right.Port()
	if leftPort == rightPort {
		return true
	}
	// An explicit default port is the same origin as its omitted spelling.
	if leftPort == "" {
		leftPort = defaultPort(left.Scheme)
	}
	if rightPort == "" {
		rightPort = defaultPort(right.Scheme)
	}
	return leftPort != "" && leftPort == rightPort
}

func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	if strings.EqualFold(scheme, "http") {
		return "80"
	}
	return ""
}

func isHTTPOrHTTPS(scheme string) bool {
	return strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}

func isLoopbackHostname(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	address := net.ParseIP(hostname)
	return address != nil && address.IsLoopback()
}

func validateReleaseAssetPath(parsed *url.URL, expectedName string) error {
	if expectedName == "" {
		return nil
	}
	if len(expectedName) > 128 || strings.ContainsAny(expectedName, "/\\\x00") {
		return errors.New("delivery: release asset name is invalid")
	}
	path := parsed.Path
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.HasSuffix(path, "/") || len(parsed.EscapedPath()) > forgejoPathLimit || strings.ContainsAny(path, "\\\x00") {
		return errors.New("delivery: release asset URL path is invalid")
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 || segments[len(segments)-1] != expectedName {
		return errors.New("delivery: release asset URL does not name the expected asset")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("delivery: release asset URL path is invalid")
		}
	}
	// Forgejo's browser URL is /<owner>/<repo>/releases/download/<tag>/<name>.
	// /download/<name> is retained for the package's small local fixture.
	standard := len(segments) >= 5 && segments[len(segments)-4] == "releases" && segments[len(segments)-3] == "download"
	fixture := len(segments) == 2 && segments[0] == "download"
	if !standard && !fixture {
		return errors.New("delivery: release asset URL is outside the release download path")
	}
	return nil
}

func (f *ForgejoArtifactFetcher) downloadAsset(ctx context.Context, target string, limit int64, expectedName string) ([]byte, error) {
	origin, err := f.origin()
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" || !sameOrigin(origin, parsed) {
		return nil, errors.New("delivery: artifact download URL is invalid")
	}
	listingQuery := expectedName == "" && parsed.RawQuery == "limit=50" && strings.HasPrefix(parsed.Path, "/api/v1/repos/") && strings.HasSuffix(parsed.Path, "/releases")
	if parsed.RawQuery != "" && !listingQuery {
		return nil, errors.New("delivery: artifact download URL is invalid")
	}
	if err := validateReleaseAssetPath(parsed, expectedName); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, errors.New("delivery: artifact download size bound is invalid")
	}
	requestContext, cancel := context.WithTimeout(ctx, forgejoDownloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	var token string
	if f.Token != nil {
		token = f.Token()
	}
	if token != "" {
		if !strings.EqualFold(origin.Scheme, "https") {
			return nil, errors.New("delivery: bearer credentials require an HTTPS Forgejo origin")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("delivery: artifact download returned status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("delivery: artifact download exceeds the size bound")
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
	if ctx == nil {
		return nil, errors.New("delivery: artifact verification requires a context")
	}
	if fetcher == nil || trust == nil || request == nil || request.Artifact == nil || request.Target == nil {
		return nil, errors.New("delivery: request carries no artifact identity")
	}
	body, signature, err := fetcher.Fetch(ctx, request)
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
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("delivery: detached artifact signature must be exactly 64 raw Ed25519 bytes")
	}
	if !trust.VerifySignature(body, signature) {
		return nil, errors.New("delivery: artifact signature failed verification against the release trust set")
	}
	keyID := trust.verifyingKey(body, signature)
	return &ReleaseArtifact{
		Service:      request.Target.Service,
		Digest:       computed,
		Architecture: request.Artifact.Architecture,
		Body:         append([]byte(nil), body...),
		SignatureKey: keyID,
		Signature:    append([]byte(nil), signature...),
	}, nil
}
