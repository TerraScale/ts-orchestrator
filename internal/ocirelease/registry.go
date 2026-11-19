package ocirelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
)

const (
	Package            = "orchestrator-release"
	Stable             = "stable"
	manifestType       = "application/vnd.oci.image.manifest.v1+json"
	titleKey           = "org.opencontainers.image.title"
	manifestLimit      = 64 << 10
	requestWait        = 30 * time.Second
	regionPublishBound = 2 * time.Minute
)

type Registry struct {
	Base       string
	Repository string
	Client     *http.Client
}

func NewRegistry(base, repository string, token func(context.Context) (string, error), next http.RoundTripper) (Registry, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.Path != "" {
		return Registry{}, fmt.Errorf("registry base %q must be scheme://host", base)
	}
	tokens := &tokens{host: parsed.Host, token: token, next: next}
	return Registry{Base: base, Repository: repository, Client: &http.Client{Transport: tokens, Timeout: requestWait}}, nil
}

func (r Registry) BlobURL(digest string) string {
	return r.Base + "/v2/" + r.Repository + "/blobs/" + digest
}

func (r Registry) ManifestURL(reference string) string {
	return r.Base + "/v2/" + r.Repository + "/manifests/" + reference
}

func (r Registry) Manifest(ctx context.Context, reference string) ([]byte, string, error) {
	data, err := r.get(ctx, r.ManifestURL(reference), manifestType, manifestLimit)
	if err != nil {
		return nil, "", err
	}
	digest := digestOf(data)
	if strings.HasPrefix(reference, "sha256:") && digest != reference {
		return nil, "", fmt.Errorf("%w: manifest %s has digest %s", releaseattest.ErrRefused, reference, digest)
	}
	return data, digest, nil
}

func (r Registry) Blob(ctx context.Context, digest string, limit int64) ([]byte, error) {
	data, err := r.get(ctx, r.BlobURL(digest), "", limit)
	if err != nil {
		return nil, err
	}
	if got := digestOf(data); got != digest {
		return nil, fmt.Errorf("%w: blob %s has digest %s", releaseattest.ErrRefused, digest, got)
	}
	return data, nil
}

func (r Registry) get(ctx context.Context, target, accept string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	response, err := r.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, &releaseattest.NotFoundError{URL: target}
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry %s: %s", target, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("registry %s: larger than %d bytes", target, limit)
	}
	return data, err
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type tokens struct {
	host  string
	token func(context.Context) (string, error)
	next  http.RoundTripper
}

func (t *tokens) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != t.host {
		return t.next.RoundTrip(request)
	}
	token, err := t.token(request.Context())
	if err != nil {
		return nil, fmt.Errorf("registry token for %s: %w", t.host, err)
	}
	authorized := request.Clone(request.Context())
	authorized.Header.Set("Authorization", "Bearer "+token)
	return t.next.RoundTrip(authorized)
}
