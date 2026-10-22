package swarmruntime

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

type registryRoundTrip func(*http.Request) (*http.Response, error)

func (f registryRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGHCRRegistryResolverAuthenticatesOnlyGHCR(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	task := func(image string) *api.Task {
		intent := serviceIntent()
		intent.Container.Image = image
		runtime, err := ContainerRuntime(intent.Container)
		if err != nil {
			t.Fatal(err)
		}
		return &api.Task{ID: "ghcrfixture", ServiceID: "ghcr", NodeID: "node", Spec: api.TaskSpec{Runtime: runtime, Resources: intent.Resources.Copy()}}
	}
	reads := 0
	token := func(context.Context) (string, error) { reads++; return "vault-memory-token", nil }
	var authorized bool
	transport := registryRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.Host != "ghcr.io" {
			t.Errorf("request to %q", request.Host)
		}
		username, password, ok := request.BasicAuth()
		if ok {
			authorized = username == "MarioGK" && password == "vault-memory-token"
			return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: http.NoBody, Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{"Www-Authenticate": {`Basic realm="ghcr"`}}, Body: http.NoBody, Request: request}, nil
	})
	resolve := ghcrResolver(token, transport)

	image := "ghcr.io/terrascale/app" + digest
	private, err := resolve(t.Context(), task(image), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := private.Resolve(t.Context(), image); err == nil || !authorized || reads != 1 {
		t.Fatalf("ghcr.io pull did not authenticate with Vault token: err=%v authorized=%v reads=%d", err, authorized, reads)
	}

	image = "docker.io/library/nginx" + digest
	public, err := resolve(t.Context(), task(image), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A canceled pull fails before the network; a GHCR-pinned resolver would refuse the host instead.
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := public.Resolve(canceled, image); err == nil || strings.Contains(err.Error(), "differs from admitted") || reads != 1 {
		t.Fatalf("docker.io must stay anonymous: err=%v reads=%d", err, reads)
	}
}

// GHCR answers blob GETs with a 307 to its CDN; the pull follows it without credentials.
func TestGHCRBlobRedirectReachesCDNWithoutCredentials(t *testing.T) {
	image := "ghcr.io/terrascale/app@sha256:" + strings.Repeat("a", 64)
	blob := imagespec.Descriptor{MediaType: imagespec.MediaTypeImageLayerGzip, Digest: digest.Digest("sha256:" + strings.Repeat("b", 64)), Size: 4}
	var cdn bool
	transport := registryRoundTrip(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "ghcr.io":
			header := http.Header{"Location": {"https://" + ghcrBlobHost + "/blob?sig=1"}}
			return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: header, Body: http.NoBody, Request: request}, nil
		case ghcrBlobHost:
			cdn = request.Header.Get("Authorization") == ""
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, ContentLength: 4, Body: io.NopCloser(strings.NewReader("data")), Request: request}, nil
		}
		t.Errorf("request to %q", request.URL.Host)
		return nil, io.EOF
	})
	resolver := privateRegistryResolver(image, "ghcr.io", func(string) (string, string, error) { return ghcrUser, "token", nil }, transport, ghcrBlobHost)
	fetcher, err := resolver.Fetcher(t.Context(), image)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fetcher.Fetch(t.Context(), blob)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if data, err := io.ReadAll(reader); err != nil || string(data) != "data" || !cdn {
		t.Fatalf("blob = %q, %v, reached CDN without credentials = %v", data, err, cdn)
	}
}
