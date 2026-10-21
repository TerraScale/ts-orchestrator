package swarmruntime

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/moby/swarmkit/v2/api"
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
