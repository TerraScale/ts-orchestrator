package swarmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ociregistry "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/moby/swarmkit/v2/api"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestRegistryResolverAuthenticatedHTTPIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const host = "gru.ocir.io"
	const repository = "namespace/terrascale/auth"
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}`)
	hash := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	image := host + "/" + repository + "@" + digest
	var authenticated atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Host != host || (request.URL.Path != "/v2/"+repository+"/manifests/"+digest &&
			request.URL.Path != "/v2/"+repository+"/blobs/"+digest) {
			t.Errorf("unexpected registry request %s %s", request.Host, request.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != "namespace/pull-user" || password != "vault-memory-token" {
			w.Header().Set("WWW-Authenticate", `Basic realm="private OCIR"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticated.Add(1)
		w.Header().Set("Content-Type", imagespec.MediaTypeImageManifest)
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		if request.Method != http.MethodHead {
			_, _ = w.Write(manifest)
		}
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	credentials := func(requested string) (string, string, error) {
		if requested != host {
			t.Errorf("credential disclosure to %q", requested)
		}
		return "namespace/pull-user", "vault-memory-token", nil
	}
	resolver := privateRegistryResolver(image, host, credentials, transport)
	name, descriptor, err := resolver.Resolve(ctx, image)
	if err != nil || name != image || descriptor.Digest.String() != digest {
		t.Fatalf("resolve admitted image: %q %+v %v", name, descriptor, err)
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	body, err := fetcher.Fetch(ctx, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(body)
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || string(actual) != string(manifest) || authenticated.Load() < 2 {
		t.Fatalf("authenticated fetch failed: read=%v close=%v requests=%d", readErr, closeErr, authenticated.Load())
	}
	before := authenticated.Load()
	for _, other := range []string{host + "/namespace/another@" + digest, host + "/" + repository + "@sha256:" + strings.Repeat("b", 64)} {
		if _, _, err := resolver.Resolve(ctx, other); err == nil {
			t.Fatal("resolver accepted a different repository or digest")
		}
		if _, err := resolver.Fetcher(ctx, other); err == nil {
			t.Fatal("fetcher accepted a different repository or digest")
		}
	}
	if _, err := resolver.Pusher(ctx, image); err == nil || authenticated.Load() != before {
		t.Fatal("pull authority escaped its admitted reference")
	}
	missing := privateRegistryResolver(image, host, func(string) (string, string, error) { return "", "", nil }, transport)
	if _, _, err := missing.Resolve(ctx, image); err == nil {
		t.Fatal("private registry accepted missing authentication")
	}
	factory, _ := ociresourcetest.Server(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("unadmitted task reached Vault")
		w.WriteHeader(http.StatusForbidden)
	})
	intent := serviceIntent()
	intent.Container.Image = image
	spec, err := intent.serviceSpec()
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: "assignedtask", ServiceID: "serviceid", NodeID: "nodeid", Spec: spec.Task, ServiceAnnotations: spec.Annotations}
	private, err := NewOCIRegistryResolver(factory, func(context.Context, *api.Task) (*RegistryAdmission, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := private(ctx, task, nil); err == nil || err.Error() != "private OCI registry release admission is unavailable" {
		t.Fatalf("missing private admission did not reject before credentials: %v", err)
	}
	private, err = NewOCIRegistryResolver(factory, func(context.Context, *api.Task) (*RegistryAdmission, error) {
		return &RegistryAdmission{ServiceID: "serviceid", Environment: intent.Environment, Region: intent.Region,
			Scope:         ociregistry.PullScope{RegistryHost: host, Repository: repository, Digest: digest, TaskPrincipal: intent.ID},
			VerifyCurrent: func(ctx context.Context) error { return ctx.Err() }}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := private(ctx, task, &api.Node{ID: "different-certificate-node"}); err == nil || err.Error() != "registry release does not match current task and admitted node" {
		t.Fatalf("foreign certificate node did not reject before credentials: %v", err)
	}
}

func TestRegistryResolverRejectsCredentialRealmRedirectionIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var leaked atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		leaked.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+other.URL+`/token",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	image := "gru.ocir.io/namespace/app@sha256:" + strings.Repeat("a", 64)
	resolver := privateRegistryResolver(image, "gru.ocir.io", func(string) (string, string, error) {
		return "namespace/user", "private-token", nil
	}, transport)
	if _, _, err := resolver.Resolve(ctx, image); err == nil || leaked.Load() != 0 {
		t.Fatal("untrusted token realm received registry credentials")
	}
}
