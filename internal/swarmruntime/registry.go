package swarmruntime

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	ociregistry "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/moby/swarmkit/v2/api"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

// RegistryResolver receives the current upstream assignment and certificate node.
type RegistryResolver func(context.Context, *api.Task, *api.Node) (remotes.Resolver, error)

// RegistryAdmission is independently verified release scope and root-owned Vault
// metadata. Task annotations alone must never produce this authority.
type RegistryAdmission struct {
	ServiceID, Environment, Region string
	Scope                          ociregistry.PullScope
	Secret                         ociregistry.PullSecret
	Claim                          ociregistry.PullClaim
	Deadline                       time.Time
	// VerifyCurrent rechecks the captured task and authority before each Vault dispatch and afterward.
	VerifyCurrent func(context.Context) error
}

// NewOCIRegistryResolver reads admitted private credentials automatically for
// each pull. lookup verifies current signed release admission and root ownership.
func NewOCIRegistryResolver(factory *ociclient.Factory, lookup func(context.Context, *api.Task) (*RegistryAdmission, error)) (RegistryResolver, error) {
	if lookup == nil {
		return nil, errors.New("registry requires authenticated release admission")
	}
	secrets, err := ociregistry.NewPullSecrets(factory)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, task *api.Task, node *api.Node) (remotes.Resolver, error) {
		spec, err := DecodeContainer(task)
		if err != nil {
			return nil, err
		}
		admitted, err := lookup(ctx, task.Copy())
		if err != nil {
			return nil, errors.New("registry release admission unavailable")
		}
		if admitted == nil {
			return nil, errors.New("private OCI registry release admission is unavailable")
		}
		approved := *admitted
		admitted = &approved
		if admitted.VerifyCurrent == nil || node == nil || node.ID == "" || task.NodeID != node.ID || admitted.ServiceID != task.ServiceID ||
			admitted.Environment == "" || admitted.Region == "" ||
			node.Spec.Annotations.Labels[LabelRegion] != admitted.Region ||
			task.ServiceAnnotations.Labels[LabelEnvironment] != admitted.Environment ||
			task.ServiceAnnotations.Labels[LabelRegion] != admitted.Region ||
			task.ServiceAnnotations.Labels[LabelIntentID] != admitted.Scope.TaskPrincipal ||
			spec.Image != admitted.Scope.RegistryHost+"/"+admitted.Scope.Repository+"@"+admitted.Scope.Digest {
			return nil, errors.New("registry release does not match current task and admitted node")
		}
		if admitted.Deadline.IsZero() || !time.Now().Before(admitted.Deadline) {
			return nil, errors.New("registry release admission expired")
		}
		ctx, cancel := context.WithDeadline(ctx, admitted.Deadline)
		defer cancel()
		if err := admitted.VerifyCurrent(ctx); err != nil {
			return nil, err
		}
		ctx = ociclient.WithRequestGuard(ctx, admitted.VerifyCurrent)
		credentials, err := secrets.Resolve(ctx, admitted.Claim, admitted.Scope, admitted.Secret)
		if err != nil {
			return nil, errors.New("registry Vault credential unavailable")
		}
		if err := admitted.VerifyCurrent(ctx); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return privateRegistryResolver(spec.Image, admitted.Scope.RegistryHost, credentials.ForHost, nil), nil
	}, nil
}

const ghcrHost = "ghcr.io"

// ghcrUser owns the GHCR pull PAT; GHCR accepts any username with a PAT.
const ghcrUser = "MarioGK"

// ghcrBlobHost serves GHCR layer blobs: blob GETs answer 307 to it.
const ghcrBlobHost = "pkg-containers.githubusercontent.com"

// GHCRResolver authenticates ghcr.io pulls with the token read at pull time
// (in memory, once per pull); every other registry stays anonymous.
func GHCRResolver(token func(context.Context) (string, error)) RegistryResolver {
	return ghcrResolver(token, nil)
}

func ghcrResolver(token func(context.Context) (string, error), transport http.RoundTripper) RegistryResolver {
	return func(ctx context.Context, task *api.Task, node *api.Node) (remotes.Resolver, error) {
		spec, err := DecodeContainer(task)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(spec.Image, ghcrHost+"/") {
			return publicRegistryResolver(ctx, task, node)
		}
		read := sync.OnceValues(func() (string, error) { return token(ctx) })
		return privateRegistryResolver(spec.Image, ghcrHost, func(host string) (string, string, error) {
			if host != ghcrHost {
				return "", "", errors.New("GHCR credentials requested for another host")
			}
			value, err := read()
			return ghcrUser, value, err
		}, transport, ghcrBlobHost), nil
	}
}

func publicRegistryResolver(_ context.Context, task *api.Task, _ *api.Node) (remotes.Resolver, error) {
	spec, err := DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	return &boundRegistryResolver{Resolver: docker.NewResolver(docker.ResolverOptions{}), image: spec.Image}, nil
}

// blobHosts are the only hosts a pull may be redirected to (a registry's blob
// CDN); credentials never reach them.
func privateRegistryResolver(image, host string, credentials func(string) (string, string, error), transport http.RoundTripper, blobHosts ...string) remotes.Resolver {
	if transport == nil {
		transport = &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second}
	}
	// No whole-request Timeout: it also bounded the body, so a TerraBase layer
	// that took over 30 s to download failed every pull (gru 2026-10-27).
	// registryTransport cancels a request only once it stalls.
	client := &http.Client{Transport: registryTransport{host: host, blobHosts: blobHosts, base: transport},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > 3 || !slices.Contains(blobHosts, request.URL.Host) {
				return http.ErrUseLastResponse
			}
			return nil
		}}
	authorizer := docker.NewDockerAuthorizer(docker.WithAuthClient(client), docker.WithAuthCreds(credentials))
	resolver := docker.NewResolver(docker.ResolverOptions{Hosts: func(requested string) ([]docker.RegistryHost, error) {
		if requested != host {
			return nil, errors.New("registry host differs from admitted image")
		}
		return []docker.RegistryHost{{Client: client, Authorizer: authorizer, Host: host, Scheme: "https", Path: "/v2",
			Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve}}, nil
	}})
	return &boundRegistryResolver{Resolver: resolver, image: image}
}

type registryTransport struct {
	host      string
	blobHosts []string
	base      http.RoundTripper
	stall     time.Duration // registryStall when zero; tests shorten it
}

func (t registryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	blob := slices.Contains(t.blobHosts, request.URL.Host)
	if request.URL.Scheme != "https" || request.URL.Host != t.host && !blob || request.URL.User != nil {
		return nil, errors.New("registry authentication endpoint differs from admitted host")
	}
	if blob && request.Header.Get("Authorization") != "" {
		return nil, errors.New("registry credentials must not reach the blob host")
	}
	limit := cmp.Or(t.stall, registryStall)
	ctx, cancel := context.WithCancel(request.Context())
	stall := time.AfterFunc(limit, cancel)
	response, err := t.base.RoundTrip(request.WithContext(ctx))
	if err != nil {
		stall.Stop()
		cancel()
		return nil, err
	}
	response.Body = &stallBody{ReadCloser: response.Body, stall: stall, limit: limit, cancel: cancel}
	return response, nil
}

// registryStall cancels a registry request that receives no response or no
// body bytes for this long.
const registryStall = 30 * time.Second

// stallBody restarts the stall timer on every read that makes progress.
type stallBody struct {
	io.ReadCloser
	stall  *time.Timer
	limit  time.Duration
	cancel context.CancelFunc
}

func (b *stallBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.stall.Reset(b.limit)
	}
	return n, err
}

func (b *stallBody) Close() error {
	b.stall.Stop()
	b.cancel()
	return b.ReadCloser.Close()
}

type boundRegistryResolver struct {
	remotes.Resolver
	image string
}

func (r *boundRegistryResolver) Resolve(ctx context.Context, image string) (string, imagespec.Descriptor, error) {
	if image != r.image {
		return "", imagespec.Descriptor{}, errors.New("registry image differs from admitted digest")
	}
	return r.Resolver.Resolve(ctx, image)
}

func (r *boundRegistryResolver) Fetcher(ctx context.Context, image string) (remotes.Fetcher, error) {
	if image != r.image {
		return nil, errors.New("registry image differs from admitted digest")
	}
	return r.Resolver.Fetcher(ctx, image)
}

func (*boundRegistryResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("task registry credentials permit pulls only")
}
