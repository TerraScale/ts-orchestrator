package swarmruntime

import (
	"context"
	"errors"
	"net/http"
	"strings"
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
}

// NewOCIRegistryResolver reads admitted private credentials automatically for
// each pull. lookup verifies signed release admission and credential ownership;
// nil admission permits only an anonymous pull, which cannot read Vault.
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
			if host, _, _ := strings.Cut(spec.Image, "/"); strings.HasSuffix(host, ".ocir.io") {
				return nil, errors.New("private OCI registry release admission is unavailable")
			}
			return publicRegistryResolver(ctx, task, node)
		}
		if node == nil || node.ID == "" || task.NodeID != node.ID || admitted.ServiceID != task.ServiceID ||
			admitted.Environment == "" || admitted.Region == "" ||
			node.Spec.Annotations.Labels[LabelRegion] != admitted.Region ||
			task.ServiceAnnotations.Labels[LabelEnvironment] != admitted.Environment ||
			task.ServiceAnnotations.Labels[LabelRegion] != admitted.Region ||
			task.ServiceAnnotations.Labels[LabelIntentID] != admitted.Scope.TaskPrincipal ||
			spec.Image != admitted.Scope.RegistryHost+"/"+admitted.Scope.Repository+"@"+admitted.Scope.Digest {
			return nil, errors.New("registry release does not match current task and admitted node")
		}
		credentials, err := secrets.Resolve(ctx, admitted.Claim, admitted.Scope, admitted.Secret)
		if err != nil {
			return nil, errors.New("registry Vault credential unavailable")
		}
		return privateRegistryResolver(spec.Image, admitted.Scope.RegistryHost, credentials.ForHost, nil), nil
	}, nil
}

func publicRegistryResolver(_ context.Context, task *api.Task, _ *api.Node) (remotes.Resolver, error) {
	spec, err := DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	return &boundRegistryResolver{Resolver: docker.NewResolver(docker.ResolverOptions{}), image: spec.Image}, nil
}

func privateRegistryResolver(image, host string, credentials func(string) (string, string, error), transport http.RoundTripper) remotes.Resolver {
	if transport == nil {
		transport = &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second}
	}
	client := &http.Client{Transport: registryTransport{host: host, base: transport}, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
	host string
	base http.RoundTripper
}

func (t registryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != t.host || request.URL.User != nil {
		return nil, errors.New("registry authentication endpoint differs from admitted host")
	}
	return t.base.RoundTrip(request)
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
