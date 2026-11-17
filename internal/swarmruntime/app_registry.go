package swarmruntime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/swarmkit/v2/api"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
)

func AppRegistryResolver(region string, oldToken func(context.Context) (string, error)) RegistryResolver {
	old := GHCRResolver(oldToken)
	return func(ctx context.Context, task *api.Task, node *api.Node) (remotes.Resolver, error) {
		spec, err := DecodeContainer(task)
		if err != nil {
			return nil, err
		}
		if !appregistry.IsImage(spec.Image) {
			return old(ctx, task, node)
		}
		deployment, floor, err := serviceDeployment(task.ServiceAnnotations.Labels[LabelServiceSpec], task.ServiceAnnotations.Labels)
		if err != nil {
			return nil, err
		}
		if deployment == nil || floor == nil || deployment.Image != spec.Image {
			return nil, errors.New("regional app image requires its signed deployment")
		}
		return appImageResolver(func(ctx context.Context) (*appregistry.Client, error) { return appregistry.Regional(ctx, region) }, *deployment, imagetrust.Verifier{})
	}
}

func AppImageResolver(registry *appregistry.Client, deployment Deployment, verifier imagetrust.Verifier) (remotes.Resolver, error) {
	return appImageResolver(func(context.Context) (*appregistry.Client, error) { return registry, nil }, deployment, verifier)
}

func appImageResolver(registry func(context.Context) (*appregistry.Client, error), deployment Deployment, verifier imagetrust.Verifier) (remotes.Resolver, error) {
	if err := deployment.Validate(); err != nil {
		return nil, err
	}
	for _, target := range appregistry.Targets {
		if target.Package == appregistry.Package(deployment.Image) && deployment.Workflow == target.Workflow {
			return &regionalResolver{registry: registry, deployment: deployment, target: target, verifier: verifier}, nil
		}
	}
	return nil, errors.New("regional app image workflow differs from its producer")
}

type regionalResolver struct {
	registry   func(context.Context) (*appregistry.Client, error)
	deployment Deployment
	target     appregistry.Target
	verifier   imagetrust.Verifier
}

func (r *regionalResolver) resolver(ctx context.Context, image string) (remotes.Resolver, string, *appregistry.Client, error) {
	if image != r.deployment.Image {
		return nil, "", nil, errors.New("regional registry image differs from admitted digest")
	}
	registry, err := r.registry(ctx)
	if err != nil {
		return nil, "", nil, err
	}
	physical, err := registry.Image(image)
	if err != nil {
		return nil, "", nil, err
	}
	transport := registry.Transport
	if transport == nil {
		transport = remote.DefaultTransport
	}
	client := &http.Client{Transport: registryTransport{host: registry.Host, base: transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorizer := appAuthorizer{registry: registry, image: image}
	resolver := docker.NewResolver(docker.ResolverOptions{Hosts: func(host string) ([]docker.RegistryHost, error) {
		if host != registry.Host {
			return nil, errors.New("app image resolved outside its region")
		}
		return []docker.RegistryHost{{Client: client, Authorizer: authorizer, Host: host, Scheme: "https", Path: "/v2", Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve}}, nil
	}})
	return &boundRegistryResolver{Resolver: resolver, image: physical}, physical, registry, nil
}

func (r *regionalResolver) Resolve(ctx context.Context, image string) (string, imagespec.Descriptor, error) {
	resolver, physical, registry, err := r.resolver(ctx, image)
	if err != nil {
		return "", imagespec.Descriptor{}, err
	}
	repository, _, _ := strings.Cut(image, "@")
	keychain, err := registry.Keychain(ctx, repository)
	if err != nil {
		return "", imagespec.Descriptor{}, err
	}
	verifier := r.verifier
	if verifier.Root == nil {
		verifier.Root, err = imagetrust.PublicGoodRoot()
		if err != nil {
			return "", imagespec.Descriptor{}, err
		}
	}
	if verifier.Transport == nil {
		verifier.Transport = remote.DefaultTransport
	}
	provenance, err := verifier.Selection(ctx, physical, r.target.Workflow, r.deployment.Revision, r.target.Service, keychain)
	if err != nil {
		return "", imagespec.Descriptor{}, err
	}
	if provenance.Repository != r.deployment.Repository || provenance.RunID != r.deployment.RunID || provenance.RunAttempt != fmt.Sprint(r.deployment.RunAttempt) {
		return "", imagespec.Descriptor{}, errors.New("app provenance differs from signed deployment")
	}
	_, descriptor, err := resolver.Resolve(ctx, physical)
	return image, descriptor, err
}

func (r *regionalResolver) Fetcher(ctx context.Context, image string) (remotes.Fetcher, error) {
	resolver, physical, _, err := r.resolver(ctx, image)
	if err != nil {
		return nil, err
	}
	return resolver.Fetcher(ctx, physical)
}

func (*regionalResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("app instance-principal credentials permit pulls only")
}

type appAuthorizer struct {
	registry *appregistry.Client
	image    string
}

func (a appAuthorizer) Authorize(ctx context.Context, request *http.Request) error {
	if request.URL.Scheme != "https" || request.URL.Host != a.registry.Host {
		return errors.New("OCIR token requested for another registry")
	}
	token, err := a.registry.Token(ctx, a.image)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (appAuthorizer) AddResponses(context.Context, []*http.Response) error {
	return errors.New("OCIR refused the instance-principal pull token")
}
