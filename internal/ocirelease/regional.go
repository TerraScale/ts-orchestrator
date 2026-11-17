package ocirelease

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/google/go-containerregistry/pkg/name"
)

type Regional struct {
	Discover func(context.Context) (Registry, error)
	Next     http.RoundTripper

	mu    sync.Mutex
	found *Registry
}

func NewRegional() *Regional {
	return &Regional{Next: http.DefaultTransport, Discover: func(context.Context) (Registry, error) {
		return Registry{}, errors.New("this host has not joined a region")
	}}
}

func (r *Regional) Registry(ctx context.Context) (Registry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.found != nil {
		return *r.found, nil
	}
	registry, err := r.Discover(ctx)
	if err != nil {
		return Registry{}, fmt.Errorf("regional release channel: %w", err)
	}
	r.found = &registry
	return registry, nil
}

func (r *Regional) RoundTrip(request *http.Request) (*http.Response, error) {
	r.mu.Lock()
	found := r.found
	r.mu.Unlock()
	if found != nil && strings.HasPrefix(request.URL.String(), found.Base+"/") {
		return found.Client.Transport.RoundTrip(request)
	}
	return r.Next.RoundTrip(request)
}

func (r *Regional) In(label string) {
	r.Discover = func(ctx context.Context) (Registry, error) {
		client, err := appregistry.Regional(ctx, label)
		if err != nil {
			return Registry{}, err
		}
		return FromApp(client)
	}
}

func FromApp(client *appregistry.Client) (Registry, error) {
	repository, err := client.Repository(Package)
	if err != nil {
		return Registry{}, err
	}
	host, path, _ := strings.Cut(repository, "/")
	registry, err := name.NewRegistry(host)
	if err != nil {
		return Registry{}, err
	}
	return NewRegistry("https://"+host, path, func(ctx context.Context) (string, error) {
		keychain, err := client.Keychain(ctx, Package)
		if err != nil {
			return "", err
		}
		auth, err := keychain.Resolve(registry)
		if err != nil {
			return "", err
		}
		config, err := auth.Authorization()
		if err != nil {
			return "", err
		}
		return config.RegistryToken, nil
	}, client.BoundTransport(nil))
}
