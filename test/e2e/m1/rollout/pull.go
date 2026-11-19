package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	digest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type registryTransport struct{ base *url.URL }

const pullRegistry = "sa-saopaulo-1.ocir.io"

func (t registryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	require(request.URL.Host == pullRegistry && request.URL.Scheme == "https", "registry client escaped its origin")
	original := request
	request = request.Clone(request.Context())
	endpoint := *request.URL
	endpoint.Scheme, endpoint.Host = t.base.Scheme, t.base.Host
	request.URL = &endpoint
	response, err := http.DefaultTransport.RoundTrip(request)
	if response != nil {
		response.Request = original
	}
	return response, err
}

func runPulled(ctx context.Context, state, image, run, service string) error {
	target := apppull.Targets[slices.IndexFunc(apppull.Targets, func(target apppull.Target) bool { return target.Service == service })]
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	client, err := containerd.New(filepath.Join(state, "run", "containerd.sock"))
	must(err)
	defer client.Close()
	cached, err := client.ImageService().Get(ctx, image)
	must(err)
	manifest, err := content.ReadBlob(ctx, client.ContentStore(), cached.Target)
	must(err)
	var decoded imagespec.Manifest
	must(json.Unmarshal(manifest, &decoded))
	config, err := content.ReadBlob(ctx, client.ContentStore(), decoded.Config)
	must(err)
	authority := sigstore.New()
	trusted, err := root.NewTrustedRootFromJSON(authority.TrustedRoot())
	must(err)
	identity := sigstore.Identity{Workflow: target.Workflow, Ref: "refs/heads/main", Trigger: "push"}
	subjects := map[string][]byte{pullRegistry + "/journey/terrascale/" + target.Package: manifest}
	provenance := authority.Bundle(identity, revision, "1", subjects)
	bundles := [][]byte{provenance}
	serve := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/20180419/docker/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "journey", "expires_in": 300})
			return
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v2/journey/terrascale/"+target.Package+"/") {
			http.NotFound(w, r)
			return
		}
		index := imagespec.Index{Versioned: decoded.Versioned, MediaType: imagespec.MediaTypeImageIndex}
		files := map[string][]byte{}
		for _, bundle := range bundles {
			bundleDigest := digest.FromBytes(bundle)
			attachment, _ := json.Marshal(imagespec.Manifest{Versioned: decoded.Versioned, MediaType: imagespec.MediaTypeImageManifest, ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Config: imagespec.Descriptor{MediaType: imagespec.MediaTypeEmptyJSON, Digest: digest.FromString("{}"), Size: 2}, Layers: []imagespec.Descriptor{{MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", Digest: bundleDigest, Size: int64(len(bundle))}}})
			attachmentDigest := digest.FromBytes(attachment)
			index.Manifests = append(index.Manifests, imagespec.Descriptor{MediaType: imagespec.MediaTypeImageManifest, ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Digest: attachmentDigest, Size: int64(len(attachment))})
			files["/v2/journey/terrascale/"+target.Package+"/manifests/"+attachmentDigest.String()] = attachment
			files["/v2/journey/terrascale/"+target.Package+"/blobs/"+bundleDigest.String()] = bundle
		}
		if data, exists := files[r.URL.Path]; exists {
			w.Header().Set("Content-Type", imagespec.MediaTypeImageManifest)
			_, _ = w.Write(data)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/referrers/"):
			w.Header().Set("Content-Type", imagespec.MediaTypeImageIndex)
			_ = json.NewEncoder(w).Encode(index)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+decoded.Config.Digest.String()):
			_, _ = w.Write(config)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", imagespec.MediaTypeImageManifest)
			w.Header().Set("Docker-Content-Digest", cached.Target.Digest.String())
			_, _ = w.Write(manifest)
		default:
			http.NotFound(w, r)
		}
	}
	registry := httptest.NewServer(http.HandlerFunc(serve))
	defer registry.Close()
	endpoint, err := url.Parse(registry.URL)
	must(err)
	registryClient := &appregistry.Client{Host: pullRegistry, Namespace: "journey", Prefix: "terrascale", Transport: registryTransport{endpoint}, Sign: func(*http.Request) error { return nil }}
	source := apppull.Source{Registry: func(context.Context) (*appregistry.Client, error) { return registryClient, nil }, Root: trusted, Transport: registryTransport{endpoint}}
	_, err = source.Pull(ctx, target)
	require(err != nil, "a mutable tag selected a built image without release authorization")
	selector := identity
	selector.Trigger = "workflow_dispatch"
	wrong := selector
	wrong.Workflow = "TerraScale/terrascale/.github/workflows/untrusted.yml@refs/heads/main"
	bundles = [][]byte{provenance, authority.Selection(wrong, revision, run, service, subjects)}
	_, err = source.Pull(ctx, target)
	require(err != nil, "host accepted a selection signed by an untrusted workflow")
	wrong = selector
	wrong.Trigger = "pull_request"
	bundles = [][]byte{provenance, authority.Selection(wrong, revision, run, service, subjects)}
	_, err = source.Pull(ctx, target)
	require(err != nil, "host accepted a PR-triggered release selection")
	if service == "terrabase" {
		wrong.Trigger = "push"
		bundles = [][]byte{provenance, authority.Selection(wrong, revision, run, service, subjects)}
		_, err = source.Pull(ctx, target)
		require(err != nil, "TerraBase released without a manual dispatch")
	}
	bundles = [][]byte{provenance, authority.Selection(selector, revision, run, "app-canary", subjects)}
	_, err = source.Pull(ctx, target)
	require(err != nil, "host accepted a selection for another service")
	bundles = [][]byte{provenance, authority.Selection(selector, revision, run, service, subjects)}
	selected, err := source.Pull(ctx, target)
	must(err)
	require(selected.Image == strings.TrimPrefix(image, "ghcr.io/terrascale/") && selected.Claims.RunID == run && selected.Claims.Repository == "TerraScale/terrascale", "host changed the verified release identity")
	var applied error
	apply := mesh.Release(state)
	err = (apppull.Updater{Source: source, Events: apppull.NewEvents("stg", nil), Apply: func(ctx context.Context, service, image string, claims releasepush.Claims, progress releasepush.Progress) (json.RawMessage, error) {
		data, failure := apply(ctx, service, image, claims, progress)
		if service == target.Service {
			applied = failure
		}
		return data, failure
	}}).Cycle(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(err, applied)
}
