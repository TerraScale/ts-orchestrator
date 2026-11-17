package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	digest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type registryTransport struct{ base *url.URL }

func (t registryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	require(request.URL.Host == "ghcr.io", "registry client escaped its origin")
	request = request.Clone(request.Context())
	endpoint := *request.URL
	endpoint.Scheme, endpoint.Host = t.base.Scheme, t.base.Host
	request.URL = &endpoint
	return http.DefaultTransport.RoundTrip(request)
}

func runPulled(ctx context.Context, state, image, run string) {
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
	identity := sigstore.Identity{Workflow: apppull.Targets[0].Workflow, Ref: "refs/heads/main", Trigger: "push"}
	wrong := identity
	wrong.Workflow = "TerraScale/terrascale/.github/workflows/untrusted.yml@refs/heads/main"
	bundle := authority.Bundle(wrong, revision, run, map[string][]byte{"ghcr.io/terrascale/terrabase": manifest})
	serve := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v2/terrascale/terrabase/") {
			http.NotFound(w, r)
			return
		}
		bundleDigest := digest.FromBytes(bundle)
		attachment, _ := json.Marshal(imagespec.Manifest{Versioned: decoded.Versioned, MediaType: imagespec.MediaTypeImageManifest, ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Config: imagespec.Descriptor{MediaType: imagespec.MediaTypeEmptyJSON, Digest: digest.FromString("{}"), Size: 2}, Layers: []imagespec.Descriptor{{MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", Digest: bundleDigest, Size: int64(len(bundle))}}})
		attachmentDigest := digest.FromBytes(attachment)
		switch {
		case strings.Contains(r.URL.Path, "/referrers/"):
			w.Header().Set("Content-Type", imagespec.MediaTypeImageIndex)
			_ = json.NewEncoder(w).Encode(imagespec.Index{Versioned: decoded.Versioned, MediaType: imagespec.MediaTypeImageIndex, Manifests: []imagespec.Descriptor{{MediaType: imagespec.MediaTypeImageManifest, ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Digest: attachmentDigest, Size: int64(len(attachment))}}})
		case strings.HasSuffix(r.URL.Path, "/manifests/"+attachmentDigest.String()):
			w.Header().Set("Content-Type", imagespec.MediaTypeImageManifest)
			_, _ = w.Write(attachment)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+bundleDigest.String()):
			_, _ = w.Write(bundle)
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
	source := apppull.Source{Token: func(context.Context) (string, error) { return "registry-journey", nil }, Root: trusted, Transport: registryTransport{endpoint}}
	_, err = source.Pull(ctx, apppull.Targets[0])
	require(err != nil, "host accepted image provenance from an untrusted workflow")
	bundle = authority.Bundle(identity, revision, run, map[string][]byte{"ghcr.io/terrascale/terrabase": manifest})
	selected, err := source.Pull(ctx, apppull.Targets[0])
	must(err)
	require(selected.Image == image && selected.Claims.RunID == run && selected.Claims.Repository == "TerraScale/terrascale", "host changed the verified release identity")
	err = (apppull.Updater{Source: source, Apply: mesh.Release(state)}).Cycle(ctx)
	if ctx.Err() == nil {
		must(err)
	}
}
