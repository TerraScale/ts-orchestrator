package apppull

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type Target = appregistry.Target

type Selection struct {
	Image  string
	Claims releasepush.Claims
}

var Targets = appregistry.Targets

var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Source struct {
	Root      root.TrustedMaterial
	Transport http.RoundTripper
	Registry  func(context.Context) (*appregistry.Client, error)
}

type release struct {
	ref       name.Tag
	keychain  authn.Keychain
	transport http.RoundTripper
}

func (s Source) release(ctx context.Context, target Target) (release, error) {
	if s.Registry == nil {
		return release{}, fmt.Errorf("app release registry is unavailable")
	}
	registry, err := s.Registry(ctx)
	if err != nil {
		return release{}, err
	}
	repository, err := registry.Repository(target.Package)
	if err != nil {
		return release{}, err
	}
	keychain, err := registry.Keychain(ctx, target.Package)
	if err != nil {
		return release{}, err
	}
	ref, err := name.NewTag(repository+":release", name.StrictValidation)
	if err != nil {
		return release{}, err
	}
	return release{ref: ref, keychain: keychain, transport: registry.BoundTransport(s.Transport)}, nil
}

func (s Source) Digest(ctx context.Context, target Target) (string, error) {
	selected, err := s.release(ctx, target)
	if err != nil {
		return "", err
	}
	head, err := remote.Head(selected.ref, remote.WithContext(ctx), remote.WithTransport(selected.transport), remote.WithAuthFromKeychain(selected.keychain))
	if err != nil {
		return "", err
	}
	return head.Digest.String(), nil
}

func (s Source) Pull(ctx context.Context, target Target) (Selection, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	selected, err := s.release(ctx, target)
	if err != nil {
		return Selection{}, err
	}
	ref, keychain, transport := selected.ref, selected.keychain, selected.transport
	trusted := s.Root
	if trusted == nil {
		trusted, err = imagetrust.PublicGoodRoot()
		if err != nil {
			return Selection{}, err
		}
	}
	image, err := remote.Image(ref, remote.WithContext(ctx), remote.WithTransport(transport), remote.WithAuthFromKeychain(keychain), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	if err != nil {
		return Selection{}, err
	}
	digest, err := image.Digest()
	if err != nil {
		return Selection{}, err
	}
	config, err := image.ConfigFile()
	if err != nil {
		return Selection{}, err
	}
	sha := config.Config.Labels["org.opencontainers.image.revision"]
	if config.OS != "linux" || config.Architecture != runtime.GOARCH || !revision.MatchString(sha) {
		return Selection{}, fmt.Errorf("%s: release must select a native Linux image with a full revision", target.Service)
	}
	pinned := ref.Context().Digest(digest.String()).Name()
	provenance, err := (imagetrust.Verifier{Root: trusted, Transport: transport}).Selection(ctx, pinned, target.Workflow, sha, target.Service, keychain)
	if err != nil {
		return Selection{}, err
	}
	return Selection{Image: target.Package + "@" + digest.String(), Claims: releasepush.Claims{Repository: provenance.Repository, SHA: sha, RunID: provenance.RunID, RunAttempt: provenance.RunAttempt, JobWorkflowRef: provenance.Workflow}}, nil
}
