package apppull

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type Target struct {
	Service  string
	Package  string
	Workflow string
}

type Selection struct {
	Image  string
	Claims releasepush.Claims
}

var Targets = []Target{
	{"terrabase", "terrabase", "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"},
	{"ts-auth", "ts-auth", "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main"},
	{"ts-dashboard", "terrascale-dashboard", "TerraScale/terrascale/.github/workflows/images-ghcr.yml@refs/heads/main"},
	{"app-canary", "app-canary", "TerraScale/ts-orchestrator/.github/workflows/app-canary.yml@refs/heads/main"},
}

var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Source struct {
	Root      root.TrustedMaterial
	Transport http.RoundTripper
	Token     func(context.Context) (string, error)
}

func (s Source) Pull(ctx context.Context, target Target) (Selection, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	token, err := s.Token(ctx)
	if err != nil {
		return Selection{}, err
	}
	keychain := registryKeychain{authn.FromConfig(authn.AuthConfig{Username: "MarioGK", Password: token})}
	ref, err := name.NewTag("ghcr.io/terrascale/"+target.Package+":release", name.StrictValidation)
	if err != nil {
		return Selection{}, err
	}
	transport := s.Transport
	if transport == nil {
		transport = remote.DefaultTransport
	}
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
	return Selection{Image: pinned, Claims: releasepush.Claims{Repository: provenance.Repository, SHA: sha, RunID: provenance.RunID, RunAttempt: provenance.RunAttempt, JobWorkflowRef: provenance.Workflow}}, nil
}

type registryKeychain struct{ auth authn.Authenticator }

func (k registryKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if resource.RegistryStr() != "ghcr.io" {
		return authn.Anonymous, nil
	}
	return k.auth, nil
}
