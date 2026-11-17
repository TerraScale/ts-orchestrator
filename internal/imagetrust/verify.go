package imagetrust

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	bundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const bundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

const provenancePredicateType = "https://slsa.dev/provenance/v1"

const actionsIssuer = "https://token.actions.githubusercontent.com"

const mainRef = "refs/heads/main"

const bundleLimit = 4 << 20

type Provenance struct {
	Repository string
	Revision   string
	Workflow   string
	RunID      string
	RunAttempt string
}

var invocation = regexp.MustCompile(`^https://github.com/(TerraScale/[^/]+)/actions/runs/([0-9]{1,20})/attempts/([0-9]+)$`)

func Verify(ctx context.Context, image, workflowRef, revision string, keychain authn.Keychain) error {
	_, err := Inspect(ctx, image, workflowRef, revision, keychain)
	return err
}

type Verifier struct {
	Root      root.TrustedMaterial
	Transport http.RoundTripper
}

func Inspect(ctx context.Context, image, workflowRef, revision string, keychain authn.Keychain) (Provenance, error) {
	trusted, err := PublicGoodRoot()
	if err != nil {
		return Provenance{}, err
	}
	return (Verifier{Root: trusted, Transport: remote.DefaultTransport}).Inspect(ctx, image, workflowRef, revision, keychain)
}

func (v Verifier) Inspect(ctx context.Context, image, workflowRef, revision string, keychain authn.Keychain) (Provenance, error) {
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return Provenance{}, fmt.Errorf("image %s refused: not a digest reference", image)
	}
	bundles, err := fetchBundles(ctx, digest, keychain, v.Transport)
	if err != nil {
		return Provenance{}, fmt.Errorf("image %s refused: attestation lookup failed: %w", image, err)
	}
	identity, err := verify.NewShortCertificateIdentity(actionsIssuer, "", "https://github.com/"+workflowRef, "")
	if err != nil {
		return Provenance{}, err
	}
	if v.Root == nil {
		return Provenance{}, fmt.Errorf("image verifier has no trusted root")
	}
	verifier, err := verify.NewVerifier(v.Root, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return Provenance{}, err
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digestBytes(digest)), verify.WithCertificateIdentity(identity))
	var newest Provenance
	var newestRun, newestAttempt uint64
	for _, data := range bundles {
		var b bundle.Bundle
		if err := b.UnmarshalJSON(data); err != nil {
			continue
		}
		result, err := verifier.Verify(&b, policy)
		if err != nil {
			continue
		}
		if !validProvenance(result, revision) {
			continue
		}
		cert := result.Signature.Certificate
		run := invocation.FindStringSubmatch(cert.RunInvocationURI)
		if run == nil || cert.SourceRepositoryURI != "https://github.com/"+run[1] || !strings.HasPrefix(workflowRef, run[1]+"/.github/workflows/") {
			continue
		}
		number, err := strconv.ParseUint(run[2], 10, 64)
		if err != nil {
			continue
		}
		attempt, err := strconv.ParseUint(run[3], 10, 64)
		if err != nil || attempt == 0 {
			continue
		}
		if newest.Repository == "" || number > newestRun || number == newestRun && attempt > newestAttempt {
			newest = Provenance{Repository: run[1], Revision: revision, Workflow: workflowRef, RunID: run[2], RunAttempt: run[3]}
			newestRun, newestAttempt = number, attempt
		}
	}
	if newest.Repository != "" {
		return newest, nil
	}
	return Provenance{}, fmt.Errorf("image %s refused: no provenance attestation signed by https://github.com/%s for commit %s", image, workflowRef, revision)
}

func PublicGoodRoot() (*root.TrustedRoot, error) {
	return root.NewTrustedRootFromJSON([]byte(trustedRootJSON))
}

func digestBytes(digest name.Digest) []byte {
	value, err := hex.DecodeString(strings.TrimPrefix(digest.DigestStr(), "sha256:"))
	if err != nil {
		return nil
	}
	return value
}

func validProvenance(result *verify.VerificationResult, revision string) bool {
	if result.VerifiedIdentity == nil || result.Statement == nil || result.Statement.PredicateType != provenancePredicateType {
		return false
	}
	signature := result.Signature
	if signature == nil || signature.Certificate == nil {
		return false
	}
	return signature.Certificate.SourceRepositoryDigest == revision && signature.Certificate.SourceRepositoryRef == mainRef
}

func fetchBundles(ctx context.Context, digest name.Digest, keychain authn.Keychain, transport http.RoundTripper) ([][]byte, error) {
	referrers, err := remote.Referrers(digest, remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain), remote.WithTransport(transport))
	if err != nil {
		return nil, err
	}
	manifests, err := referrers.IndexManifest()
	if err != nil {
		return nil, err
	}
	var bundles [][]byte
	for _, descriptor := range manifests.Manifests {
		if descriptor.ArtifactType != bundleArtifactType {
			continue
		}
		data, err := fetchBundle(ctx, digest.Context().Digest(descriptor.Digest.String()), keychain, transport)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, data)
	}
	return bundles, nil
}

func fetchBundle(ctx context.Context, manifest name.Digest, keychain authn.Keychain, transport http.RoundTripper) ([]byte, error) {
	fetched, err := remote.Get(manifest, remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain), remote.WithTransport(transport))
	if err != nil {
		return nil, err
	}
	var index v1.Manifest
	if err := json.Unmarshal(fetched.Manifest, &index); err != nil {
		return nil, err
	}
	if len(index.Layers) != 1 {
		return nil, fmt.Errorf("bundle manifest %s: expected one layer", manifest)
	}
	layer, err := remote.Layer(manifest.Context().Digest(index.Layers[0].Digest.String()), remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain), remote.WithTransport(transport))
	if err != nil {
		return nil, err
	}
	blob, err := layer.Compressed()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(blob, bundleLimit+1))
	closeErr := blob.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > bundleLimit {
		return nil, fmt.Errorf("bundle layer %s: too large", index.Layers[0].Digest)
	}
	return data, nil
}
