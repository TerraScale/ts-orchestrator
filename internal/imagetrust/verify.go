package imagetrust

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

func Verify(ctx context.Context, image, workflowRef, revision string, keychain authn.Keychain) error {
	digest, err := name.NewDigest(image, name.StrictValidation)
	if err != nil {
		return fmt.Errorf("image %s refused: not a digest reference", image)
	}
	bundles, err := fetchBundles(ctx, digest, keychain)
	if err != nil {
		return fmt.Errorf("image %s refused: attestation lookup failed: %w", image, err)
	}
	identity, err := verify.NewShortCertificateIdentity(actionsIssuer, "", "https://github.com/"+workflowRef, "")
	if err != nil {
		return err
	}
	trustedRoot, err := root.NewTrustedRootFromJSON([]byte(trustedRootJSON))
	if err != nil {
		return fmt.Errorf("image %s refused: attestation lookup failed: %w", image, err)
	}
	verifier, err := verify.NewVerifier(trustedRoot, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return err
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digestBytes(digest)), verify.WithCertificateIdentity(identity))
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
		return nil
	}
	return fmt.Errorf("image %s refused: no provenance attestation signed by https://github.com/%s for commit %s", image, workflowRef, revision)
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

func fetchBundles(ctx context.Context, digest name.Digest, keychain authn.Keychain) ([][]byte, error) {
	referrers, err := remote.Referrers(digest, remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain))
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
		data, err := fetchBundle(ctx, digest.Context().Digest(descriptor.Digest.String()), keychain)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, data)
	}
	return bundles, nil
}

func fetchBundle(ctx context.Context, manifest name.Digest, keychain authn.Keychain) ([]byte, error) {
	fetched, err := remote.Get(manifest, remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain))
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
	layer, err := remote.Layer(manifest.Context().Digest(index.Layers[0].Digest.String()), remote.WithContext(ctx), remote.WithAuthFromKeychain(keychain))
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
