package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
)

type releaseSignatureContextKey struct{}
type releaseEvidenceContextKey struct{}

// PreparedReleaseEvidence is the authenticated release proof retained by a
// master across preparation and recovery. The raw manifest is intentional:
// recovery must re-verify the exact signed bytes alongside the mirrored binary.
type PreparedReleaseEvidence struct {
	Signature         []byte
	Manifest          []byte
	ManifestSignature []byte
	SignatureKey      string
}

// WithPreparedReleaseSignature binds the detached signature authenticated by
// the global master's signed delegation. Callers must verify that delegation.
func WithPreparedReleaseSignature(ctx context.Context, signature []byte) context.Context {
	return context.WithValue(ctx, releaseSignatureContextKey{}, append([]byte(nil), signature...))
}

func WithPreparedReleaseEvidence(ctx context.Context, evidence PreparedReleaseEvidence) context.Context {
	evidence.Signature = bytes.Clone(evidence.Signature)
	evidence.Manifest = bytes.Clone(evidence.Manifest)
	evidence.ManifestSignature = bytes.Clone(evidence.ManifestSignature)
	return context.WithValue(ctx, releaseEvidenceContextKey{}, evidence)
}

type releasePair struct{ body, signature []byte }

func (p releasePair) Fetch(context.Context, *Request) ([]byte, []byte, error) {
	return p.body, p.signature, nil
}

type preparedMirrorFetcher struct{ mirror *ArtifactMirror }

func (f preparedMirrorFetcher) Fetch(ctx context.Context, request *Request) ([]byte, []byte, error) {
	if ctx == nil || f.mirror == nil || request == nil || request.Target == nil || request.Artifact == nil {
		return nil, nil, errors.New("delivery: complete prepared mirror identity is required")
	}
	evidence, hasEvidence := ctx.Value(releaseEvidenceContextKey{}).(PreparedReleaseEvidence)
	signature := evidence.Signature
	if !hasEvidence {
		signature, _ = ctx.Value(releaseSignatureContextKey{}).([]byte)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, errors.New("delivery: signed prepared release signature is required")
	}
	reader, ok := f.mirror.Store.(RegionObjectStoreContentReader)
	if !ok || len(f.mirror.Spec.Regions) == 0 {
		return nil, nil, errors.New("delivery: prepared mirror reader is required")
	}
	for _, region := range f.mirror.Spec.Regions {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		bucket, err := ReleaseBucket(region)
		if err != nil {
			continue
		}
		stream, identity, err := reader.Get(ctx, region.Code, bucket, MirrorObject(request.Target.Service, request.Artifact.Digest))
		if err != nil {
			continue
		}
		if stream == nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(stream, MaxArtifactBytes+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || len(body) == 0 || int64(len(body)) > MaxArtifactBytes || !SameDigest(SHA256Digest(body), request.Artifact.Digest) || !identityMatches(identity, ObjectIdentity{Digest: request.Artifact.Digest, Size: int64(len(body))}) {
			continue
		}
		return body, append([]byte(nil), signature...), nil
	}
	return nil, nil, errors.New("delivery: no verified prepared mirror is available")
}

type preparedManifestMirrorFetcher struct{ preparedMirrorFetcher }

func (f preparedManifestMirrorFetcher) FetchRelease(ctx context.Context, request *Request) ([]byte, []byte, []byte, []byte, error) {
	evidence, ok := ctx.Value(releaseEvidenceContextKey{}).(PreparedReleaseEvidence)
	if !ok || len(evidence.Manifest) == 0 || len(evidence.ManifestSignature) != ed25519.SignatureSize {
		return nil, nil, nil, nil, errors.New("delivery: authenticated prepared release manifest is required")
	}
	body, signature, err := f.preparedMirrorFetcher.Fetch(ctx, request)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return body, signature, bytes.Clone(evidence.Manifest), bytes.Clone(evidence.ManifestSignature), nil
}

// LoadMasterRelease verifies a release before the caller durably saves its
// detached signature. Existing signatures prefer mirrors and cannot change.
func LoadMasterRelease(ctx context.Context, request *Request, fetcher ArtifactFetcher, trust *TrustSet, mirror *ArtifactMirror, signature []byte, prepared bool) (*ReleaseArtifact, error) {
	return LoadMasterReleaseEvidence(ctx, request, fetcher, trust, mirror, PreparedReleaseEvidence{Signature: signature}, prepared)
}

// LoadMasterReleaseEvidence is the master-only admission path. A new master
// release must provide manifest-capable fetching; prepared recovery uses the
// durable authenticated evidence and the mirrored binary.
func LoadMasterReleaseEvidence(ctx context.Context, request *Request, fetcher ArtifactFetcher, trust *TrustSet, mirror *ArtifactMirror, evidence PreparedReleaseEvidence, prepared bool) (*ReleaseArtifact, error) {
	if ctx == nil || fetcher == nil || trust == nil || mirror == nil {
		return nil, errors.New("delivery: complete master release inputs are required")
	}
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	if len(evidence.Signature) != 0 && len(evidence.Signature) != ed25519.SignatureSize {
		return nil, errors.New("delivery: persisted release signature is invalid")
	}
	if len(evidence.Signature) != 0 {
		preparedContext := WithPreparedReleaseEvidence(ctx, evidence)
		artifact, err := verifyArtifact(preparedContext, preparedManifestMirrorFetcher{preparedMirrorFetcher{mirror}}, trust, request)
		if err == nil && evidence.SignatureKey != "" && artifact.SignatureKey != evidence.SignatureKey {
			err = errors.New("delivery: persisted release signature key changed")
		}
		if err == nil || prepared {
			return artifact, err
		}
	}
	if prepared {
		return nil, errors.New("delivery: prepared release has no saved authenticated evidence")
	}
	if _, ok := fetcher.(ManifestArtifactFetcher); !ok {
		return nil, errors.New("delivery: master release fetcher must provide a signed manifest")
	}
	artifact, err := verifyArtifact(ctx, fetcher, trust, request)
	if err != nil {
		return nil, err
	}
	if len(evidence.Signature) != 0 && !bytes.Equal(evidence.Signature, artifact.Signature) {
		return nil, errors.New("delivery: release signature changed after preparation admission")
	}
	return artifact, nil
}

// PrepareMasterRelease performs global preparation only after the caller has
// durably saved the verified signature, then proves every mirror's bytes.
func PrepareMasterRelease(ctx context.Context, artifact *ReleaseArtifact, mirror *ArtifactMirror, prepared bool, fence OperationFence, check FenceChecker) error {
	if check == nil || mirror == nil {
		return errors.New("delivery: master preparation requires mirror and authority fence")
	}
	if err := check(fence); err != nil {
		return err
	}
	if !prepared {
		if err := mirror.MirrorAllFenced(ctx, artifact, fence, check); err != nil {
			return err
		}
	}
	return mirror.VerifyAllFenced(ctx, artifact, fence, check)
}
