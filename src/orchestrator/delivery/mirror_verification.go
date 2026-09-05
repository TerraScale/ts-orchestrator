package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// RegionObjectStoreContentReader opens the complete immutable object. Mirror
// verification hashes its actual bytes; user supplied metadata is insufficient.
type RegionObjectStoreContentReader interface {
	Get(context.Context, string, string, string) (io.ReadCloser, ObjectIdentity, error)
}

// MirrorMode separates master artifact preparation from regional execution.
// Every executor must select a mode explicitly.
type MirrorMode string

const (
	MirrorModePrepareAll MirrorMode = "prepare-all"
	MirrorModeVerifyAll  MirrorMode = "verify-all"
)

// VerifyAllFenced observes the artifacts prepared by the global master. It
// requires the exact digest and size in every declared region and never puts
// objects. A missing or unreadable mirror prevents regional rollout.
func (m *ArtifactMirror) VerifyAllFenced(ctx context.Context, artifact *ReleaseArtifact, fence OperationFence, check FenceChecker) error {
	if m == nil || m.Store == nil || check == nil {
		return errors.New("delivery: mirror verification and operation fence are required")
	}
	if _, ok := m.Store.(RegionObjectStoreContentReader); !ok {
		return errors.New("delivery: mirror content reader is required")
	}
	return m.mirrorAll(ctx, artifact, fence, check, true)
}

func (m *ArtifactMirror) verifyRegion(ctx context.Context, region, bucket, object string, artifact *ReleaseArtifact, fence OperationFence, check FenceChecker) *MirrorError {
	expected := ObjectIdentity{Digest: artifact.Digest, Size: int64(len(artifact.Body))}
	failed := func(kind MirrorFailureKind, observed ObjectIdentity, err error) *MirrorError {
		return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: kind, Retryable: true, Expected: expected, Observed: observed, Remediation: "Complete global artifact preparation before retrying regional delivery.", Err: err}
	}
	if err := ctx.Err(); err != nil {
		return failed(MirrorFailureCanceled, ObjectIdentity{}, err)
	}
	if err := check(fence); err != nil {
		return failed(MirrorFailureCanceled, ObjectIdentity{}, err)
	}
	reader, identity, err := m.Store.(RegionObjectStoreContentReader).Get(ctx, region, bucket, object)
	if err != nil {
		return failed(MirrorFailureRead, identity, err)
	}
	if reader == nil {
		return failed(MirrorFailureRead, identity, errors.New("prepared artifact reader is missing"))
	}
	closed := false
	defer func() {
		if !closed {
			_ = reader.Close()
		}
	}()
	if !identityMatches(identity, expected) {
		return failed(MirrorFailureMismatch, identity, errors.New("prepared artifact identity is missing or mismatched"))
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(reader, expected.Size+1))
	if err != nil {
		return failed(MirrorFailureRead, identity, err)
	}
	if size != expected.Size || !SameDigest("sha256:"+hex.EncodeToString(hash.Sum(nil)), expected.Digest) {
		return failed(MirrorFailureMismatch, identity, errors.New("prepared artifact bytes differ from signed digest or size"))
	}
	closeErr := reader.Close()
	closed = true
	if err := closeErr; err != nil {
		return failed(MirrorFailureRead, identity, err)
	}
	return nil
}
