package delivery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// ReleaseBucketPurpose names the per-Region bucket release artifacts mirror
// into (D-71). Every declared Region declares exactly one.
const ReleaseBucketPurpose = "release-artifact"

// RegionObjectStore puts one object into one Region's bucket. The wiring
// adapter implements it over the OCI object-storage transport.
type RegionObjectStore interface {
	Put(ctx context.Context, region, bucket, object string, body []byte) error
}

// ObjectIdentity is the read-after-write identity returned by an object
// store. Digest and Size are required for verification. Version, ETag, and
// Metadata are optional because their availability differs between object
// storage providers.
type ObjectIdentity struct {
	Digest   string
	Size     int64
	Version  string
	ETag     string
	Metadata map[string]string
}

// RegionObjectStoreInspector is the optional metadata read contract for a
// RegionObjectStore. A store that implements it gets strict read-after-write
// verification. The bool is false when the object is not present. This shape
// mirrors OCI Object Storage's HeadObject contract without coupling delivery
// to the provider package.
type RegionObjectStoreInspector interface {
	Head(ctx context.Context, region, bucket, object string) (identity ObjectIdentity, found bool, err error)
}

// RegionObjectStoreReader is retained as a descriptive alias for callers that
// think of the operation as a read rather than an inspection.
type RegionObjectStoreReader = RegionObjectStoreInspector

// RegionObjectStoreIdentityWriter is an optional write contract for adapters
// that expose the provider's returned object identity. When present, the
// returned version/ETag/metadata are compared with the subsequent Head result
// as well as the artifact digest and size.
type RegionObjectStoreIdentityWriter interface {
	PutWithIdentity(ctx context.Context, region, bucket, object string, body []byte) (identity ObjectIdentity, err error)
}

// MirrorFailureKind identifies the safe action for a failed Region mirror.
type MirrorFailureKind string

const (
	MirrorFailureWrite         MirrorFailureKind = "write_failed"
	MirrorFailureRead          MirrorFailureKind = "read_failed"
	MirrorFailureIndeterminate MirrorFailureKind = "write_indeterminate"
	MirrorFailureMismatch      MirrorFailureKind = "identity_mismatch"
	MirrorFailureCanceled      MirrorFailureKind = "canceled"
)

// MirrorError is an actionable, typed failure for one Region. It deliberately
// includes the expected and observed identity so an operator can distinguish
// a transient provider outcome from an object that was overwritten or
// corrupted. Never treat an error from this type as permission to roll out.
type MirrorError struct {
	Region      string
	Bucket      string
	Object      string
	Kind        MirrorFailureKind
	Retryable   bool
	Expected    ObjectIdentity
	Observed    ObjectIdentity
	Remediation string
	Err         error
}

func (e *MirrorError) Error() string {
	if e == nil {
		return "delivery: artifact mirror failed"
	}
	message := fmt.Sprintf("delivery: artifact mirror %s in Region %s", e.Kind, e.Region)
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	if e.Remediation != "" {
		message += " (" + e.Remediation + ")"
	}
	return message
}

func (e *MirrorError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ArtifactMirrorError is the long-form name for MirrorError.
type ArtifactMirrorError = MirrorError

// MirrorBatchError reports every Region failure. All Regions are attempted
// before this is returned, so a partial mirror is never mistaken for a safe
// rollout. Failures are sorted by Region for stable logs and tests.
type MirrorBatchError struct {
	Failures []*MirrorError
}

// ArtifactMirrorBatchError is the long-form name for MirrorBatchError.
type ArtifactMirrorBatchError = MirrorBatchError

func (e *MirrorBatchError) Error() string {
	if e == nil || len(e.Failures) == 0 {
		return "delivery: artifact mirror incomplete"
	}
	parts := make([]string, 0, len(e.Failures))
	for _, failure := range e.Failures {
		if failure != nil {
			parts = append(parts, failure.Error())
		}
	}
	return "delivery: artifact mirror incomplete: " + strings.Join(parts, "; ")
}

func (e *MirrorBatchError) Unwrap() []error {
	if e == nil {
		return nil
	}
	errs := make([]error, 0, len(e.Failures))
	for _, failure := range e.Failures {
		if failure != nil {
			errs = append(errs, failure)
		}
	}
	return errs
}

// ArtifactMirror mirrors one verified release artifact into EVERY Region's
// release bucket before the delivery acknowledges (D-71): a Forgejo outage
// may block a new deploy, but a Region-local copy means one can never strand
// a rollout mid-way.
type ArtifactMirror struct {
	// Spec is the declared estate; its Regions define the mirror set.
	Spec estate.Spec
	// Store puts objects; required.
	Store RegionObjectStore
}

// NewArtifactMirror validates the mirror against the declared estate: every
// Region must declare exactly one release-artifact bucket.
func NewArtifactMirror(spec estate.Spec, store RegionObjectStore) (*ArtifactMirror, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("delivery: artifact mirror requires a region object store")
	}
	for _, region := range spec.Regions {
		if bucket, err := ReleaseBucket(region); err != nil {
			return nil, err
		} else if bucket == "" {
			return nil, fmt.Errorf("delivery: region %s declares no %s bucket", region.Code, ReleaseBucketPurpose)
		}
	}
	return &ArtifactMirror{Spec: spec, Store: store}, nil
}

// ReleaseBucket resolves one Region's release bucket name.
func ReleaseBucket(region estate.Region) (string, error) {
	found := ""
	for _, bucket := range region.Buckets {
		if bucket.Purpose == ReleaseBucketPurpose {
			if found != "" {
				return "", fmt.Errorf("delivery: region %s declares more than one %s bucket", region.Code, ReleaseBucketPurpose)
			}
			found = bucket.Name
		}
	}
	return found, nil
}

// MirrorObject is the object key a release artifact mirrors under:
// releases/<service>/<hex>; digest uniqueness makes every key immutable.
func MirrorObject(service, digest string) string {
	return "releases/" + service + "/" + strings.TrimPrefix(digest, "sha256:")
}

// MirrorAll copies the artifact into every declared Region's release bucket.
// It mirrors into ALL Regions, not only the delivery's target Regions, so a
// later delivery targeting any Region finds its artifact locally. Every
// Region must succeed before the rollout may start.
func (m *ArtifactMirror) MirrorAll(ctx context.Context, artifact *ReleaseArtifact) error {
	if m == nil || artifact == nil {
		return errors.New("delivery: artifact mirror is not configured")
	}
	if ctx == nil {
		return errors.New("delivery: mirror context is required")
	}
	if err := ctx.Err(); err != nil {
		return &MirrorBatchError{Failures: []*MirrorError{{
			Kind:        MirrorFailureCanceled,
			Retryable:   true,
			Remediation: "Retry the same operation ID after the delivery context is available.",
			Err:         err,
		}}}
	}
	if len(artifact.Body) == 0 || !SameDigest(SHA256Digest(artifact.Body), artifact.Digest) {
		return &MirrorBatchError{Failures: []*MirrorError{{
			Kind:        MirrorFailureMismatch,
			Retryable:   false,
			Remediation: "Submit the exact bytes named by the verified artifact digest.",
			Err:         errors.New("artifact bytes do not match the declared sha256 digest"),
		}}}
	}
	if strings.TrimSpace(artifact.Service) == "" || len(artifact.Service) > maxText ||
		strings.ContainsAny(artifact.Service, "/\\\x00") || strings.ContainsAny(artifact.Service, "\r\n\t") {
		return &MirrorBatchError{Failures: []*MirrorError{{
			Kind: MirrorFailureMismatch, Retryable: false,
			Remediation: "Submit an artifact for the declared service using a safe immutable object name.",
			Err:         errors.New("artifact service is not a safe object path component"),
		}}}
	}
	if !sha256Pattern.MatchString(artifact.Digest) {
		return &MirrorBatchError{Failures: []*MirrorError{{
			Kind: MirrorFailureMismatch, Retryable: false,
			Remediation: "Submit the exact artifact sha256 digest.",
			Err:         errors.New("artifact digest is not a sha256 digest"),
		}}}
	}
	object := MirrorObject(artifact.Service, artifact.Digest)
	inspector, _ := m.Store.(RegionObjectStoreInspector)
	results := make(chan *MirrorError, len(m.Spec.Regions))
	for _, region := range m.Spec.Regions {
		region := region
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					results <- &MirrorError{Region: region.Code, Kind: MirrorFailureIndeterminate, Retryable: true, Remediation: "Do not start rollout; inspect the Region object store after the provider failure, then retry the same operation ID.", Err: fmt.Errorf("object store panicked: %v", recovered)}
				}
			}()
			bucket, err := ReleaseBucket(region)
			if err != nil {
				results <- &MirrorError{Region: region.Code, Kind: MirrorFailureMismatch, Err: err, Remediation: "Correct the declared release-artifact bucket and reconcile the estate."}
				return
			}
			if bucket == "" {
				results <- &MirrorError{Region: region.Code, Kind: MirrorFailureMismatch, Err: fmt.Errorf("region declares no %s bucket", ReleaseBucketPurpose), Remediation: "Declare exactly one release-artifact bucket in the Region estate."}
				return
			}
			results <- m.mirrorRegion(ctx, inspector, region.Code, bucket, object, artifact)
		}()
	}
	var failures []*MirrorError
	for range m.Spec.Regions {
		if failure := <-results; failure != nil {
			failures = append(failures, failure)
		}
	}
	if len(failures) > 0 {
		sort.Slice(failures, func(i, j int) bool { return failures[i].Region < failures[j].Region })
		return &MirrorBatchError{Failures: failures}
	}
	return nil
}

func (m *ArtifactMirror) mirrorRegion(ctx context.Context, inspector RegionObjectStoreInspector, region, bucket, object string, artifact *ReleaseArtifact) *MirrorError {
	expected := ObjectIdentity{Digest: artifact.Digest, Size: int64(len(artifact.Body))}
	if err := ctx.Err(); err != nil {
		return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: MirrorFailureCanceled, Retryable: true, Expected: expected, Remediation: "Retry the same operation ID after the delivery context is available.", Err: err}
	}
	putIdentity, writeErr, hasPutIdentity := m.put(ctx, region, bucket, object, artifact.Body)
	if inspector == nil {
		// Keep the original Put-only seam source-compatible. A production
		// object-store adapter should implement Head; without it there is no
		// provider read contract from which delivery can obtain identity.
		if writeErr == nil && (!hasPutIdentity || identityMatches(putIdentity, expected)) {
			return nil
		}
		if writeErr == nil {
			return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: MirrorFailureMismatch, Expected: expected, Observed: putIdentity, Retryable: false, Remediation: "Do not roll out; inspect the Region object identity and retry with the same operation ID only after it is corrected.", Err: errors.New("object write identity does not match")}
		}
		return mirrorWriteError(region, bucket, object, expected, writeErr)
	}
	identity, found, readErr := inspector.Head(ctx, region, bucket, object)
	if readErr == nil && found && identityMatches(identity, expected) && identitiesConsistent(identity, putIdentity, expected, hasPutIdentity) {
		return nil // also resolves an If-None-Match conflict or indeterminate PUT.
	}
	if writeErr != nil {
		if readErr != nil {
			return mirrorIndeterminateError(region, bucket, object, expected, identity, writeErr, readErr)
		}
		if !found {
			return mirrorIndeterminateError(region, bucket, object, expected, identity, writeErr, errors.New("object is not visible after the write"))
		}
		return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: MirrorFailureMismatch, Expected: expected, Observed: identity, Retryable: false, Remediation: "Do not roll out; remove or quarantine the conflicting object, then retry the same operation ID.", Err: writeErr}
	}
	if readErr != nil {
		return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: MirrorFailureRead, Expected: expected, Observed: identity, Retryable: true, Remediation: "Retry the same operation ID after Region object metadata reads are healthy.", Err: readErr}
	}
	return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: MirrorFailureMismatch, Expected: expected, Observed: identity, Retryable: false, Remediation: "Do not roll out; inspect the Region object and retry with the same operation ID only after it is corrected.", Err: errors.New("read-after-write object identity does not match")}
}

func (m *ArtifactMirror) put(ctx context.Context, region, bucket, object string, body []byte) (ObjectIdentity, error, bool) {
	if writer, ok := m.Store.(RegionObjectStoreIdentityWriter); ok {
		identity, err := writer.PutWithIdentity(ctx, region, bucket, object, body)
		return identity, err, true
	}
	return ObjectIdentity{}, m.Store.Put(ctx, region, bucket, object, body), false
}

func identityMatches(actual, expected ObjectIdentity) bool {
	digest := strings.TrimSpace(actual.Digest)
	if digest == "" {
		for key, value := range actual.Metadata {
			if strings.EqualFold(key, "sha256") || strings.EqualFold(key, "digest") || strings.EqualFold(key, "opc-meta-terrascale-sha256") {
				digest = value
				break
			}
		}
	}
	return digest != "" && SameDigest(digest, expected.Digest) && actual.Size == expected.Size
}

func identitiesConsistent(observed, written, expected ObjectIdentity, haveWritten bool) bool {
	if !haveWritten {
		return true
	}
	if !identityMatches(written, expected) {
		// A provider adapter that returns an identity must return a complete
		// digest/size pair; a later matching HEAD cannot redeem a bad write
		// response.
		return false
	}
	if written.ETag != "" && written.ETag != observed.ETag {
		return false
	}
	if written.Version != "" && written.Version != observed.Version {
		return false
	}
	for key, value := range written.Metadata {
		observedValue, ok := metadataValue(observed.Metadata, key)
		if !ok || observedValue != value {
			return false
		}
	}
	return true
}

func metadataValue(metadata map[string]string, key string) (string, bool) {
	for candidate, value := range metadata {
		if strings.EqualFold(candidate, key) {
			return value, true
		}
	}
	return "", false
}

func mirrorWriteError(region, bucket, object string, expected ObjectIdentity, err error) *MirrorError {
	return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: mirrorFailureKind(err), Expected: expected, Retryable: true, Remediation: "Retry the same operation ID after the Region object store is reachable.", Err: err}
}

func mirrorIndeterminateError(region, bucket, object string, expected, observed ObjectIdentity, writeErr, readErr error) *MirrorError {
	return &MirrorError{Region: region, Bucket: bucket, Object: object, Kind: MirrorFailureIndeterminate, Expected: expected, Observed: observed, Retryable: true, Remediation: "Do not start rollout; verify the Region object store, then retry the same operation ID.", Err: errors.Join(writeErr, readErr)}
}

func mirrorFailureKind(err error) MirrorFailureKind {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return MirrorFailureCanceled
	}
	if indeterminateMirrorError(err) {
		return MirrorFailureIndeterminate
	}
	return MirrorFailureWrite
}

type mirrorIndeterminate interface{ Indeterminate() bool }

func indeterminateMirrorError(err error) bool {
	var marker mirrorIndeterminate
	return errors.Is(err, ErrMirrorIndeterminate) || (errors.As(err, &marker) && marker.Indeterminate())
}

// ErrMirrorIndeterminate marks a provider outcome where the PUT may have
// committed but its result was not observed. Callers can wrap this sentinel.
var ErrMirrorIndeterminate = errors.New("delivery: mirror write outcome is indeterminate")
