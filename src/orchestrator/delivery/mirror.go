package delivery

import (
	"context"
	"errors"
	"fmt"
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
	object := MirrorObject(artifact.Service, artifact.Digest)
	var failures []string
	for _, region := range m.Spec.Regions {
		bucket, err := ReleaseBucket(region)
		if err != nil {
			return err
		}
		if bucket == "" {
			return fmt.Errorf("delivery: region %s declares no %s bucket", region.Code, ReleaseBucketPurpose)
		}
		if err := m.Store.Put(ctx, region.Code, bucket, object, artifact.Body); err != nil {
			failures = append(failures, region.Code+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("delivery: artifact mirror incomplete: %s", strings.Join(failures, "; "))
	}
	return nil
}
