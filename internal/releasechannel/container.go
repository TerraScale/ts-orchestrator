package releasechannel

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const MaxContainerBundleBytes = 32 << 10

var containerRole = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ContainerReleaseObject keeps OCI claims separate from native binary releases.
func ContainerReleaseObject(role, architecture string) string {
	return servicePrefix + role + "/containers/" + architecture + "/container.json"
}
func ContainerEvidenceObject(role, digest string) string {
	return servicePrefix + role + "/containers/objects/" + digest
}

func ReadContainerBundle(ctx context.Context, location Location, role, architecture string) (release.ContainerBundle, bool, error) {
	if !containerRole.MatchString(role) || architecture != "amd64" && architecture != "arm64" {
		return release.ContainerBundle{}, false, ErrInvalid
	}
	wire, _, found, err := location.get(ctx, ContainerReleaseObject(role, architecture), MaxContainerBundleBytes)
	if err != nil || !found {
		return release.ContainerBundle{}, found, err
	}
	var bundle release.ContainerBundle
	if err := protocol.DecodeStrict(wire, &bundle, MaxContainerBundleBytes); err != nil {
		return release.ContainerBundle{}, true, err
	}
	return bundle, true, nil
}

// ReadContainerEvidence streams immutable bytes; VerifyContainerCurrent checks
// their signed size and SHA-256 before allowing a runtime mutation.
func ReadContainerEvidence(ctx context.Context, location Location, role, digest string) (io.ReadCloser, error) {
	if !containerRole.MatchString(role) || len(digest) != 64 {
		return nil, ErrInvalid
	}
	for _, char := range digest {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return nil, ErrInvalid
		}
	}
	name := ContainerEvidenceObject(role, digest)
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name})
	if err != nil {
		return nil, err
	}
	if response.Content == nil {
		return nil, fmt.Errorf("%w: container evidence has no body", ErrInvalid)
	}
	return response.Content, nil
}

// PublishContainer verifies fresh authority and compares the authenticated
// retained floor, including expired historical releases. Renewing independent
// qualification may reuse a sequence only for identical immutable content.
func PublishContainer(ctx context.Context, location Location, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget, now, deadline time.Time, evidence func(context.Context, string) (io.ReadCloser, error)) error {
	verified, err := release.VerifyContainerCurrent(ctx, bundle, roots, target, now, deadline, evidence)
	if err != nil {
		return err
	}
	incoming := verified.Claim()
	bucket, err := BucketName(target.Cell)
	if err != nil {
		return err
	}
	if location.Bucket != bucket || location.Namespace != verified.Migration().Namespace {
		return fmt.Errorf("%w: container publication target", ErrInvalid)
	}
	wire, err := json.Marshal(bundle, json.Deterministic(true))
	if err != nil {
		return err
	}
	if len(wire) > MaxContainerBundleBytes {
		return fmt.Errorf("%w: container bundle exceeds bound", ErrInvalid)
	}
	name := ContainerReleaseObject(target.Role, target.Architecture)
	for range 3 {
		current, etag, found, err := location.get(ctx, name, MaxContainerBundleBytes)
		if err != nil {
			return err
		}
		if found {
			var retained release.ContainerBundle
			if err := protocol.DecodeStrict(current, &retained, MaxContainerBundleBytes); err != nil {
				return err
			}
			previous, err := release.VerifyContainerHistorical(retained, roots, target)
			if err != nil {
				return fmt.Errorf("authenticate retained container floor: %w", err)
			}
			floor := previous.Claim()
			if incoming.ReleaseSequence < floor.ReleaseSequence {
				return ErrStale
			}
			if incoming.ReleaseSequence == floor.ReleaseSequence && verified.ReleaseIdentity() != previous.ReleaseIdentity() {
				return fmt.Errorf("%w: container sequence already names different content", ErrInvalid)
			}
		} else {
			if _, err := release.VerifySequenceMigrationCurrent(verified.MigrationEnvelope(), roots, target.Role, target.Environment, now); err != nil {
				return err
			}
		}
		if err := location.put(ctx, name, wire, etag); !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}

const ContainerStatusSchema = "terrascale.release.container-status.v1"

type ContainerStatus struct {
	Schema          string    `json:"schema"`
	Cell            string    `json:"cell"`
	Environment     string    `json:"environment"`
	Role            string    `json:"role"`
	Architecture    string    `json:"architecture"`
	Image           string    `json:"image"`
	ReleaseSequence uint64    `json:"release_sequence"`
	Fingerprint     string    `json:"fingerprint"`
	State           State     `json:"state"`
	Reason          string    `json:"reason,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func ContainerStatusObject(role, architecture string) string {
	return servicePrefix + role + "/containers/" + architecture + "/status.json"
}
func ReadContainerStatus(ctx context.Context, location Location, role, architecture string) (ContainerStatus, bool, error) {
	var status ContainerStatus
	if !containerRole.MatchString(role) || architecture != "amd64" && architecture != "arm64" {
		return status, false, ErrInvalid
	}
	found, err := location.read(ctx, ContainerStatusObject(role, architecture), maxStatusBytes, &status)
	return status, found, err
}
func WriteContainerStatus(ctx context.Context, location Location, status ContainerStatus) error {
	if !containerRole.MatchString(status.Role) || status.Architecture != "amd64" && status.Architecture != "arm64" {
		return ErrInvalid
	}
	status.Schema = ContainerStatusSchema
	status.Reason = Clip(status.Reason)
	wire, err := json.Marshal(status, json.Deterministic(true))
	if err != nil {
		return err
	}
	// Telemetry may be overwritten; the authenticated release is the admission record.
	name := ContainerStatusObject(status.Role, status.Architecture)
	for range 3 {
		_, etag, _, err := location.get(ctx, name, maxStatusBytes)
		if err != nil {
			return err
		}
		if err := location.put(ctx, name, wire, etag); !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}
