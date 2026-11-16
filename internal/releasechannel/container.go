package releasechannel

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// Reserve room for the authenticated intent source, scope and operation fields.
const MaxContainerBundleBytes = delivery.MaxIntentBytes - (2 << 10)

var containerRole = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func ContainerEvidenceObject(role, digest string) string {
	return servicePrefix + role + "/containers/objects/" + digest
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

const ContainerStatusSchema = "terrascale.release.container-status.v1"

type ContainerStatus struct {
	Schema          string    `json:"schema"`
	OperationID     string    `json:"operation_id,omitempty"`
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
