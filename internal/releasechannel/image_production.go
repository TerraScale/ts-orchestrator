package releasechannel

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// ImageProductionEvidenceObject is immutable evidence in the existing regional head bucket.
func ImageProductionEvidenceObject(digest string) string {
	return "releases/images/production/objects/" + digest
}

// OpenImageProductionEvidence uses the region's authenticated Object Storage client.
// The consumer checks the stream against its independently signed size and digest.
func OpenImageProductionEvidence(ctx context.Context, location Location, digest string) (io.ReadCloser, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
		return nil, fmt.Errorf("%w: image evidence digest", ErrInvalid)
	}
	name := ImageProductionEvidenceObject(digest)
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{
		NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name,
	})
	if err != nil {
		return nil, fmt.Errorf("read retained image evidence: %w", err)
	}
	if response.Content == nil {
		return nil, fmt.Errorf("%w: empty image evidence response", ErrInvalid)
	}
	return response.Content, nil
}
