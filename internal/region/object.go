package region

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const foundationRecordLimit = 128 << 10
const foundationObjectPrefix = "orchestrator/regions/v1/"

type FoundationObjects interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

// ObjectFoundationStore uses a pre-existing protected home-region bucket. IAM
// access to the bucket alone does not authorize a regional footprint.
type ObjectFoundationStore struct {
	client            FoundationObjects
	namespace, bucket string
}

func NewObjectFoundationStore(client FoundationObjects, namespace, bucket string) (*ObjectFoundationStore, error) {
	if client == nil || namespace == "" || bucket == "" || strings.ContainsAny(namespace+bucket, "/\\\r\n") {
		return nil, errors.New("regional foundation store requires an existing home bucket and namespace")
	}
	return &ObjectFoundationStore{client: client, namespace: namespace, bucket: bucket}, nil
}

func (s *ObjectFoundationStore) Load(ctx context.Context, cell string) (FoundationRecord, string, error) {
	if !catalog.IsCell(cell) {
		return FoundationRecord{}, "", errors.New("foundation record cell is outside catalog")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	name := foundationObjectPrefix + cell + ".json"
	response, err := s.client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(s.namespace), BucketName: new(s.bucket), ObjectName: new(name)})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return FoundationRecord{}, "", ErrFoundationMissing
	}
	if err != nil {
		return FoundationRecord{}, "", fmt.Errorf("read regional foundation record: %w", err)
	}
	if response.Content == nil {
		return FoundationRecord{}, "", errors.New("foundation record has no content")
	}
	defer response.Content.Close()
	if response.ETag == nil || *response.ETag == "" {
		return FoundationRecord{}, "", errors.New("foundation record has no conditional-write ETag")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Content, foundationRecordLimit+1))
	if err != nil {
		return FoundationRecord{}, "", err
	}
	if len(wire) > foundationRecordLimit {
		return FoundationRecord{}, "", errors.New("foundation record exceeds size bound")
	}
	var record FoundationRecord
	if err := json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)); err != nil {
		return FoundationRecord{}, "", errors.New("foundation record has invalid schema")
	}
	if err := record.validate(); err != nil {
		return FoundationRecord{}, "", err
	}
	if record.Cell != cell {
		return FoundationRecord{}, "", errors.New("foundation record differs from its object key")
	}
	return record, *response.ETag, nil
}

func (s *ObjectFoundationStore) CompareAndSwap(ctx context.Context, record FoundationRecord, etag string) (string, error) {
	if err := record.validate(); err != nil {
		return "", err
	}
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	if len(wire) > foundationRecordLimit {
		return "", errors.New("foundation record exceeds size bound")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	name := foundationObjectPrefix + record.Cell + ".json"
	// CAS outcomes can be unknown after transport loss. Read on the next pass;
	// never retry an unconditional write or regenerate an operation identity.
	policy := common.NoRetryPolicy()
	request := objectstorage.PutObjectRequest{NamespaceName: new(s.namespace), BucketName: new(s.bucket), ObjectName: new(name),
		ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)),
		ContentType: new("application/json"), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(etag)
	}
	response, err := s.client.PutObject(ociclient.RequestContext(ctx), request)
	if service, ok := common.IsServiceError(err); ok && (service.GetHTTPStatusCode() == 409 || service.GetHTTPStatusCode() == 412) {
		return "", ErrFoundationConflict
	}
	if err != nil {
		return "", fmt.Errorf("write regional foundation record: %w", err)
	}
	if response.ETag == nil || *response.ETag == "" {
		return "", errors.New("foundation write returned no conditional-write ETag")
	}
	return *response.ETag, nil
}

func (r FoundationRecord) validate() error {
	entry, ok := catalog.Lookup(r.Cell)
	digest, digestErr := hex.DecodeString(r.IntentDigest)
	if r.SchemaVersion != 1 || !ok || r.OCIRegion != entry.OCIRegion || !strings.HasPrefix(r.TenancyID, "ocid1.tenancy.") ||
		!strings.HasPrefix(r.ParentCompartmentID, "ocid1.compartment.") || !strings.HasPrefix(r.SharedCompartmentID, "ocid1.compartment.") ||
		r.Generation == 0 || r.Epoch == 0 || !entityid.Valid(r.OperationID) || digestErr != nil || len(digest) != 32 ||
		r.StartedAt.IsZero() || r.UpdatedAt.Before(r.StartedAt) || len(r.ResourceIDs) > 128 {
		return errors.New("foundation record has invalid scope, generation, operation or timestamps")
	}
	if r.LeaseID != "" && (!entityid.Valid(r.LeaseID) || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.UpdatedAt)) ||
		r.LeaseID == "" && !r.ExpiresAt.IsZero() {
		return errors.New("foundation record lease is invalid")
	}
	switch r.Stage {
	case "foundation":
		if r.LeaseID == "" || !r.CompletedAt.IsZero() || r.BlockedReason != "" {
			return errors.New("active foundation record has invalid outcome")
		}
	case "reconciled":
		if r.LeaseID != "" || r.CompletedAt.IsZero() || r.BlockedReason != "" {
			return errors.New("reconciled foundation record has invalid outcome")
		}
	case "blocked":
		if r.LeaseID != "" || r.BlockedReason != "foundation-unavailable" || !r.CompletedAt.IsZero() {
			return errors.New("blocked foundation record has invalid outcome")
		}
	default:
		return errors.New("foundation record has unknown stage")
	}
	for key, id := range r.ResourceIDs {
		if key == "" || len(key) > 128 || !strings.HasPrefix(id, "ocid1.") || len(id) > 512 {
			return errors.New("foundation record has invalid resource identity")
		}
	}
	return nil
}
