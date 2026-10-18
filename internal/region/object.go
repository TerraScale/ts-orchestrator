package region

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
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

// The finite journal retains all three regions' requests, receipts and outcomes;
// grants and individual policy requests keep their separate 128 KiB bound.
const foundationJournalLimit = 512 << 10
const foundationObjectPrefix = "orchestrator/regions/v1/"

type FoundationObjects interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

// ObjectFoundationStore uses a pre-existing protected home-region bucket. IAM
// access to the bucket alone does not authorize a regional footprint.
type ObjectFoundationStore struct {
	originalCompartmentScope *OriginalFoundationCompartments
	originalSourceBirth      *[3]OriginalSourceProducerBirth
	client                   FoundationObjects
	namespace, bucket        string
}

func NewObjectFoundationStore(client FoundationObjects, namespace, bucket string) (*ObjectFoundationStore, error) {
	if client == nil || namespace == "" || bucket == "" || strings.ContainsAny(namespace+bucket, "/\\\r\n") {
		return nil, errors.New("regional foundation store requires an existing home bucket and namespace")
	}
	return &ObjectFoundationStore{client: client, namespace: namespace, bucket: bucket}, nil
}

// MarshalJSONTo preserves omitted OCI SDK fields across durable record roundtrips.
func (r FoundationRecord) MarshalJSONTo(enc *jsontext.Encoder) error {
	type foundationRecord FoundationRecord
	return json.MarshalEncode(enc, foundationRecord(r), json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true))
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
	wire, err := io.ReadAll(io.LimitReader(response.Content, foundationJournalLimit+1))
	if err != nil {
		return FoundationRecord{}, "", err
	}
	if len(wire) > foundationJournalLimit {
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
	// The original prerequisite section is born only after the existing complete
	// material record has been independently read and conditionally extended.
	if etag == "" && record.OriginalFoundationCompartments != nil {
		return "", ErrOriginalSourceProducerHold
	}
	// Attach the complete purpose array to the SAME original NetBird birth CAS.
	// Only the verified original operator binds this private initial scope.
	if etag == "" && record.NetBirdMaterial != nil && record.OriginalSourceProducers == nil && s.originalSourceBirth != nil {
		birth := *s.originalSourceBirth
		for index := range birth {
			birth[index].BornAt = record.NetBirdMaterial.BornAt
		}
		record.OriginalSourceProducers = &birth
	}
	if etag == "" && record.NetBirdMaterial != nil {
		if s.originalSourceBirth == nil || record.OriginalSourceProducers == nil {
			return "", ErrOriginalSourceProducerHold
		}
		expected := *s.originalSourceBirth
		for index := range expected {
			expected[index].BornAt = record.NetBirdMaterial.BornAt
		}
		if !sameOriginalSourceValue(expected, record.OriginalSourceProducers) {
			return "", ErrOriginalSourceProducerHold
		}
	}
	if err := record.validate(); err != nil {
		return "", err
	}
	if etag != "" {
		previous, observedETag, err := s.Load(ociclient.CheckpointContext(ctx), record.Cell)
		if err != nil {
			return "", err
		}
		if observedETag != etag {
			return "", ErrFoundationConflict
		}
		if err := record.retainFoundationWriterQuote(previous); err != nil {
			return "", err
		}
		if err := record.retainNetBirdManager(previous); err != nil {
			return "", err
		}
		if err := record.retainNetBirdMaterial(previous); err != nil {
			return "", err
		}
		if err := record.retainOriginalSourceProducers(previous); err != nil {
			return "", err
		}
		if err := record.retainOriginalFoundationCompartments(previous); err != nil {
			return "", err
		}
		if previous.OriginalFoundationCompartments == nil && record.OriginalFoundationCompartments != nil &&
			(s.originalCompartmentScope == nil || !sameOriginalSourceValue(record.OriginalFoundationCompartments, s.originalCompartmentScope)) {
			return "", ErrOriginalSourceProducerHold
		}
		if err := previous.retainOCIRIssuances(record); err != nil {
			return "", err
		}
		if err := record.retainCapacity(previous); err != nil {
			return "", err
		}
		if err := record.retainPoolDrains(previous); err != nil {
			return "", err
		}
		if err := record.retainCapacityJournal(previous); err != nil {
			return "", err
		}
	}
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	if len(wire) > foundationJournalLimit {
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
	if err := r.validateOriginalFoundationCompartments(); err != nil {
		return err
	}
	if err := r.validateOriginalSourceProducers(); err != nil {
		return err
	}
	if err := r.validateNetBirdMaterial(); err != nil {
		return err
	}
	if err := r.validateOCIRIssuances(); err != nil {
		return err
	}
	if r.OCIResources != nil {
		if err := r.OCIResources.Validate(r.Cell); err != nil {
			return fmt.Errorf("protected OCI amendment journal: %w", err)
		}
	}
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
	case "original-foundation":
		if r.OriginalFoundationCompartments == nil || !r.netBirdMaterialOnly() {
			return errors.New("original foundation prerequisites cannot authorize runtime progress")
		}
	case "material":
		if r.OriginalFoundationCompartments != nil || !r.netBirdMaterialOnly() {
			return errors.New("material-only reservation cannot authorize foundation progress")
		}
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
	// Retained worker grants are finite; wire size remains independently bounded.
	if len(r.WorkerPolicyIDs) > 256 {
		return errors.New("worker IAM journal exceeds its fixed bound")
	}
	for key, worker := range r.WorkerPolicyIDs {
		if err := worker.validate(key); err != nil {
			return err
		}
	}
	if len(r.SourcePolicyIDs) > 64 {
		return errors.New("source policy reservations exceed their fixed bound")
	}
	for key, source := range r.SourcePolicyIDs {
		if err := source.validate(key); err != nil {
			return err
		}
	}
	if r.FoundationWriter != nil {
		if r.FoundationWriter.Cell != r.Cell || r.FoundationWriter.Generation > r.Generation || r.FoundationWriter.validate() != nil || r.FoundationWriter.OriginalQuote != nil && r.FoundationWriter.OriginalQuote.IssuedAt.After(r.UpdatedAt) {
			return errors.New("original home writer checkpoint is invalid")
		}
	}
	if r.NetBirdManager != nil {
		if r.Cell != "GRU" || r.NetBirdManager.validate() != nil || r.NetBirdManager.OriginalQuote != nil &&
			(r.NetBirdManager.OriginalQuote.CompartmentID != r.ResourceIDs["control_compartment"] || r.NetBirdManager.StartedAt.After(r.UpdatedAt)) {
			return errors.New("dedicated NetBird manager checkpoint is invalid")
		}
	}
	if r.GrantSHA256 != "" && !validFoundationDigest(r.GrantSHA256) || len(r.ResourceProvenance) > 128 {
		return errors.New("foundation record has invalid grant or resource provenance bound")
	}
	for key, proof := range r.ResourceProvenance {
		pending := proof.Create
		if proof.ResourceID != r.ResourceIDs[key] && proof.ResourceID != r.AuxiliaryIDs[key] ||
			proof.Generation == 0 || proof.Generation > r.Generation || !validFoundationDigest(proof.GrantSHA256) ||
			pending.OperationID != entityid.Derive("regional-foundation", r.TenancyID, r.Cell, fmt.Sprint(proof.Generation)) ||
			!validFoundationDigest(pending.IntentDigest) || pending.Request.Key != key || pending.Request.Validate() != nil ||
			pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.After(r.UpdatedAt) {
			return errors.New("foundation resource provenance differs from original creation authority")
		}
		if proof.Generation == r.Generation && (proof.GrantSHA256 != r.GrantSHA256 || pending.IntentDigest != r.IntentDigest || pending.FirstAttemptAt.Before(r.StartedAt)) {
			return errors.New("foundation resource provenance differs from current generation")
		}
	}
	if len(r.AuxiliaryIDs) > 12 || len(r.PendingCreates) > 64 || r.Stage == "reconciled" && len(r.PendingCreates) != 0 {
		return errors.New("foundation auxiliary identities or pending creates exceed their bound")
	}
	for key, id := range r.AuxiliaryIDs {
		if !validAuxiliaryID(key, id, r.OCIRegion) {
			return errors.New("foundation record has invalid auxiliary identity")
		}
	}
	for key, pending := range r.PendingCreates {
		if pending.OperationID != r.OperationID || pending.IntentDigest != r.IntentDigest || pending.Request.Key != key ||
			pending.Request.Validate() != nil || pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(r.StartedAt) || pending.FirstAttemptAt.After(r.UpdatedAt) {
			return errors.New("foundation record has invalid pending create")
		}
	}
	if err := r.validateCapacity(); err != nil {
		return err
	}
	return r.validatePoolDrains()
}

func validAuxiliaryID(key, id, region string) bool {
	kind := ""
	switch key {
	case "controller_usage_policy", "netbird_enrollment_policy":
		kind = "policy"
		region = ""
	case "ledger_bucket", "head_bucket", "backup_bucket", "material_bucket":
		kind = "bucket"
	case "netbird_manager_vcn":
		kind = "vcn"
	case "netbird_manager_internet_gateway":
		kind = "internetgateway"
	case "netbird_manager_route":
		kind = "routetable"
	case "netbird_manager_security_list":
		kind = "securitylist"
	case "netbird_manager_subnet":
		kind = "subnet"
	case "netbird_manager_nsg":
		kind = "networksecuritygroup"
	default:
		return false
	}
	parts := strings.Split(id, ".")
	if len(parts) < 5 || parts[0] != "ocid1" || parts[1] != kind || parts[2] != "oc1" || len(id) > 512 {
		return false
	}
	// Phoenix and Ashburn retain the original short OCID region spelling.
	if parts[3] != region && !(region == "us-phoenix-1" && parts[3] == "phx") && !(region == "us-ashburn-1" && parts[3] == "iad") {
		return false
	}
	for _, part := range parts[4:] {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < 'a' || char > 'z' {
				if char < '0' || char > '9' {
					return false
				}
			}
		}
	}
	return true
}

func validFoundationDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == value
}
