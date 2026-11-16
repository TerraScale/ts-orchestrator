package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// FoundationWriterRecord permanently reserves the initial home controller.
// Grant renewal cannot transfer this launch or its exact protected objects.
type FoundationWriterRecord struct {
	OriginalQuote         *capacityledger.Quote            `json:"originalQuote,omitempty"`
	Cell                  string                           `json:"cell"`
	Slot                  string                           `json:"slot"`
	InstallationID        string                           `json:"installationId"`
	GrantSHA256           string                           `json:"grantSha256"`
	Generation            uint64                           `json:"generation"`
	SlotID                string                           `json:"slotId"`
	OperationID           string                           `json:"operationId"`
	ProfileSHA256         string                           `json:"profileSha256"`
	RecipeSHA256          string                           `json:"recipeSha256"`
	BindingSHA256         string                           `json:"bindingSha256"`
	ScopeSHA256           string                           `json:"scopeSha256"`
	PhysicalScopeSHA256   string                           `json:"physicalScopeSha256"`
	Namespace             string                           `json:"namespace"`
	Bucket                string                           `json:"bucket"`
	BucketCompartment     string                           `json:"bucketCompartment"`
	KMSKeyID              string                           `json:"kmsKeyId"`
	Request               core.LaunchInstanceDetails       `json:"request"`
	RequestDigest         string                           `json:"requestDigest"`
	RetryToken            string                           `json:"retryToken"`
	FirstAttemptAt        time.Time                        `json:"firstAttemptAt"`
	InstanceID            string                           `json:"instanceId,omitempty"`
	Policy                *FoundationWriterPolicy          `json:"policy,omitempty"`
	CapacityJournal       *CapacityJournalPolicy           `json:"capacityJournal,omitempty"`
	CapacityJournalScopes map[string]CapacityJournalPolicy `json:"capacityJournalScopes,omitempty"`
}

type FoundationWriterPolicy struct {
	Request        identity.CreatePolicyDetails `json:"request"`
	RequestDigest  string                       `json:"requestDigest"`
	RetryToken     string                       `json:"retryToken"`
	FirstAttemptAt time.Time                    `json:"firstAttemptAt"`
	PolicyID       string                       `json:"policyId,omitempty"`
	VerifiedAt     time.Time                    `json:"verifiedAt,omitzero"`
}

func foundationWriterPolicy(record FoundationWriterRecord) (identity.CreatePolicyDetails, error) {
	if !sourceInstancePattern.MatchString(record.InstanceID) || !sourceCompartmentPattern.MatchString(record.BucketCompartment) || !sourceStoragePattern.MatchString(record.Bucket) {
		return identity.CreatePolicyDetails{}, errors.New("home writer policy has invalid exact scope")
	}
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", record.InstanceID)
	statements := make([]string, 0, 5)
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		key := "orchestrator/regions/v1/" + cell + ".json"
		permissions := "request.permission='OBJECT_READ'"
		if cell == record.Cell {
			permissions += ", request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'"
		}
		statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, target.bucket.name='%s', target.object.name='%s', any {%s}}", record.BucketCompartment, principal, record.Bucket, key, permissions))
	}
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, target.bucket.name='%s', target.object.name='%s', any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}", record.BucketCompartment, principal, record.Bucket, homeIAMObject))
	// OCI cannot constrain a created policy body; the root process confines this principal.
	statements = append(statements, fmt.Sprintf("Allow any-user to manage policies in compartment id %s where all {%s, any {request.permission='POLICY_INSPECT', request.permission='POLICY_READ', request.permission='POLICY_CREATE'}}", record.BucketCompartment, principal))
	// Durable JSON restores nil maps as empty; send the same maps initially.
	return identity.CreatePolicyDetails{CompartmentId: new(record.BucketCompartment), Name: new("ts-foundation-writer-" + digestSource([]byte(record.InstallationID + "\x00" + record.Cell))[:32]), Description: new("Original home writer exact protected journals and policy creation"), Statements: statements, FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}, nil
}

func foundationWriterPolicyBody(details identity.CreatePolicyDetails) ([]byte, error) {
	request := identity.CreatePolicyRequest{CreatePolicyDetails: details}
	httpRequest, err := request.HTTPRequest(http.MethodPost, "/20160918/policies", nil, nil)
	if err != nil {
		return nil, err
	}
	if httpRequest.Body == nil {
		return nil, errors.New("home writer SDK policy request has no body")
	}
	defer httpRequest.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(httpRequest.Body, foundationRecordLimit+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > foundationRecordLimit {
		return nil, errors.New("home writer SDK policy request exceeds size bound")
	}
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		return nil, err
	}
	return json.Marshal(object, json.Deterministic(true))
}

// VerifyFoundationWriter gates principal effects on sealed local identity and
// the independently read original launch and current exact IAM policy.
func (authority *HomeIAMAuthority) VerifyFoundationWriter(ctx context.Context) error {
	if err := authority.guardScope(ctx); err != nil {
		return err
	}
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok {
		return ErrFoundationFenced
	}
	record, _, err := authority.resolver.Store.Load(ctx, entry.Cell)
	if err != nil {
		return err
	}
	pending := record.FoundationWriter
	if pending == nil || pending.validate() != nil || pending.Cell != entry.Cell || pending.InstanceID != authority.instanceID || pending.InstallationID != authority.installationID || pending.Namespace != authority.domain.Namespace || pending.Bucket != authority.domain.HeadBucket || pending.KMSKeyID != authority.domain.HeadKMSKeyOCID || pending.BucketCompartment != authority.bucketCompartment || pending.Policy == nil || pending.Policy.PolicyID == "" || pending.Policy.VerifiedAt.IsZero() {
		return ErrFoundationFenced
	}
	material, err := authority.resolver.BootstrapMaterial(ctx, entry.Cell)
	if err != nil {
		return err
	}
	writerImage, imageExpected, err := foundationWriterImage(ctx, authority.resolver, material, entry.Cell)
	if err != nil {
		return err
	}
	home, err := authority.factory.HomeRegion(ctx, authority.tenancyID)
	if err != nil {
		return err
	}
	factory, err := authority.factory.ForRegion(home)
	if err != nil {
		return err
	}
	iam, err := factory.Identity()
	if err != nil {
		return err
	}
	if err := (&SourceFounder{iam: iam}).verifyPolicy(ctx, SourcePolicyRecord{Request: pending.Policy.Request, PolicyID: pending.Policy.PolicyID}); err != nil {
		return err
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	if err := writerImage.ValidFor(imageExpected, time.Now()); err != nil {
		return err
	}
	if err := ociclient.LimitAdmission(ctx, writerImage.ExpiresAt()); err != nil {
		return err
	}
	return ociclient.LimitAdmission(ctx, material.ExpiresAt())
}

func (record FoundationWriterRecord) validate() error {
	digest, err := netBirdRequestDigest(record.Request)
	entry, ok := catalog.Lookup(record.Cell)
	if err != nil || !ok || !slices.Contains([]string{"GRU", "SJC", "FRA"}, record.Cell) || !entityid.Valid(record.InstallationID) || record.SlotID != BootstrapSlotID(record.InstallationID, record.Cell, "controller", record.Slot) || record.OperationID != BootstrapOperationID(record.InstallationID, record.SlotID) || record.InstanceID != "" && !strings.HasPrefix(record.InstanceID, "ocid1.instance.oc1."+entry.OCIRegion+".") || record.Generation == 0 || !sourceDigest(record.GrantSHA256) || !sourceDigest(record.ProfileSHA256) || !sourceDigest(record.RecipeSHA256) || !sourceDigest(record.ScopeSHA256) || !sourceDigest(record.PhysicalScopeSHA256) || record.BindingSHA256 != "" && !sourceDigest(record.BindingSHA256) || record.RequestDigest != digest || record.RetryToken != BootstrapRetryToken(record.OperationID, digest) || record.FirstAttemptAt.IsZero() || !bootstrapSlotName.MatchString(record.Slot) || !foundationWriterKeyPattern.MatchString(record.KMSKeyID) || !sourceStoragePattern.MatchString(record.Namespace) || !sourceStoragePattern.MatchString(record.Bucket) || !sourceCompartmentPattern.MatchString(record.BucketCompartment) || record.InstanceID != "" && !sourceInstancePattern.MatchString(record.InstanceID) || record.Request.CompartmentId == nil || !sourceCompartmentPattern.MatchString(*record.Request.CompartmentId) || !maps.Equal(record.Request.Metadata, foundationWriterMetadata(record.Slot)) || len(record.Request.ExtendedMetadata) != 0 {
		return errors.New("home writer original launch reservation is invalid")
	}
	if q := record.OriginalQuote; q != nil {
		source, ok := record.Request.SourceDetails.(core.InstanceSourceViaImageDetails)
		shape := record.Request.ShapeConfig
		if q.Validate() != nil || q.ScopeSHA256 != record.PhysicalScopeSHA256 || q.Cell != record.Cell || q.CompartmentID != *record.Request.CompartmentId || record.Request.Shape == nil || q.Shape != *record.Request.Shape ||
			shape == nil || shape.Ocpus == nil || shape.MemoryInGBs == nil || q.OCPUs != float64(*shape.Ocpus) || q.MemoryGB != float64(*shape.MemoryInGBs) ||
			!ok || source.BootVolumeSizeInGBs == nil || q.BootGB != float64(*source.BootVolumeSizeInGBs) || source.BootVolumeVpusPerGB == nil || *source.BootVolumeVpusPerGB != 10 || q.IssuedAt.Before(record.FirstAttemptAt) {
			return errors.New("home writer original quote differs from its exact launch scope, geometry or first attempt")
		}
	}
	if record.Policy == nil {
		if record.CapacityJournal != nil || len(record.CapacityJournalScopes) != 0 {
			return errors.New("capacity journal lacks the original foundation writer policy")
		}
		return nil
	}
	expected, err := foundationWriterPolicy(record)
	if err != nil {
		return err
	}
	expectedWire, err := foundationWriterPolicyBody(expected)
	if err != nil {
		return err
	}
	actualWire, err := foundationWriterPolicyBody(record.Policy.Request)
	policy := record.Policy
	if err != nil || string(expectedWire) != string(actualWire) || policy.RequestDigest != digestSource(actualWire) || policy.RetryToken != digestSource([]byte(record.RequestDigest+"\x00"+record.InstanceID+"\x00"+policy.RequestDigest)) || policy.FirstAttemptAt.Before(record.FirstAttemptAt) || policy.PolicyID == "" && !policy.VerifiedAt.IsZero() || policy.PolicyID != "" && (!validAuxiliaryID("controller_usage_policy", policy.PolicyID, "") || policy.VerifiedAt.Before(policy.FirstAttemptAt)) {
		return errors.New("home writer IAM reservation differs from its canonical original policy")
	}
	return record.validateCapacityJournal()
}

func (next FoundationRecord) retainFoundationWriterQuote(previous FoundationRecord) error {
	if previous.FoundationWriter == nil {
		return nil
	}
	if next.FoundationWriter == nil {
		return errors.New("home writer original reservation cannot be removed")
	}
	old := *previous.FoundationWriter
	if old.OriginalQuote == nil {
		if next.FoundationWriter.OriginalQuote != nil {
			return errors.New("historical home writer cannot acquire a reconstructed original quote")
		}
		return nil
	}
	current := *next.FoundationWriter
	if !retainedString(old.InstanceID, current.InstanceID) {
		return errors.New("quoted home writer cannot replace its original instance")
	}
	current.InstanceID = old.InstanceID
	current.Policy, old.Policy = nil, nil
	current.CapacityJournal, old.CapacityJournal = nil, nil
	current.CapacityJournalScopes, old.CapacityJournalScopes = nil, nil
	if !sameCapacityValue(old, current) {
		return errors.New("home writer cannot replace its original quote or launch identity")
	}
	return nil
}

func foundationWriterMetadata(slot string) map[string]string {
	return map[string]string{"terrascale-bootstrap": fmt.Sprintf(`{"schemaVersion":1,"slot":%q}`, slot)}
}

var foundationWriterKeyPattern = regexp.MustCompile(`^ocid1\.key\.oc1\.sa-saopaulo-1\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

func foundationWriterImage(ctx context.Context, resolver FoundationResolver, material VerifiedBootstrapMaterial, cell string) (release.VerifiedFoundationWriterImage, release.ImageExpectation, error) {
	startup, err := material.Startup()
	if err != nil {
		return release.VerifiedFoundationWriterImage{}, release.ImageExpectation{}, err
	}
	expected := release.ImageExpectation{Environment: material.Config().Environment, LogicalRegion: cell, OCIImageOCID: startup.ImageOCID, Architecture: strings.TrimPrefix(startup.ImageArchitecture, "linux-")}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return release.VerifiedFoundationWriterImage{}, expected, errors.New("writer image requires independently signed foundation")
	}
	proof, err := release.VerifyFoundationWriterImageCurrent(ctx, release.HostImageQualification{Receipt: startup.ReleaseImageReceiptWire, Delegation: startup.ReleaseDelegationWire, Expected: expected, Role: "manager"}, reader.roots, reader.openNetBirdEvidence, time.Now())
	return proof, expected, err
}
