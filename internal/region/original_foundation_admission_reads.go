package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const originalAdmissionReadPurpose = "original-actor-admission-reads/v1"

var ErrOriginalFoundationAdmissionReadsPending = fmt.Errorf("%w: original actor admission reads retained; local original proof, custody, source archive and runtime admission remain unavailable", ErrOriginalSourceProducerHold)

// OriginalActorAdmissionReadOperation authorizes one fixed API in its explicit
// scope. ListBootVolumeAttachments deliberately authorizes compartment-wide
// read inspection; an instanceId query is not an OCI IAM condition.
type OriginalActorAdmissionReadOperation struct {
	Operation    string `json:"operation"`
	ResourceType string `json:"resourceType"`
	Permission   string `json:"permission"`
	Scope        string `json:"scope"`
}

// OriginalActorAdmissionReadIntent is prospective root-signed permission, not
// an extension of an older original birth, launch or public-read policy.
type OriginalActorAdmissionReadIntent struct {
	Purpose              string                                  `json:"purpose"`
	Cell                 string                                  `json:"cell"`
	OCIRegion            string                                  `json:"ociRegion"`
	TenancyID            string                                  `json:"tenancyId"`
	InstallationID       string                                  `json:"installationId"`
	ProducerIntentSHA256 string                                  `json:"producerIntentSha256"`
	ActorOperationID     string                                  `json:"actorOperationId"`
	ActorRecipeSHA256    string                                  `json:"actorRecipeSha256"`
	Home                 bootstrap.StorageDomain                 `json:"home"`
	Objects              [3]string                               `json:"objects"`
	ControlCompartment   string                                  `json:"controlCompartment"`
	NetworkCompartment   string                                  `json:"networkCompartment"`
	ImageCompartment     string                                  `json:"imageCompartment"`
	ImageID              string                                  `json:"imageId"`
	Operations           [12]OriginalActorAdmissionReadOperation `json:"operations"`
}

func originalAdmissionReadOperations() [12]OriginalActorAdmissionReadOperation {
	return [12]OriginalActorAdmissionReadOperation{
		{"GetNamespace", "objectstorage-namespaces", "OBJECTSTORAGE_NAMESPACE_READ", "tenancy"},
		{"GetObject", "objects", "OBJECT_READ", "home-objects"},
		{"GetBucket", "buckets", "BUCKET_READ", "home-bucket"},
		{"GetPolicy", "policies", "POLICY_READ", "original-source-policy"},
		{"GetInstance", "instances", "INSTANCE_READ", "actor-control"},
		{"ListVnicAttachments", "instances", "INSTANCE_INSPECT", "actor-control"},
		{"ListVnicAttachments", "vnic-attachments", "VNIC_ATTACHMENT_READ", "actor-control"},
		{"GetVnic", "vnics", "VNIC_READ", "actor-network"},
		{"GetSubnet", "subnets", "SUBNET_READ", "actor-network"},
		{"ListBootVolumeAttachments", "all-resources", "", "actor-control"},
		{"GetBootVolume", "volumes", "VOLUME_INSPECT", "actor-control"},
		{"GetImage", "instance-images", "INSTANCE_IMAGE_INSPECT", "actor-image"},
	}
}

func originalAdmissionReadRecipe(purpose OriginalSourceProducerIntent, startup bootstrap.StartupTemplate, network string) (OriginalActorAdmissionReadIntent, error) {
	wire, err := json.Marshal(purpose, json.Deterministic(true))
	if err != nil || purpose.Home.Validate() != nil || purpose.JournalObject != foundationObjectPrefix+"GRU.json" || network == "" {
		return OriginalActorAdmissionReadIntent{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return OriginalActorAdmissionReadIntent{Purpose: originalAdmissionReadPurpose, Cell: purpose.Cell, OCIRegion: purpose.OCIRegion,
		TenancyID: purpose.TenancyID, InstallationID: purpose.InstallationID, ProducerIntentSHA256: digestSource(wire),
		ActorOperationID: purpose.OperationID, ActorRecipeSHA256: purpose.Allocation.RecipeSHA256, Home: purpose.Home,
		Objects:            [3]string{purpose.JournalObject, foundationRootChainObject, strings.TrimSuffix(purpose.Home.Prefix, "/") + "/" + foundationGrantObject},
		ControlCompartment: purpose.Profile.CompartmentOCID, NetworkCompartment: network,
		ImageCompartment: originalActorResources(startup).ImageCompartmentOCID, ImageID: purpose.ImageOCID,
		Operations: originalAdmissionReadOperations()}, nil
}

func originalAdmissionReadIntents(grant FoundationGrant, home bootstrap.StorageDomain) ([3]OriginalActorAdmissionReadIntent, error) {
	var intents [3]OriginalActorAdmissionReadIntent
	if grant.SchemaVersion != 3 || grant.Generation != 1 || len(grant.Regions) != 3 || requireOriginalSourceProducerPurposes(grant) != nil {
		return intents, ErrOriginalSourceProducerHold
	}
	for index, cell := range [3]string{"GRU", "SFO", "FRA"} {
		found := false
		for _, regional := range grant.Regions {
			if regional.Plan["cell"] != cell {
				continue
			}
			material := regional.BootstrapMaterial
			if found || material == nil || material.Startup == nil || material.OriginalSourceProducer == nil || material.OriginalSourceProducer.Home != home {
				return intents, ErrOriginalSourceProducerHold
			}
			network, err := preparationResource(regional.Plan, cell, "network_compartment")
			if err != nil {
				return intents, err
			}
			intents[index], err = originalAdmissionReadRecipe(*material.OriginalSourceProducer, *material.Startup, network)
			if err != nil {
				return intents, err
			}
			found = true
		}
		if !found {
			return intents, ErrOriginalSourceProducerHold
		}
	}
	return intents, nil
}

func validateOriginalAdmissionReadIntents(grant FoundationGrant, home bootstrap.StorageDomain) error {
	if grant.OriginalActorAdmissionReads == nil {
		return nil
	}
	expected, err := originalAdmissionReadIntents(grant, home)
	if err != nil || !sameOriginalSourceValue(expected, grant.OriginalActorAdmissionReads) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return nil
}

// OriginalFoundationAdmissionReads records a separately acknowledged original
// operator effect. It is not a local instance, startup or runtime capability.
type OriginalFoundationAdmissionReads struct {
	Recipe              OriginalActorAdmissionReadIntent `json:"recipe"`
	GrantSHA256         string                           `json:"grantSha256"`
	BundleSHA256        string                           `json:"bundleSha256"`
	IntentSHA256        string                           `json:"intentSha256"`
	Generation          uint64                           `json:"generation"`
	OperationID         string                           `json:"operationId"`
	ActorID             string                           `json:"actorId"`
	ActorRequestSHA256  string                           `json:"actorRequestSha256"`
	ActorReadbackSHA256 string                           `json:"actorReadbackSha256"`
	SourceIAMSHA256     string                           `json:"sourceIamSha256"`
	SourcePolicyID      string                           `json:"sourcePolicyId"`
	BucketID            string                           `json:"bucketId"`
	BucketCompartment   string                           `json:"bucketCompartment"`
	ControlCompartment  string                           `json:"controlCompartment"`
	NetworkCompartment  string                           `json:"networkCompartment"`
	ImageCompartment    string                           `json:"imageCompartment"`
	IdentitySHA256      string                           `json:"identitySha256"`
	Request             identity.CreatePolicyDetails     `json:"request"`
	Pending             *PendingFoundationCreate         `json:"pending,omitempty"`
	Provenance          *FoundationResourceProvenance    `json:"provenance,omitempty"`
	ReadbackSHA256      string                           `json:"readbackSha256,omitempty"`
	VerifiedAt          time.Time                        `json:"verifiedAt,omitzero"`
	HoldReason          string                           `json:"holdReason,omitempty"`
}

func completeOriginalAdmissionReadPrerequisites(record FoundationRecord) error {
	if originalActorReadsActors(record) != nil {
		return ErrOriginalSourceProducerHold
	}
	for _, regional := range record.OriginalFoundationCompartments.Regions {
		reads, source := regional.ActorReads, regional.SourceIAM
		if reads == nil || reads.Pending == nil || reads.Provenance == nil || reads.VerifiedAt.IsZero() || reads.ReadbackSHA256 == "" || reads.HoldReason != "" ||
			source == nil || source.Pending == nil || source.Provenance == nil || source.VerifiedAt.IsZero() || source.ReadbackSHA256 == "" || source.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}

func completeOriginalFoundationAdmissionReads(record FoundationRecord) error {
	if completeOriginalAdmissionReadPrerequisites(record) != nil || record.validateOriginalFoundationAdmissionReads() != nil {
		return ErrOriginalSourceProducerHold
	}
	for _, regional := range record.OriginalFoundationCompartments.Regions {
		entry := regional.AdmissionReads
		if entry == nil || entry.Pending == nil || entry.Provenance == nil || entry.ReadbackSHA256 == "" || entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}

func originalAdmissionReadScope(record FoundationRecord, index int, recipe OriginalActorAdmissionReadIntent) (OriginalFoundationAdmissionReads, error) {
	var scope OriginalFoundationAdmissionReads
	if index < 0 || index >= 3 || completeOriginalAdmissionReadPrerequisites(record) != nil {
		return scope, ErrOriginalSourceProducerHold
	}
	root := record.OriginalFoundationCompartments
	regional, birth := root.Regions[index], (*record.OriginalSourceProducers)[index]
	actor, source := regional.Actor, regional.SourceIAM
	network, err := preparationResource(regional.Network.Plan, regional.Cell, "network_compartment")
	if err != nil {
		return scope, err
	}
	expected, err := originalAdmissionReadRecipe(birth.Intent, actor.Startup, network)
	if err != nil || !sameOriginalSourceValue(recipe, expected) || !originalActorRole(regional.Cell, "control_compartment", recipe.ControlCompartment, actor.ControlCompartmentID) ||
		!originalActorRole(regional.Cell, "network_compartment", recipe.NetworkCompartment, regional.Network.CompartmentID) {
		return scope, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	image, err := originalActorImageCompartment(regional.Cell, recipe.ImageCompartment, actor.ControlCompartmentID)
	if err != nil {
		return scope, err
	}
	sourceWire, err := json.Marshal(source, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope = OriginalFoundationAdmissionReads{Recipe: recipe, GrantSHA256: root.GrantSHA256, BundleSHA256: root.BundleSHA256,
		IntentSHA256: regional.IntentSHA256, Generation: regional.Generation, OperationID: regional.OperationID,
		ActorID: originalActorID(actor), ActorRequestSHA256: actor.Pending.Request.RequestDigest, ActorReadbackSHA256: actor.ReadbackSHA256,
		SourceIAMSHA256: digestSource(sourceWire), SourcePolicyID: source.Provenance.ResourceID, BucketID: birth.HeadBucketID,
		BucketCompartment: source.BucketCompartment, ControlCompartment: actor.ControlCompartmentID,
		NetworkCompartment: regional.Network.CompartmentID, ImageCompartment: image}
	wire, err := json.Marshal(scope, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope.IdentitySHA256 = digestSource(wire)
	scope.Request = originalAdmissionReadPolicy(scope)
	return scope, nil
}

func originalAdmissionReadPolicy(scope OriginalFoundationAdmissionReads) identity.CreatePolicyDetails {
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", scope.ActorID)
	statements := []string{}
	for _, operation := range scope.Recipe.Operations {
		conditions := principal + fmt.Sprintf(", request.operation='%s'", operation.Operation)
		if operation.Permission != "" {
			conditions += fmt.Sprintf(", request.permission='%s'", operation.Permission)
		}
		verb, location := "inspect", "compartment id "+scope.ControlCompartment
		switch operation.Scope {
		case "tenancy":
			verb, location = "read", "tenancy"
		case "home-objects":
			for _, key := range scope.Recipe.Objects {
				statements = append(statements, fmt.Sprintf("Allow any-user to read objects in compartment id %s where all {%s, target.bucket.name='%s', target.object.name='%s'}", scope.BucketCompartment, conditions, scope.Recipe.Home.HeadBucket, key))
			}
			continue
		case "home-bucket":
			verb, location = "read", "compartment id "+scope.BucketCompartment
			conditions += fmt.Sprintf(", target.bucket.name='%s'", scope.Recipe.Home.HeadBucket)
		case "original-source-policy":
			location = "compartment id " + scope.BucketCompartment
			conditions += fmt.Sprintf(", target.policy.id='%s'", scope.SourcePolicyID)
		case "actor-network":
			location = "compartment id " + scope.NetworkCompartment
		case "actor-image":
			location = "compartment id " + scope.ImageCompartment
			conditions += fmt.Sprintf(", target.image.id='%s'", scope.Recipe.ImageID)
		}
		if operation.Operation == "GetInstance" || operation.Operation == "ListBootVolumeAttachments" {
			verb = "read"
		}
		statements = append(statements, fmt.Sprintf("Allow any-user to %s %s in %s where all {%s}", verb, operation.ResourceType, location, conditions))
	}
	return identity.CreatePolicyDetails{CompartmentId: new(scope.Recipe.TenancyID), Name: new("ts-original-admission-read-" + scope.IdentitySHA256[:32]),
		Description: new("Prospectively authorized original actor admission observations"), Statements: statements,
		FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}
}

func originalAdmissionReadPrerequisites(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, [3]OriginalFoundationAdmissionReads, time.Time, error) {
	var scopes [3]OriginalFoundationAdmissionReads
	record, etag, _, deadline, err := originalActorReadsPrerequisites(ctx, authority)
	if err != nil || completeOriginalAdmissionReadPrerequisites(record) != nil {
		return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return record, etag, scopes, time.Time{}, ErrOriginalSourceProducerHold
	}
	grant, _, err := reader.verifyOriginalDocument(authority.operator.bundle.GrantWire)
	if err != nil || grant.OriginalActorAdmissionReads == nil || validateOriginalAdmissionReadIntents(grant, authority.domain) != nil {
		return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	iam, err := authority.factory.Identity()
	if err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	for index, regional := range record.OriginalFoundationCompartments.Regions {
		// Reconstruct from independently verified signed material, not record fields.
		material, err := originalActorMaterial(grant, regional.Cell)
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
		actor, err := originalActorScope(record, index, *material.Startup, material.Config)
		if err != nil || !sameOriginalSourceValue(actor, regional.Actor.scopeOnly()) {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		source, err := originalSourceIAMScope(record, index)
		if err != nil || !sameOriginalSourceValue(source, regional.SourceIAM.scopeOnly()) {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		entry := regional.SourceIAM
		response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(entry.Provenance.ResourceID)})
		if err != nil || deref(response.Id) != entry.Provenance.ResourceID || deref(response.CompartmentId) != deref(entry.Request.CompartmentId) ||
			deref(response.Name) != deref(entry.Request.Name) || deref(response.Description) != deref(entry.Request.Description) ||
			response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, entry.Request.Statements) ||
			!sameOriginalSourceValue(response.VersionDate, entry.Request.VersionDate) || !sameOriginalSourceValue(response.FreeformTags, entry.Request.FreeformTags) || !sameOriginalSourceValue(response.DefinedTags, entry.Request.DefinedTags) {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		scopes[index], err = originalAdmissionReadScope(record, index, (*grant.OriginalActorAdmissionReads)[index])
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	return record, etag, scopes, deadline, nil
}

func provisionOriginalFoundationAdmissionReads(ctx context.Context, authority *HomeIAMAuthority) error {
	record, etag, expected, _, err := originalAdmissionReadPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	changed := false
	for index := range expected {
		entry := record.OriginalFoundationCompartments.Regions[index].AdmissionReads
		if entry == nil {
			record.OriginalFoundationCompartments.Regions[index].AdmissionReads = &expected[index]
			changed = true
		} else if !sameOriginalSourceValue(entry.scopeOnly(), expected[index]) {
			return ErrOriginalSourceProducerHold
		}
	}
	if changed {
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	for index := range expected {
		if err := provisionOriginalAdmissionRead(ctx, authority, index); err != nil {
			return err
		}
	}
	if err := retainOriginalFoundationPublication(ctx, authority); err != nil {
		return err
	}
	return ErrOriginalFoundationAdmissionReadsPending
}

func (entry OriginalFoundationAdmissionReads) scopeOnly() OriginalFoundationAdmissionReads {
	entry.Pending, entry.Provenance = nil, nil
	entry.ReadbackSHA256, entry.VerifiedAt, entry.HoldReason = "", time.Time{}, ""
	return entry
}

func originalAdmissionReadCreateIdentity(regional OriginalFoundationCompartmentRegion, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: "actor-admission-read", Region: foundationHomeRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(regional.OperationID, digest)}
}

func originalAdmissionReadDuplicate(record FoundationRecord, index int, id string) bool {
	for other, regional := range record.OriginalFoundationCompartments.Regions {
		if regional.SourceIAM != nil && regional.SourceIAM.Provenance != nil && regional.SourceIAM.Provenance.ResourceID == id ||
			regional.ActorReads != nil && regional.ActorReads.Provenance != nil && regional.ActorReads.Provenance.ResourceID == id ||
			other != index && regional.AdmissionReads != nil && regional.AdmissionReads.Provenance != nil && regional.AdmissionReads.Provenance.ResourceID == id {
			return true
		}
	}
	return false
}

func originalAdmissionReadback(entry OriginalFoundationAdmissionReads) (string, error) {
	if entry.Pending == nil || entry.Provenance == nil {
		return "", ErrOriginalSourceProducerHold
	}
	body, err := foundationWriterPolicyBody(entry.Request)
	if err != nil {
		return "", err
	}
	wire, err := json.Marshal([]string{entry.Provenance.ResourceID, digestSource(body), "ACTIVE"}, json.Deterministic(true))
	return digestSource(wire), err
}

func provisionOriginalAdmissionRead(ctx context.Context, authority *HomeIAMAuthority, index int) error {
	record, etag, scopes, _, err := originalAdmissionReadPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	regional := record.OriginalFoundationCompartments.Regions[index]
	entry := regional.AdmissionReads
	if entry == nil || entry.HoldReason != "" || !sameOriginalSourceValue(entry.scopeOnly(), scopes[index]) {
		return ErrOriginalSourceProducerHold
	}
	body, err := foundationWriterPolicyBody(entry.Request)
	if err != nil {
		return err
	}
	digest := digestSource(body)
	if entry.Pending == nil {
		entry.Pending = &PendingFoundationCreate{OperationID: regional.OperationID, IntentDigest: regional.IntentSHA256,
			FirstAttemptAt: time.Now().UTC(), Request: originalAdmissionReadCreateIdentity(regional, digest)}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	if entry.Provenance == nil && !time.Now().Before(entry.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
		entry.HoldReason = "retry-expired"
		return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
	}
	guard := func(dispatchCtx context.Context) error {
		saved, _, currentScopes, deadline, err := originalAdmissionReadPrerequisites(ociclient.CheckpointContext(ctx), authority)
		if err != nil {
			return err
		}
		current := saved.OriginalFoundationCompartments.Regions[index].AdmissionReads
		if current == nil || current.HoldReason != "" || !sameOriginalSourceValue(current, entry) || !sameOriginalSourceValue(current.scopeOnly(), currentScopes[index]) ||
			current.Pending == nil || current.Pending.Request != originalAdmissionReadCreateIdentity(regional, digest) {
			return ErrOriginalSourceProducerHold
		}
		actual, err := foundationWriterPolicyBody(current.Request)
		if err != nil || !bytes.Equal(actual, body) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if current.Provenance == nil {
			deadline = originalActorDeadline(deadline, current.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime))
		}
		return ociclient.LimitAdmission(dispatchCtx, deadline)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	iam, err := authority.factory.Identity()
	if err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	policyCtx := ociclient.WithRequestGuard(ociclient.WithAuthority(ctx, guard), guard)
	if entry.Provenance == nil {
		// HomeWrite remains advisory; provider revocation is not atomic with dispatch.
		createCtx := ociclient.WithAdmission(policyCtx, func(dispatchCtx context.Context) (func(), error) {
			if err := guard(dispatchCtx); err != nil {
				return nil, err
			}
			return func() {}, nil
		})
		response, err := iam.CreatePolicy(ociclient.RequestContext(createCtx), identity.CreatePolicyRequest{CreatePolicyDetails: entry.Request,
			OpcRetryToken: new(entry.Pending.Request.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil {
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				entry.HoldReason = "create-refused"
				return errors.Join(err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
			}
			return err
		}
		id := deref(response.Id)
		if !validAuxiliaryID("controller_usage_policy", id, "") || originalAdmissionReadDuplicate(record, index, id) {
			entry.HoldReason = "create-unresolved"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: id, Generation: regional.Generation, GrantSHA256: entry.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	if err := guard(ctx); err != nil {
		return err
	}
	response, err := iam.GetPolicy(ociclient.RequestContext(policyCtx), identity.GetPolicyRequest{PolicyId: new(entry.Provenance.ResourceID), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return err
	}
	if deref(response.Id) != entry.Provenance.ResourceID || deref(response.CompartmentId) != deref(entry.Request.CompartmentId) ||
		deref(response.Name) != deref(entry.Request.Name) || deref(response.Description) != deref(entry.Request.Description) ||
		response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, entry.Request.Statements) ||
		!sameOriginalSourceValue(response.VersionDate, entry.Request.VersionDate) || !sameOriginalSourceValue(response.FreeformTags, entry.Request.FreeformTags) || !sameOriginalSourceValue(response.DefinedTags, entry.Request.DefinedTags) {
		entry.HoldReason = "readback-conflict"
		return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
	}
	readback, err := originalAdmissionReadback(*entry)
	if err != nil || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != readback {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if entry.VerifiedAt.IsZero() {
		entry.ReadbackSHA256, entry.VerifiedAt = readback, time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func (record FoundationRecord) validateOriginalFoundationAdmissionReads() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	for index, regional := range root.Regions {
		entry := regional.AdmissionReads
		if entry == nil {
			continue
		}
		expected, err := originalAdmissionReadScope(record, index, entry.Recipe)
		if err != nil || !sameOriginalSourceValue(entry.scopeOnly(), expected) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if entry.Pending == nil {
			if entry.Provenance != nil || entry.ReadbackSHA256 != "" || !entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		body, err := foundationWriterPolicyBody(entry.Request)
		pending := *entry.Pending
		if err != nil || pending.OperationID != regional.OperationID || pending.IntentDigest != regional.IntentSHA256 ||
			pending.Request != originalAdmissionReadCreateIdentity(regional, digestSource(body)) || pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.After(record.UpdatedAt) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		for _, upstream := range root.Regions {
			if pending.FirstAttemptAt.Before(upstream.ActorReads.VerifiedAt) || pending.FirstAttemptAt.Before(upstream.SourceIAM.VerifiedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.HoldReason != "" && !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved", "readback-conflict"}, entry.HoldReason) {
			return ErrOriginalSourceProducerHold
		}
		if entry.Provenance != nil {
			proof := entry.Provenance
			if !sameOriginalSourceValue(proof.Create, pending) || proof.Generation != entry.Generation || proof.GrantSHA256 != entry.GrantSHA256 ||
				!validAuxiliaryID("controller_usage_policy", proof.ResourceID, "") || originalAdmissionReadDuplicate(record, index, proof.ResourceID) ||
				entry.HoldReason != "" && entry.HoldReason != "readback-conflict" {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() &&
			(entry.Provenance == nil || entry.VerifiedAt.Before(pending.FirstAttemptAt) || entry.VerifiedAt.After(record.UpdatedAt)) {
			return ErrOriginalSourceProducerHold
		}
		if entry.ReadbackSHA256 != "" {
			readback, err := originalAdmissionReadback(*entry)
			if err != nil || entry.ReadbackSHA256 != readback {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationAdmissionReads(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		if after != nil {
			for _, regional := range after.Regions {
				if regional.AdmissionReads != nil {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		return nil
	}
	for index, regional := range before.Regions {
		old := regional.AdmissionReads
		if after == nil {
			if old != nil {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		current := after.Regions[index].AdmissionReads
		if old == nil {
			if current != nil {
				expected, err := originalAdmissionReadScope(previous, index, current.Recipe)
				if err != nil || !sameOriginalSourceValue(current, expected) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			continue
		}
		if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) ||
			old.Pending != nil && !sameOriginalSourceValue(old.Pending, current.Pending) || old.Provenance != nil && !sameOriginalSourceValue(old.Provenance, current.Provenance) ||
			old.ReadbackSHA256 != "" && old.ReadbackSHA256 != current.ReadbackSHA256 || !old.VerifiedAt.IsZero() && !old.VerifiedAt.Equal(current.VerifiedAt) ||
			old.HoldReason != "" && old.HoldReason != current.HoldReason {
			return ErrOriginalSourceProducerHold
		}
		// Each effect transition needs its own acknowledged durable predecessor.
		if old.Pending == nil && current.Provenance != nil || old.Provenance == nil && !current.VerifiedAt.IsZero() {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}
