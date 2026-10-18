package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var ErrOriginalFoundationActorReadsPending = fmt.Errorf("%w: exact original public bundle reads retained; original host entry, local custody, source IAM and archive remain unavailable", ErrOriginalSourceProducerHold)

// OriginalFoundationActorReads records one finite original-operator effect;
// it cannot establish host entry, local custody or runtime authority.
type OriginalFoundationActorReads struct {
	GrantSHA256            string                        `json:"grantSha256"`
	BundleSHA256           string                        `json:"bundleSha256"`
	IntentSHA256           string                        `json:"intentSha256"`
	Generation             uint64                        `json:"generation"`
	OperationID            string                        `json:"operationId"`
	ActorID                string                        `json:"actorId"`
	ActorRequestSHA256     string                        `json:"actorRequestSha256"`
	ActorReadbackSHA256    string                        `json:"actorReadbackSha256"`
	ReleaseAuthoritySHA256 string                        `json:"releaseAuthoritySha256"`
	Origin                 release.WorkloadGenesis       `json:"origin"`
	ObjectKey              string                        `json:"objectKey"`
	BucketID               string                        `json:"bucketId"`
	BucketCompartmentID    string                        `json:"bucketCompartmentId"`
	KMSKeyID               string                        `json:"kmsKeyId"`
	BundleBytes            int64                         `json:"bundleBytes"`
	DocumentReadbackSHA256 string                        `json:"documentReadbackSha256"`
	IdentitySHA256         string                        `json:"identitySha256"`
	Request                identity.CreatePolicyDetails  `json:"request"`
	Pending                *PendingFoundationCreate      `json:"pending,omitempty"`
	Provenance             *FoundationResourceProvenance `json:"provenance,omitempty"`
	ReadbackSHA256         string                        `json:"readbackSha256,omitempty"`
	VerifiedAt             time.Time                     `json:"verifiedAt,omitzero"`
	HoldReason             string                        `json:"holdReason,omitempty"`
}

func provisionOriginalFoundationActorReads(ctx context.Context, authority *HomeIAMAuthority) error {
	if err := retainOriginalFoundationActorReads(ctx, authority); err != nil {
		return err
	}
	grant, err := decodeOriginalMaterialGrant(authority.operator.bundle)
	if err != nil {
		return err
	}
	if grant.OriginalActorAdmissionReads == nil {
		return ErrOriginalFoundationActorReadsPending
	}
	if err := validateOriginalAdmissionReadIntents(grant, authority.domain); err != nil {
		return err
	}
	for index := range 3 {
		if err := retainOriginalSourceIAM(ctx, authority, index); err != nil {
			return err
		}
	}
	return provisionOriginalFoundationAdmissionReads(ctx, authority)
}

func retainOriginalFoundationActorReads(ctx context.Context, authority *HomeIAMAuthority) error {
	record, etag, expected, _, err := originalActorReadsPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	changed := false
	for index := range expected {
		entry := record.OriginalFoundationCompartments.Regions[index].ActorReads
		if entry == nil {
			record.OriginalFoundationCompartments.Regions[index].ActorReads = &expected[index]
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
		if err := provisionOriginalActorRead(ctx, authority, index); err != nil {
			return err
		}
	}
	return nil
}

// All actor results must already be durable and complete. This path never
// calls a producer that could create an absent actor or prerequisite.
func originalActorReadsActors(record FoundationRecord) error {
	if err := record.validateOriginalFoundationActors(); err != nil {
		return err
	}
	if record.OriginalFoundationCompartments == nil || record.OriginalSourceProducers == nil {
		return ErrOriginalSourceProducerHold
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		actor := region.Actor
		if actor == nil || actor.Pending == nil || actor.Provenance == nil || actor.VerifiedAt.IsZero() || actor.ReadbackSHA256 == "" || actor.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}

func originalActorReadsPrerequisites(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, [3]OriginalFoundationActorReads, time.Time, error) {
	var scopes [3]OriginalFoundationActorReads
	if authority == nil || authority.operator == nil {
		return FoundationRecord{}, "", scopes, time.Time{}, ErrOriginalSourceProducerHold
	}
	lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
	if !ok || lease == nil || lease.authority != authority {
		return FoundationRecord{}, "", scopes, time.Time{}, ErrOriginalSourceProducerHold
	}
	// Refuse incomplete actors before invoking any upstream readback path.
	record, _, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil || originalActorReadsActors(record) != nil {
		return record, "", scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	record, etag, grant, expires, err := originalActorPrerequisites(ctx, authority)
	if err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	if err := originalActorReadsActors(record); err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok || reader.storage != authority.domain {
		return record, etag, scopes, time.Time{}, ErrOriginalSourceProducerHold
	}
	if err := ValidateContainerReleaseAuthorities(grant, reader.roots, authority.domain, time.Now()); err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	origins, err := foundationWorkloadGenesis(grant, authority.domain)
	if err != nil || !slices.Equal(origins, grant.WorkloadGenesis) {
		return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	bundle, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil || len(bundle) == 0 || digestSource(bundle) != record.OriginalFoundationCompartments.BundleSHA256 {
		return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	objects, err := authority.factory.ObjectStorage()
	if err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	namespace, err := discoveryNamespace(ctx, &objects, grant.TenancyID)
	if err != nil || namespace != authority.domain.Namespace {
		return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	bucket, err := objects.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(namespace), BucketName: new(authority.domain.HeadBucket)})
	if err != nil || deref(bucket.Namespace) != namespace || deref(bucket.Name) != authority.domain.HeadBucket ||
		deref(bucket.CompartmentId) != authority.bucketCompartment || deref(bucket.KmsKeyId) != authority.domain.HeadKMSKeyOCID ||
		!validAuxiliaryID("head_bucket", deref(bucket.Id), foundationHomeRegion) {
		return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	deadline := originalActorDeadline(expires, authority.operator.deadline)
	for index, region := range record.OriginalFoundationCompartments.Regions {
		actor := region.Actor
		material, err := originalActorMaterial(grant, region.Cell)
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
		expected, err := originalActorScope(record, index, *material.Startup, material.Config)
		if err != nil || !sameOriginalSourceValue(actor.scopeOnly(), expected) {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		proof, imageExpected, err := originalActorImage(ctx, authority, record, index)
		if err != nil || proof.ValidFor(imageExpected, time.Now()) != nil {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		regional, err := authority.factory.ForRegion(region.OCIRegion)
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
		boot, vnic, err := readOriginalActor(ctx, regional, region, actor)
		if err != nil || boot != actor.BootVolumeID || vnic != actor.PrimaryVNICID {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		readback, err := originalActorReadback(actor, boot, vnic)
		if err != nil || readback != actor.ReadbackSHA256 {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		selected, delegationExpires, err := originalActorReadRelease(grant, region.Cell)
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
		origin, key, err := originalActorReadOrigin(record, index, grant)
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
		birth := (*record.OriginalSourceProducers)[index]
		if deref(bucket.Id) != birth.HeadBucketID || origin.Namespace != namespace || origin.Bucket != deref(bucket.Name) {
			return record, etag, scopes, time.Time{}, ErrOriginalSourceProducerHold
		}
		published, err := readDiscoveryObject(ctx, &objects, namespace, key, int64(len(bundle)))
		if err != nil || !bytes.Equal(published, bundle) || digestSource(published) != birth.OriginalBundleSHA256 {
			return record, etag, scopes, time.Time{}, errors.Join(ErrOriginalSourceProducerHold, err)
		}
		scopes[index], err = originalActorReadScope(record, index, selected, origin, key, deref(bucket.CompartmentId), int64(len(bundle)))
		if err != nil {
			return record, etag, scopes, time.Time{}, err
		}
		deadline = originalActorDeadline(deadline, proof.ExpiresAt(), actor.Startup.FounderResources.LaunchDeadline, delegationExpires)
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	lease.mu.Lock()
	deadline = originalActorDeadline(deadline, lease.record.ExpiresAt)
	lease.mu.Unlock()
	if err := ociclient.LimitAdmission(ctx, deadline); err != nil {
		return record, etag, scopes, time.Time{}, err
	}
	return record, etag, scopes, deadline, nil
}

func originalActorReadRelease(grant FoundationGrant, cell string) (string, time.Time, error) {
	var selected *ContainerReleaseAuthorityIntent
	for index := range grant.ReleaseAuthorities {
		candidate := &grant.ReleaseAuthorities[index]
		if candidate.Role != "ts-auth" || candidate.Environment != "production" || !slices.Contains(candidate.Cells, cell) {
			continue
		}
		if selected != nil {
			return "", time.Time{}, ErrOriginalSourceProducerHold
		}
		selected = candidate
	}
	if selected == nil {
		return "", time.Time{}, ErrOriginalSourceProducerHold
	}
	wire, err := json.Marshal(selected, json.Deterministic(true))
	if err != nil {
		return "", time.Time{}, err
	}
	envelope, err := trust.DecodeEnvelope(selected.DelegationWire)
	if err != nil {
		return "", time.Time{}, err
	}
	return digestSource(wire), envelope.ExpiresAt, nil
}

func originalActorReadOrigin(record FoundationRecord, index int, grant FoundationGrant) (release.WorkloadGenesis, string, error) {
	var selected release.WorkloadGenesis
	region := record.OriginalFoundationCompartments.Regions[index]
	q := (*record.OriginalSourceProducers)[index].Intent
	for _, origin := range grant.WorkloadGenesis {
		if origin.Cell != region.Cell || origin.Role != "ts-auth" || origin.Environment != "production" {
			continue
		}
		if selected.Schema != "" {
			return selected, "", ErrOriginalSourceProducerHold
		}
		selected = origin
	}
	if selected.Validate() != nil || selected.TenancyID != record.TenancyID || selected.InstallationID != q.InstallationID ||
		selected.DeploymentID != q.DeploymentID || selected.ClusterID != q.ClusterID || selected.Environment != q.Environment ||
		selected.Namespace != q.Home.Namespace || selected.Bucket != q.Home.HeadBucket {
		return selected, "", ErrOriginalSourceProducerHold
	}
	key, err := release.WorkloadGenesisObject(selected.TenancyID, selected.Cell, selected.Environment, selected.Role)
	if err != nil || !slices.Contains((*record.OriginalSourceProducers)[index].OriginObjects[:], key) {
		return selected, "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return selected, key, nil
}

func originalActorReadScope(record FoundationRecord, index int, releaseDigest string, origin release.WorkloadGenesis, key, compartment string, bundleBytes int64) (OriginalFoundationActorReads, error) {
	var scope OriginalFoundationActorReads
	if err := originalActorReadsActors(record); err != nil {
		return scope, err
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	actor := region.Actor
	birth := (*record.OriginalSourceProducers)[index]
	scope = OriginalFoundationActorReads{GrantSHA256: birth.OriginalGrantSHA256, BundleSHA256: birth.OriginalBundleSHA256,
		IntentSHA256: region.IntentSHA256, Generation: region.Generation, OperationID: region.OperationID,
		ActorID: originalActorID(actor), ActorRequestSHA256: actor.Pending.Request.RequestDigest, ActorReadbackSHA256: actor.ReadbackSHA256,
		ReleaseAuthoritySHA256: releaseDigest, Origin: origin, ObjectKey: key, BucketID: birth.HeadBucketID, BucketCompartmentID: compartment,
		KMSKeyID: birth.Intent.Home.HeadKMSKeyOCID, BundleBytes: bundleBytes}
	wire, err := json.Marshal([]string{scope.GrantSHA256, scope.BundleSHA256, region.Cell, scope.ActorID, origin.Namespace, origin.Bucket, key}, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope.IdentitySHA256 = digestSource(wire)
	scope.DocumentReadbackSHA256, err = originalActorReadDocument(scope)
	if err != nil {
		return scope, err
	}
	scope.Request = originalActorReadPolicy(scope)
	return scope, nil
}

func originalActorReadPolicy(scope OriginalFoundationActorReads) identity.CreatePolicyDetails {
	statement := fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.bucket.name='%s', target.object.name='%s', request.permission='OBJECT_READ'}", scope.BucketCompartmentID, scope.ActorID, scope.Origin.Bucket, scope.ObjectKey)
	return identity.CreatePolicyDetails{CompartmentId: new(scope.BucketCompartmentID), Name: new("ts-original-actor-read-" + scope.IdentitySHA256[:32]),
		Description: new("Original actor reads one exact original public foundation bundle"), Statements: []string{statement},
		FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}
}

func originalActorReadDocument(scope OriginalFoundationActorReads) (string, error) {
	wire, err := json.Marshal(struct {
		Origin                                               release.WorkloadGenesis
		Key, BucketID, CompartmentID, KMSKeyID, BundleSHA256 string
		Bytes                                                int64
	}{scope.Origin, scope.ObjectKey, scope.BucketID, scope.BucketCompartmentID, scope.KMSKeyID, scope.BundleSHA256, scope.BundleBytes}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func (scope OriginalFoundationActorReads) scopeOnly() OriginalFoundationActorReads {
	scope.Pending, scope.Provenance = nil, nil
	scope.ReadbackSHA256, scope.VerifiedAt, scope.HoldReason = "", time.Time{}, ""
	return scope
}

func originalActorReadCreateIdentity(region OriginalFoundationCompartmentRegion, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: "actor-public-read", Region: foundationHomeRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(region.OperationID, digest)}
}

func provisionOriginalActorRead(ctx context.Context, authority *HomeIAMAuthority, index int) error {
	record, etag, scopes, _, err := originalActorReadsPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	entry := region.ActorReads
	if entry == nil || entry.HoldReason != "" || !sameOriginalSourceValue(entry.scopeOnly(), scopes[index]) {
		return ErrOriginalSourceProducerHold
	}
	body, err := foundationWriterPolicyBody(entry.Request)
	if err != nil {
		return err
	}
	digest := digestSource(body)
	if entry.Provenance == nil && entry.Pending == nil {
		entry.Pending = &PendingFoundationCreate{OperationID: region.OperationID, IntentDigest: region.IntentSHA256, FirstAttemptAt: time.Now().UTC(), Request: originalActorReadCreateIdentity(region, digest)}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	if entry.Provenance == nil && !time.Now().Before(entry.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
		entry.HoldReason = "retry-expired"
		return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
	}
	guard := func(dispatchCtx context.Context) error {
		// Use the captured base context so policy request guards cannot recurse
		// through the authenticated prerequisite and checkpoint reads.
		checkCtx := ociclient.CheckpointContext(ctx)
		saved, _, currentScopes, deadline, err := originalActorReadsPrerequisites(checkCtx, authority)
		if err != nil {
			return err
		}
		current := saved.OriginalFoundationCompartments.Regions[index].ActorReads
		if current == nil || current.HoldReason != "" || !sameOriginalSourceValue(current, entry) || !sameOriginalSourceValue(current.scopeOnly(), currentScopes[index]) {
			return ErrOriginalSourceProducerHold
		}
		actual, err := foundationWriterPolicyBody(current.Request)
		if err != nil || !bytes.Equal(actual, body) || current.Pending == nil || current.Pending.Request != originalActorReadCreateIdentity(region, digest) {
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
	home, err := authority.factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	policyCtx := ociclient.WithRequestGuard(ociclient.WithAuthority(ctx, guard), guard)
	if entry.Provenance == nil {
		// The advisory lease cannot fence a paused provider send; source review
		// does not activate the separate live dispatch contract.
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
		if !validAuxiliaryID("controller_usage_policy", id, "") || originalActorReadDuplicate(record, index, id) {
			entry.HoldReason = "create-unresolved"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: id, Generation: region.Generation, GrantSHA256: entry.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	if err := guard(ctx); err != nil {
		return err
	}
	response, err := iam.GetPolicy(ociclient.RequestContext(policyCtx), identity.GetPolicyRequest{PolicyId: new(entry.Provenance.ResourceID), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
			entry.HoldReason = "readback-unavailable"
			return errors.Join(err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		return err
	}
	if deref(response.Id) != entry.Provenance.ResourceID || deref(response.CompartmentId) != entry.BucketCompartmentID ||
		deref(response.Name) != deref(entry.Request.Name) || deref(response.Description) != deref(entry.Request.Description) ||
		response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, entry.Request.Statements) || len(response.FreeformTags) != 0 || len(response.DefinedTags) != 0 {
		entry.HoldReason = "readback-conflict"
		return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
	}
	readback, err := originalActorPolicyReadback(*entry)
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

func originalActorReadDuplicate(record FoundationRecord, index int, id string) bool {
	for other, region := range record.OriginalFoundationCompartments.Regions {
		if other != index && region.ActorReads != nil && region.ActorReads.Provenance != nil && region.ActorReads.Provenance.ResourceID == id {
			return true
		}
	}
	return false
}

func originalActorPolicyReadback(entry OriginalFoundationActorReads) (string, error) {
	if entry.Provenance == nil {
		return "", ErrOriginalSourceProducerHold
	}
	body, err := foundationWriterPolicyBody(entry.Request)
	if err != nil {
		return "", err
	}
	wire, err := json.Marshal([]string{entry.Provenance.ResourceID, digestSource(body), "ACTIVE"}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func (record FoundationRecord) validateOriginalFoundationActorReads() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	attached := 0
	for _, region := range root.Regions {
		if region.ActorReads != nil {
			attached++
		}
	}
	if attached == 0 {
		return nil
	}
	if attached != 3 {
		return ErrOriginalSourceProducerHold
	}
	if err := originalActorReadsActors(record); err != nil {
		return err
	}
	notBefore := root.BornAt
	for _, region := range root.Regions {
		if region.Actor.VerifiedAt.After(notBefore) {
			notBefore = region.Actor.VerifiedAt
		}
	}
	for index, region := range root.Regions {
		entry := region.ActorReads
		q := (*record.OriginalSourceProducers)[index].Intent
		origin := entry.Origin
		key, err := release.WorkloadGenesisObject(record.TenancyID, region.Cell, q.Environment, "ts-auth")
		if err != nil || origin.Validate() != nil || origin.TenancyID != record.TenancyID || origin.InstallationID != q.InstallationID || origin.DeploymentID != q.DeploymentID ||
			origin.ClusterID != q.ClusterID || origin.Cell != region.Cell || origin.Environment != q.Environment || origin.Environment != "production" || origin.Role != "ts-auth" ||
			origin.Namespace != q.Home.Namespace || origin.Bucket != q.Home.HeadBucket || entry.ObjectKey != key || !slices.Contains((*record.OriginalSourceProducers)[index].OriginObjects[:], key) ||
			!sourceCompartmentPattern.MatchString(entry.BucketCompartmentID) || len(entry.BucketCompartmentID) > 512 || entry.BucketCompartmentID != q.Escrow.CompartmentOCID ||
			!validFoundationDigest(entry.ReleaseAuthoritySHA256) || entry.BundleBytes <= 0 {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		expected, err := originalActorReadScope(record, index, entry.ReleaseAuthoritySHA256, origin, key, entry.BucketCompartmentID, entry.BundleBytes)
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
		if err != nil || pending.OperationID != region.OperationID || pending.IntentDigest != region.IntentSHA256 || pending.Request != originalActorReadCreateIdentity(region, digestSource(body)) ||
			pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.Before(notBefore) || pending.FirstAttemptAt.After(record.UpdatedAt) || !pending.FirstAttemptAt.Before(q.LaunchDeadline) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if entry.Provenance != nil {
			proof := entry.Provenance
			if !sameOriginalSourceValue(proof.Create, pending) || proof.Generation != region.Generation || proof.GrantSHA256 != root.GrantSHA256 ||
				!validAuxiliaryID("controller_usage_policy", proof.ResourceID, "") || originalActorReadDuplicate(record, index, proof.ResourceID) {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.HoldReason != "" {
			if entry.Provenance == nil && !slices.Contains([]string{"create-refused", "create-unresolved", "retry-expired"}, entry.HoldReason) ||
				entry.Provenance != nil && !slices.Contains([]string{"readback-unavailable", "readback-conflict"}, entry.HoldReason) {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.VerifiedAt.IsZero() {
			if entry.ReadbackSHA256 != "" {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		readback, err := originalActorPolicyReadback(*entry)
		if err != nil || entry.Provenance == nil || entry.VerifiedAt.Before(pending.FirstAttemptAt) || entry.VerifiedAt.After(record.UpdatedAt) || entry.ReadbackSHA256 != readback {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationActorReads(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		if after != nil {
			for _, region := range after.Regions {
				if region.ActorReads != nil {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		return nil
	}
	for index, region := range before.Regions {
		old := region.ActorReads
		if after == nil {
			if old != nil {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		current := after.Regions[index].ActorReads
		if old == nil {
			if current != nil && (originalActorReadsActors(previous) != nil || !sameOriginalSourceValue(current, current.scopeOnly())) {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) || old.Pending != nil && !sameOriginalSourceValue(old.Pending, current.Pending) ||
			old.Provenance != nil && !sameOriginalSourceValue(old.Provenance, current.Provenance) || old.ReadbackSHA256 != "" && old.ReadbackSHA256 != current.ReadbackSHA256 ||
			!old.VerifiedAt.IsZero() && !old.VerifiedAt.Equal(current.VerifiedAt) || old.HoldReason != "" && old.HoldReason != current.HoldReason {
			return ErrOriginalSourceProducerHold
		}
		// Each effect transition needs its own acknowledged durable predecessor.
		if old.Pending == nil && current.Provenance != nil || old.Provenance == nil && !current.VerifiedAt.IsZero() {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}
