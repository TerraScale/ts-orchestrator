package region

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/oracle/oci-go-sdk/v65/identity"
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

// All actor results must already be durable and complete. This path never
// calls a producer that could create an absent actor or prerequisite.
func originalActorReadsActors(record FoundationRecord) error {
	return rememberOriginalRecordCheck("actor-reads-actors", record, originalActorReadsActorsChecked)
}

func originalActorReadsActorsChecked(record FoundationRecord) error {
	if err := record.validateOriginalFoundationActors(); err != nil {
		return err
	}
	return originalActorReadsActorsFromValidatedActors(record)
}

func originalActorReadsActorsFromValidatedActors(record FoundationRecord) error {
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

func originalActorReadScopeFromPrerequisites(record FoundationRecord, index int, releaseDigest string, origin release.WorkloadGenesis, key, compartment string, bundleBytes int64) (OriginalFoundationActorReads, error) {
	var scope OriginalFoundationActorReads
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

func (record FoundationRecord) validateOriginalFoundationActorReadsFromValidatedActors() error {
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
	if err := originalActorReadsActorsFromValidatedActors(record); err != nil {
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
		expected, err := originalActorReadScopeFromPrerequisites(record, index, entry.ReleaseAuthoritySHA256, origin, key, entry.BucketCompartmentID, entry.BundleBytes)
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
