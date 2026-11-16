package region

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// OriginalFoundationSourceIAM is an original-operator effect, never a local
// SourceFounder, selected inventory or generic foundation IAM capability.
type OriginalFoundationSourceIAM struct {
	GrantSHA256       string                        `json:"grantSha256"`
	BundleSHA256      string                        `json:"bundleSha256"`
	IntentSHA256      string                        `json:"intentSha256"`
	BirthSHA256       string                        `json:"birthSha256"`
	Generation        uint64                        `json:"generation"`
	OperationID       string                        `json:"operationId"`
	Cell              string                        `json:"cell"`
	InstanceID        string                        `json:"instanceId"`
	ActorSHA256       string                        `json:"actorSha256"`
	Namespace         string                        `json:"namespace"`
	Bucket            string                        `json:"bucket"`
	BucketID          string                        `json:"bucketId"`
	BucketCompartment string                        `json:"bucketCompartment"`
	Object            string                        `json:"object"`
	SecretName        string                        `json:"secretName"`
	Escrow            bootstrapmaterial.VaultTarget `json:"escrow"`
	Request           identity.CreatePolicyDetails  `json:"request"`
	Pending           *PendingFoundationCreate      `json:"pending,omitempty"`
	Provenance        *FoundationResourceProvenance `json:"provenance,omitempty"`
	ReadbackSHA256    string                        `json:"readbackSha256,omitempty"`
	VerifiedAt        time.Time                     `json:"verifiedAt,omitzero"`
	HoldReason        string                        `json:"holdReason,omitempty"`
}

func completeOriginalSourceIAMActors(record FoundationRecord) error {
	if record.OriginalFoundationCompartments == nil || record.validateOriginalFoundationActors() != nil {
		return ErrOriginalSourceProducerHold
	}
	return completeOriginalSourceIAMActorsFromValidatedActors(record)
}

func completeOriginalSourceIAMActorsFromValidatedActors(record FoundationRecord) error {
	if record.OriginalFoundationCompartments == nil {
		return ErrOriginalSourceProducerHold
	}
	for _, region := range record.OriginalFoundationCompartments.Regions {
		a := region.Actor
		if a == nil || a.Pending == nil || a.Provenance == nil || a.ReadbackSHA256 == "" || a.VerifiedAt.IsZero() || a.BootVolumeID == "" || a.PrimaryVNICID == "" || a.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}

func originalSourceIAMScope(record FoundationRecord, index int) (OriginalFoundationSourceIAM, error) {
	var scope OriginalFoundationSourceIAM
	if index < 0 || index >= 3 || record.OriginalSourceProducers == nil || completeOriginalSourceIAMActors(record) != nil {
		return scope, ErrOriginalSourceProducerHold
	}
	return originalSourceIAMScopeFromActors(record, index)
}

func originalSourceIAMScopeFromActors(record FoundationRecord, index int) (OriginalFoundationSourceIAM, error) {
	var scope OriginalFoundationSourceIAM
	root := record.OriginalFoundationCompartments
	region, birth := root.Regions[index], (*record.OriginalSourceProducers)[index]
	q := birth.Intent
	birthWire, err := json.Marshal(birth, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	actorWire, err := json.Marshal(region.Actor, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	if q.Home.Validate() != nil || q.Escrow.CompartmentOCID != originalCompartmentID(root.Regions[0].Compartments[0]) || q.Escrow != (*record.OriginalSourceProducers)[0].Intent.Escrow || birth.HeadBucketID != record.AuxiliaryIDs["head_bucket"] {
		return scope, ErrOriginalSourceProducerHold
	}
	scope = OriginalFoundationSourceIAM{GrantSHA256: root.GrantSHA256, BundleSHA256: root.BundleSHA256, IntentSHA256: region.ProducerIntentSHA256,
		BirthSHA256: digestSource(birthWire), Generation: region.Generation, OperationID: q.OperationID, Cell: region.Cell,
		InstanceID: originalActorID(region.Actor), ActorSHA256: digestSource(actorWire), Namespace: q.Home.Namespace, Bucket: q.Home.HeadBucket,
		BucketID: birth.HeadBucketID, BucketCompartment: q.Escrow.CompartmentOCID, Object: q.SourceObject, SecretName: q.SourceSecretName, Escrow: q.Escrow}
	statements, err := ociregion.BootstrapSourceStatements(scope.InstanceID, scope.SecretName, vaultsecret.Target{CompartmentID: scope.Escrow.CompartmentOCID, VaultID: scope.Escrow.VaultOCID, KeyID: scope.Escrow.KMSKeyOCID})
	if err != nil {
		return scope, err
	}
	condition := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s', target.bucket.name='%s', target.object.name='%s'", scope.InstanceID, scope.Bucket, scope.Object)
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE', request.permission='OBJECT_READ'}}", scope.BucketCompartment, condition))
	key := sourcePolicyKey(scope.Namespace, scope.Bucket, scope.Object)
	scope.Request = identity.CreatePolicyDetails{CompartmentId: new(scope.Escrow.CompartmentOCID), Name: new("ts-bootstrap-source-" + key[:32]), Description: new("Exact founder source escrow and registration"), Statements: statements}
	return scope, nil
}

func (entry OriginalFoundationSourceIAM) scopeOnly() OriginalFoundationSourceIAM {
	entry.Pending, entry.Provenance = nil, nil
	entry.ReadbackSHA256, entry.VerifiedAt, entry.HoldReason = "", time.Time{}, ""
	return entry
}

func originalSourceIAMRequestSHA(details identity.CreatePolicyDetails) (string, error) {
	r, err := (identity.CreatePolicyRequest{CreatePolicyDetails: details}).HTTPRequest(http.MethodPost, "/20160918/policies", nil, nil)
	if err != nil || r.Body == nil {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	defer r.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(wire) > 16384 {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		return "", err
	}
	wire, err = json.Marshal(body, json.Deterministic(true))
	return digestSource(wire), err
}

func originalSourceIAMCreateIdentity(entry OriginalFoundationSourceIAM, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: "original-source-policy", Region: foundationHomeRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(entry.OperationID, digest)}
}

func originalSourceIAMReadback(entry OriginalFoundationSourceIAM) (string, error) {
	if entry.Pending == nil || entry.Provenance == nil {
		return "", ErrOriginalSourceProducerHold
	}
	wire, err := json.Marshal([]string{entry.Provenance.ResourceID, entry.Pending.Request.RequestDigest, "ACTIVE"}, json.Deterministic(true))
	return digestSource(wire), err
}

func (record FoundationRecord) validateOriginalFoundationSourceIAMFromValidatedActors() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	for _, region := range root.Regions {
		if region.SourceIAM != nil {
			if err := completeOriginalSourceIAMActorsFromValidatedActors(record); err != nil {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
			break
		}
	}
	seen := map[string]bool{}
	for index, region := range root.Regions {
		entry := region.SourceIAM
		if entry == nil {
			continue
		}
		expected, err := originalSourceIAMScopeFromActors(record, index)
		if err != nil || !sameOriginalSourceValue(entry.scopeOnly(), expected) || entry.Pending == nil {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		digest, err := originalSourceIAMRequestSHA(entry.Request)
		p := *entry.Pending
		if err != nil || p.OperationID != entry.OperationID || p.IntentDigest != entry.IntentSHA256 || p.Request != originalSourceIAMCreateIdentity(*entry, digest) || p.FirstAttemptAt.IsZero() || p.FirstAttemptAt.After(record.UpdatedAt) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		for _, actorRegion := range root.Regions {
			if p.FirstAttemptAt.Before(actorRegion.Actor.VerifiedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.HoldReason != "" && (entry.Provenance != nil || !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved"}, entry.HoldReason)) {
			return ErrOriginalSourceProducerHold
		}
		if entry.Provenance != nil {
			proof := entry.Provenance
			if !sameOriginalSourceValue(proof.Create, p) || proof.Generation != entry.Generation || proof.GrantSHA256 != entry.GrantSHA256 || !validAuxiliaryID("controller_usage_policy", proof.ResourceID, "") || seen[proof.ResourceID] {
				return ErrOriginalSourceProducerHold
			}
			seen[proof.ResourceID] = true
		}
		if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() && (entry.Provenance == nil || entry.VerifiedAt.Before(p.FirstAttemptAt) || entry.VerifiedAt.After(record.UpdatedAt)) {
			return ErrOriginalSourceProducerHold
		}
		if entry.ReadbackSHA256 != "" {
			digest, err := originalSourceIAMReadback(*entry)
			if err != nil || digest != entry.ReadbackSHA256 {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationSourceIAM(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		if after != nil {
			for _, region := range after.Regions {
				if region.SourceIAM != nil {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		return nil
	}
	for index, region := range before.Regions {
		old := region.SourceIAM
		if old == nil {
			if after != nil && after.Regions[index].SourceIAM != nil {
				current := after.Regions[index].SourceIAM
				expected, err := originalSourceIAMScope(previous, index)
				if err != nil || !sameOriginalSourceValue(current.scopeOnly(), expected) || current.Pending == nil || current.Provenance != nil || current.ReadbackSHA256 != "" || !current.VerifiedAt.IsZero() || current.HoldReason != "" {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			continue
		}
		if after == nil {
			return ErrOriginalSourceProducerHold
		}
		current := after.Regions[index].SourceIAM
		if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) || !sameOriginalSourceValue(old.Pending, current.Pending) || old.Provenance != nil && !sameOriginalSourceValue(old.Provenance, current.Provenance) || old.ReadbackSHA256 != "" && old.ReadbackSHA256 != current.ReadbackSHA256 || !old.VerifiedAt.IsZero() && !old.VerifiedAt.Equal(current.VerifiedAt) || old.HoldReason != "" && old.HoldReason != current.HoldReason {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}
