package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

var ErrOriginalFoundationSourceIAMPending = fmt.Errorf("%w: original seed source IAM retained; local custody, source archive and runtime admission remain unavailable", ErrOriginalSourceProducerHold)

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

func ProvisionOriginalFoundationSourceIAM(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, bundle RetainedFoundation) error {
	if err := VerifyFoundationProvisionBundle(ctx, roots, bundle); err != nil {
		return err
	}
	authority, _, err := newOperatorHomeIAMAuthority(ctx, factory, roots, bundle)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, authority.operator.deadline)
	defer cancel()
	record, _, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil || completeOriginalSourceIAMActors(record) != nil {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	expected, err := originalCompartmentScope(ctx, authority)
	if err != nil || !sameOriginalSourceValue(record.OriginalFoundationCompartments.scopeOnly(), expected) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	for index := range 3 {
		if err := retainOriginalSourceIAM(ctx, authority, index); err != nil {
			return err
		}
	}
	grant, err := decodeOriginalMaterialGrant(bundle)
	if err != nil {
		return err
	}
	if grant.OriginalActorAdmissionReads == nil {
		return ErrOriginalFoundationSourceIAMPending
	}
	return provisionOriginalFoundationAdmissionReads(ctx, authority)
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

func originalSourceIAMAuthority(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, error) {
	record, _, _, _, err := originalActorPrerequisites(ctx, authority)
	if err != nil || completeOriginalSourceIAMActors(record) != nil {
		return record, "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for index := range 3 {
		if err := retainOriginalActorReadback(ctx, authority, record, index); err != nil {
			return record, "", err
		}
	}
	bucket, err := authority.objects.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(authority.domain.Namespace), BucketName: new(authority.domain.HeadBucket)})
	if err != nil || deref(bucket.Id) != record.AuxiliaryIDs["head_bucket"] || deref(bucket.Name) != authority.domain.HeadBucket || deref(bucket.Namespace) != authority.domain.Namespace || deref(bucket.KmsKeyId) != authority.domain.HeadKMSKeyOCID || deref(bucket.CompartmentId) != authority.bucketCompartment || authority.bucketCompartment != (*record.OriginalSourceProducers)[0].Intent.Escrow.CompartmentOCID {
		return record, "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return authority.resolver.Store.Load(ctx, "GRU")
}

func originalSourceIAMAbsent(ctx context.Context, authority *HomeIAMAuthority, iam identity.IdentityClient, entry OriginalFoundationSourceIAM) error {
	_, err := authority.objects.HeadObject(ociclient.RequestContext(ctx), objectstorage.HeadObjectRequest{NamespaceName: new(entry.Namespace), BucketName: new(entry.Bucket), ObjectName: new(entry.Object)})
	service, absent := common.IsServiceError(err)
	if !absent || service.GetHTTPStatusCode() != http.StatusNotFound {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	client, err := vault.NewVaultsClientWithConfigurationProvider(authority.factory.Provider())
	if err != nil {
		return err
	}
	client.SetRegion(foundationHomeRegion)
	authority.factory.Configure(&client.BaseClient, ociclient.ServiceKMS)
	request := vault.ListSecretsRequest{CompartmentId: new(entry.Escrow.CompartmentOCID), VaultId: new(entry.Escrow.VaultOCID), Name: new(entry.SecretName), Limit: new(100)}
	seen := map[string]bool{}
	for range 32 {
		response, err := client.ListSecrets(ociclient.RequestContext(ctx), request)
		if err != nil {
			return err
		}
		for _, item := range response.Items {
			if deref(item.SecretName) == entry.SecretName {
				return ErrOriginalSourceProducerHold
			}
		}
		page := deref(response.OpcNextPage)
		if page == "" {
			return originalSourceIAMPolicyAbsent(ctx, iam, entry.Request)
		}
		if seen[page] {
			return ErrOriginalSourceProducerHold
		}
		seen[page], request.Page = true, new(page)
	}
	return ErrOriginalSourceProducerHold
}

func originalSourceIAMPolicyAbsent(ctx context.Context, iam identity.IdentityClient, details identity.CreatePolicyDetails) error {
	request := identity.ListPoliciesRequest{CompartmentId: details.CompartmentId, Name: details.Name, Limit: new(100)}
	seen := map[string]bool{}
	for range 32 {
		response, err := iam.ListPolicies(ociclient.RequestContext(ctx), request)
		if err != nil {
			return err
		}
		for _, row := range response.Items {
			if deref(row.Name) == deref(details.Name) {
				return ErrOriginalSourceProducerHold
			}
		}
		page := deref(response.OpcNextPage)
		if page == "" {
			return nil
		}
		if seen[page] {
			return ErrOriginalSourceProducerHold
		}
		seen[page], request.Page = true, new(page)
	}
	return ErrOriginalSourceProducerHold
}

func retainOriginalSourceIAM(ctx context.Context, authority *HomeIAMAuthority, index int) error {
	record, etag, err := originalSourceIAMAuthority(ctx, authority)
	if err != nil {
		return err
	}
	expected, err := originalSourceIAMScope(record, index)
	if err != nil {
		return err
	}
	iam, err := authority.factory.Identity()
	if err != nil {
		return err
	}
	entry := record.OriginalFoundationCompartments.Regions[index].SourceIAM
	if entry == nil {
		if err := originalSourceIAMAbsent(ctx, authority, iam, expected); err != nil {
			return err
		}
		initial := expected
		entry = &initial
		record.OriginalFoundationCompartments.Regions[index].SourceIAM = entry
	} else if !sameOriginalSourceValue(entry.scopeOnly(), expected) {
		return ErrOriginalSourceProducerHold
	}
	if entry.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	if entry.Provenance == nil {
		digest, err := originalSourceIAMRequestSHA(entry.Request)
		if err != nil {
			return err
		}
		if entry.Pending == nil {
			if err := originalSourceIAMAbsent(ctx, authority, iam, *entry); err != nil {
				return err
			}
			entry.Pending = &PendingFoundationCreate{OperationID: entry.OperationID, IntentDigest: entry.IntentSHA256, FirstAttemptAt: time.Now().UTC(), Request: originalSourceIAMCreateIdentity(*entry, digest)}
			if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
				return err
			}
		}
		pending := *entry.Pending
		if !time.Now().Before(pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
			entry.HoldReason = "retry-expired"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		guard := func(sendCtx context.Context) error {
			checkCtx := ociclient.CheckpointContext(sendCtx)
			saved, currentETag, err := originalSourceIAMAuthority(checkCtx, authority)
			if err != nil {
				return err
			}
			current := saved.OriginalFoundationCompartments.Regions[index].SourceIAM
			if currentETag != etag || current == nil || !sameOriginalSourceValue(current.scopeOnly(), expected) || !sameOriginalSourceValue(current.Pending, pending) || current.Provenance != nil || current.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			if err := originalSourceIAMAbsent(checkCtx, authority, iam, *current); err != nil {
				return err
			}
			if err := authority.Guard(checkCtx, 0); err != nil {
				return err
			}
			lease, ok := checkCtx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
			if !ok || lease == nil || lease.authority != authority {
				return ErrOriginalSourceProducerHold
			}
			lease.mu.Lock()
			leaseExpiry := lease.record.ExpiresAt
			lease.mu.Unlock()
			for _, deadline := range []time.Time{authority.operator.deadline, pending.FirstAttemptAt.Add(bootstrapRetryLifetime), leaseExpiry} {
				if err := ociclient.LimitAdmission(sendCtx, deadline); err != nil {
					return err
				}
			}
			return nil
		}
		if err := guard(ctx); err != nil {
			return err
		}
		// HomeWrite is advisory; provider-side remote revocation is not atomic.
		noRetry := common.NoRetryPolicy()
		response, err := iam.CreatePolicy(ociclient.RequestContext(ociclient.WithAuthority(ctx, guard)), identity.CreatePolicyRequest{CreatePolicyDetails: entry.Request, OpcRetryToken: new(pending.Request.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil {
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				entry.HoldReason = "create-refused"
				return errors.Join(err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
			}
			return err
		}
		id := deref(response.Id)
		if !validAuxiliaryID("controller_usage_policy", id, "") {
			entry.HoldReason = "create-unresolved"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		entry.Provenance = &FoundationResourceProvenance{Create: pending, ResourceID: id, Generation: entry.Generation, GrantSHA256: entry.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(entry.Provenance.ResourceID)})
	if err != nil {
		return err
	}
	if deref(response.Id) != entry.Provenance.ResourceID || deref(response.CompartmentId) != deref(entry.Request.CompartmentId) || deref(response.Name) != deref(entry.Request.Name) || deref(response.Description) != deref(entry.Request.Description) || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, entry.Request.Statements) || !sameOriginalSourceValue(response.VersionDate, entry.Request.VersionDate) || !sameOriginalSourceValue(response.FreeformTags, entry.Request.FreeformTags) || !sameOriginalSourceValue(response.DefinedTags, entry.Request.DefinedTags) {
		return ErrOriginalSourceProducerHold
	}
	readback, err := originalSourceIAMReadback(*entry)
	if err != nil || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != readback {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if entry.VerifiedAt.IsZero() {
		entry.ReadbackSHA256, entry.VerifiedAt = readback, time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func originalSourceIAMReadback(entry OriginalFoundationSourceIAM) (string, error) {
	if entry.Pending == nil || entry.Provenance == nil {
		return "", ErrOriginalSourceProducerHold
	}
	wire, err := json.Marshal([]string{entry.Provenance.ResourceID, entry.Pending.Request.RequestDigest, "ACTIVE"}, json.Deterministic(true))
	return digestSource(wire), err
}

func (record FoundationRecord) validateOriginalFoundationSourceIAM() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	for _, region := range root.Regions {
		if region.SourceIAM != nil {
			if err := completeOriginalSourceIAMActors(record); err != nil {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
			break
		}
	}
	return record.validateOriginalFoundationSourceIAMFromValidatedActors()
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
