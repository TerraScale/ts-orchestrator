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
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const originalMaterialIAMPurpose = "original-material-publication-iam/v1"

var ErrOriginalFoundationMaterialIAMPending = fmt.Errorf("%w: original material-publication IAM retained; startup and runtime admission remain unavailable", ErrOriginalFoundationAdmissionReadsPending)

// OriginalMaterialPublicationIAMIntent is prospective root permission for the
// original actor's finite material publication, never general startup authority.
type OriginalMaterialPublicationIAMIntent struct {
	Purpose                      string                                 `json:"purpose"`
	Cell                         string                                 `json:"cell"`
	OCIRegion                    string                                 `json:"ociRegion"`
	TenancyID                    string                                 `json:"tenancyId"`
	InstallationID               string                                 `json:"installationId"`
	ProducerIntentSHA256         string                                 `json:"producerIntentSha256"`
	PlanSHA256                   string                                 `json:"planSha256"`
	AdmissionAuthorizationSHA256 string                                 `json:"admissionAuthorizationSha256"`
	ActorOperationID             string                                 `json:"actorOperationId"`
	ActorRecipeSHA256            string                                 `json:"actorRecipeSha256"`
	ControlCompartment           string                                 `json:"controlCompartment"`
	Vault                        string                                 `json:"vault"`
	Key                          string                                 `json:"key"`
	SecretNames                  []string                               `json:"secretNames"`
	Operations                   [7]OriginalActorAdmissionReadOperation `json:"operations"`
}

func originalMaterialIAMOperations() [7]OriginalActorAdmissionReadOperation {
	return [7]OriginalActorAdmissionReadOperation{
		{"ListSecrets", "secrets", "SECRET_INSPECT", "regional-control-list"},
		{"CreateSecret", "secrets", "SECRET_CREATE", "material-names-vault"},
		{"GetSecret", "secrets", "SECRET_READ", "material-names-vault"},
		{"GetSecretBundle", "secret-bundles", "SECRET_BUNDLE_READ", "material-names-vault"},
		{"CreateSecret", "vaults", "VAULT_CREATE_SECRET", "material-vault"},
		{"CreateSecret", "keys", "KEY_ENCRYPT", "material-key"},
		{"CreateSecret", "keys", "KEY_DECRYPT", "material-key"},
	}
}

func originalMaterialIAMRecipe(purpose OriginalSourceProducerIntent, config bootstrapmaterial.Config, control, vault, key string) (OriginalMaterialPublicationIAMIntent, error) {
	var recipe OriginalMaterialPublicationIAMIntent
	wire, err := json.Marshal(purpose, json.Deterministic(true))
	plan, configErr := json.Marshal(config, json.Deterministic(true))
	names, namesErr := bootstrapmaterial.OriginalPublicationSecretNames(config)
	if err != nil || configErr != nil || namesErr != nil || len(names) != 33 || purpose.Home.Validate() != nil || purpose.PlanSHA256 != digestSource(plan) ||
		purpose.Cell != strings.ToUpper(config.Cell) || purpose.OCIRegion != config.Region || !validFoundationDigest(purpose.AdmissionAuthorizationSHA256) ||
		control == "" || vault == "" || key == "" {
		return recipe, ErrOriginalSourceProducerHold
	}
	return OriginalMaterialPublicationIAMIntent{Purpose: originalMaterialIAMPurpose, Cell: purpose.Cell, OCIRegion: purpose.OCIRegion,
		TenancyID: purpose.TenancyID, InstallationID: purpose.InstallationID, ProducerIntentSHA256: digestSource(wire),
		PlanSHA256: purpose.PlanSHA256, AdmissionAuthorizationSHA256: purpose.AdmissionAuthorizationSHA256,
		ActorOperationID: purpose.OperationID, ActorRecipeSHA256: purpose.Allocation.RecipeSHA256,
		ControlCompartment: control, Vault: vault, Key: key, SecretNames: names, Operations: originalMaterialIAMOperations()}, nil
}

func originalMaterialIAMIntents(grant FoundationGrant, home bootstrap.StorageDomain) ([3]OriginalMaterialPublicationIAMIntent, error) {
	var intents [3]OriginalMaterialPublicationIAMIntent
	if grant.SchemaVersion != 3 || grant.Generation != 1 || len(grant.Regions) != 3 || requireOriginalSourceProducerPurposes(grant) != nil ||
		grant.OriginalActorAdmissionReads == nil || grant.OriginalPublication == nil || validateOriginalAdmissionReadIntents(grant, home) != nil || validateOriginalFoundationPublicationIntent(grant, home) != nil {
		return intents, ErrOriginalSourceProducerHold
	}
	for index, cell := range [3]string{"GRU", "SFO", "FRA"} {
		found := false
		for _, regional := range grant.Regions {
			if regional.Plan["cell"] != cell {
				continue
			}
			material := regional.BootstrapMaterial
			if found || material == nil || material.Startup == nil || material.AdmissionAttestor == nil || material.OriginalSourceProducer == nil || material.OriginalSourceProducer.Home != home {
				return intents, ErrOriginalSourceProducerHold
			}
			auth, err := material.AdmissionAttestor.Digest()
			if err != nil || auth != material.OriginalSourceProducer.AdmissionAuthorizationSHA256 {
				return intents, ErrOriginalSourceProducerHold
			}
			control, err := preparationResource(regional.Plan, cell, "control_compartment")
			if err != nil {
				return intents, err
			}
			vault, err := preparationResource(regional.Plan, cell, "vault")
			if err != nil {
				return intents, err
			}
			key, err := preparationResource(regional.Plan, cell, "key")
			if err != nil {
				return intents, err
			}
			intents[index], err = originalMaterialIAMRecipe(*material.OriginalSourceProducer, material.Config, control, vault, key)
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

func validateOriginalMaterialIAMIntents(grant FoundationGrant, home bootstrap.StorageDomain) error {
	if grant.OriginalMaterialPublicationIAM == nil {
		return nil
	}
	expected, err := originalMaterialIAMIntents(grant, home)
	if err != nil || !sameOriginalSourceValue(expected, grant.OriginalMaterialPublicationIAM) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return nil
}

// OriginalFoundationMaterialIAM retains only a separately authenticated
// original-operator policy effect. It grants no local startup capability.
type OriginalFoundationMaterialIAM struct {
	Recipe            OriginalMaterialPublicationIAMIntent `json:"recipe"`
	GrantSHA256       string                               `json:"grantSha256"`
	BundleSHA256      string                               `json:"bundleSha256"`
	IntentSHA256      string                               `json:"intentSha256"`
	BirthSHA256       string                               `json:"birthSha256"`
	Generation        uint64                               `json:"generation"`
	OperationID       string                               `json:"operationId"`
	ActorID           string                               `json:"actorId"`
	ActorSHA256       string                               `json:"actorSha256"`
	VaultSHA256       string                               `json:"vaultSha256"`
	AdmissionSHA256   string                               `json:"admissionSha256"`
	PublicationSHA256 string                               `json:"publicationSha256"`
	Target            bootstrapmaterial.VaultTarget        `json:"target"`
	IdentitySHA256    string                               `json:"identitySha256"`
	Request           identity.CreatePolicyDetails         `json:"request"`
	Pending           *PendingFoundationCreate             `json:"pending,omitempty"`
	Provenance        *FoundationResourceProvenance        `json:"provenance,omitempty"`
	PolicyETag        string                               `json:"policyEtag,omitempty"`
	ReadbackSHA256    string                               `json:"readbackSha256,omitempty"`
	VerifiedAt        time.Time                            `json:"verifiedAt,omitzero"`
	HoldReason        string                               `json:"holdReason,omitempty"`
}

func completeOriginalMaterialIAMPrerequisites(record FoundationRecord) error {
	if completeOriginalFoundationAdmissionReads(record) != nil || record.validateOriginalFoundationPublication() != nil || record.OriginalFoundationCompartments.Publication == nil || record.OriginalFoundationCompartments.Publication.Readbacks == nil {
		return ErrOriginalSourceProducerHold
	}
	for _, regional := range record.OriginalFoundationCompartments.Regions {
		v := regional.Vault
		if v == nil || v.Vault.VerifiedAt.IsZero() || v.Key.VerifiedAt.IsZero() || v.Vault.ReadbackSHA256 == "" || v.Key.ReadbackSHA256 == "" || v.Vault.HoldReason != "" || v.Key.HoldReason != "" {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}

func originalMaterialIAMScope(record FoundationRecord, index int, recipe OriginalMaterialPublicationIAMIntent) (OriginalFoundationMaterialIAM, error) {
	var scope OriginalFoundationMaterialIAM
	if index < 0 || index >= 3 || completeOriginalMaterialIAMPrerequisites(record) != nil {
		return scope, ErrOriginalSourceProducerHold
	}
	root := record.OriginalFoundationCompartments
	regional, birth := root.Regions[index], (*record.OriginalSourceProducers)[index]
	actor, v := regional.Actor, regional.Vault
	expected, err := originalMaterialIAMRecipe(birth.Intent, actor.Config, recipe.ControlCompartment, recipe.Vault, recipe.Key)
	if err != nil || !sameOriginalSourceValue(expected, recipe) || !originalActorRole(regional.Cell, "control_compartment", recipe.ControlCompartment, v.ControlCompartmentID) ||
		!originalActorRole(regional.Cell, "vault", recipe.Vault, originalVaultID(v.Vault.OriginalFoundationKMSCreate)) || !originalActorRole(regional.Cell, "key", recipe.Key, originalVaultID(v.Key.OriginalFoundationKMSCreate)) || actor.ControlCompartmentID != v.ControlCompartmentID {
		return scope, ErrOriginalSourceProducerHold
	}
	scope = OriginalFoundationMaterialIAM{Recipe: recipe, GrantSHA256: root.GrantSHA256, BundleSHA256: root.BundleSHA256,
		IntentSHA256: regional.IntentSHA256, Generation: regional.Generation, OperationID: regional.OperationID,
		ActorID: originalActorID(actor), Target: bootstrapmaterial.VaultTarget{CompartmentOCID: v.ControlCompartmentID, VaultOCID: originalVaultID(v.Vault.OriginalFoundationKMSCreate), KMSKeyOCID: originalVaultID(v.Key.OriginalFoundationKMSCreate)}}
	if scope.Target.Validate(regional.OCIRegion) != nil {
		return OriginalFoundationMaterialIAM{}, ErrOriginalSourceProducerHold
	}
	for _, pin := range []struct {
		value any
		out   *string
	}{{birth, &scope.BirthSHA256}, {actor, &scope.ActorSHA256}, {v, &scope.VaultSHA256}, {regional.AdmissionReads, &scope.AdmissionSHA256}, {root.Publication, &scope.PublicationSHA256}} {
		wire, err := json.Marshal(pin.value, json.Deterministic(true))
		if err != nil {
			return scope, err
		}
		*pin.out = digestSource(wire)
	}
	wire, err := json.Marshal(scope, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope.IdentitySHA256 = digestSource(wire)
	scope.Request = originalMaterialIAMPolicy(scope)
	return scope, nil
}

func originalMaterialIAMPolicy(scope OriginalFoundationMaterialIAM) identity.CreatePolicyDetails {
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", scope.ActorID)
	names := make([]string, len(scope.Recipe.SecretNames))
	for index, name := range scope.Recipe.SecretNames {
		names[index] = fmt.Sprintf("target.secret.name='%s'", name)
	}
	statements := make([]string, 0, 7)
	for _, operation := range scope.Recipe.Operations {
		conditions := principal + fmt.Sprintf(", request.operation='%s', request.permission='%s'", operation.Operation, operation.Permission)
		verb := "use"
		switch operation.Scope {
		case "regional-control-list":
			// Oracle maps ListSecrets to SECRET_INSPECT; name/Vault filters do not confine IAM LIST scope.
			verb = "inspect"
		case "material-names-vault":
			verb = "read"
			if operation.Permission == "SECRET_CREATE" {
				verb = "manage"
			}
			conditions += fmt.Sprintf(", target.vault.id='%s', any {%s}", scope.Target.VaultOCID, strings.Join(names, ", "))
		case "material-vault":
			conditions += fmt.Sprintf(", target.vault.id='%s'", scope.Target.VaultOCID)
		case "material-key":
			conditions += fmt.Sprintf(", target.key.id='%s'", scope.Target.KMSKeyOCID)
		}
		statements = append(statements, fmt.Sprintf("Allow any-user to %s %s in compartment id %s where all {%s}", verb, operation.ResourceType, scope.Target.CompartmentOCID, conditions))
	}
	return identity.CreatePolicyDetails{CompartmentId: new(scope.Target.CompartmentOCID), Name: new("ts-original-material-iam-" + scope.IdentitySHA256[:32]), Description: new("Prospectively authorized finite original material publication"), Statements: statements, FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}
}

func originalMaterialIAMPrerequisites(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, [3]OriginalFoundationMaterialIAM, time.Time, error) {
	var scopes [3]OriginalFoundationMaterialIAM
	if ctx == nil || authority == nil || authority.operator == nil {
		return FoundationRecord{}, "", scopes, time.Time{}, ErrOriginalSourceProducerHold
	}
	lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
	if !ok || lease == nil || lease.authority != authority || authority.Guard(ctx, 0) != nil {
		return FoundationRecord{}, "", scopes, time.Time{}, ErrOriginalSourceProducerHold
	}
	record, etag, publication, deadline, err := originalPublicationAuthority(ctx, authority)
	if err != nil || completeOriginalMaterialIAMPrerequisites(record) != nil || !sameOriginalSourceValue(record.OriginalFoundationCompartments.Publication.scopeOnly(), publication) {
		return record, etag, scopes, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for index, wire := range [2][]byte{authority.operator.bundle.RootChainWire, authority.operator.bundle.GrantWire} {
		readback, err := originalPublicationReadback(ctx, authority, publication.Intent.Objects[index], wire)
		saved := (*record.OriginalFoundationCompartments.Publication.Readbacks)[index]
		if err != nil || readback.ETag != saved.ETag || readback.ContentSHA256 != saved.ContentSHA256 {
			return record, etag, scopes, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
		}
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return record, etag, scopes, deadline, ErrOriginalSourceProducerHold
	}
	grant, _, err := reader.verifyOriginalDocument(authority.operator.bundle.GrantWire)
	if err != nil || grant.OriginalMaterialPublicationIAM == nil || validateOriginalMaterialIAMIntents(grant, authority.domain) != nil {
		return record, etag, scopes, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for index := range scopes {
		scopes[index], err = originalMaterialIAMScope(record, index, (*grant.OriginalMaterialPublicationIAM)[index])
		if err != nil {
			return record, etag, scopes, deadline, err
		}
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return record, etag, scopes, deadline, err
	}
	return record, etag, scopes, deadline, nil
}

func provisionOriginalFoundationMaterialIAM(ctx context.Context, authority *HomeIAMAuthority) error {
	record, etag, expected, _, err := originalMaterialIAMPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	changed := false
	for index := range expected {
		entry := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM
		if entry == nil {
			record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM = &expected[index]
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
		if err := provisionOriginalMaterialIAM(ctx, authority, index); err != nil {
			return err
		}
	}
	return ErrOriginalFoundationMaterialIAMPending
}

func (entry OriginalFoundationMaterialIAM) scopeOnly() OriginalFoundationMaterialIAM {
	entry.Pending, entry.Provenance = nil, nil
	entry.PolicyETag, entry.ReadbackSHA256, entry.VerifiedAt, entry.HoldReason = "", "", time.Time{}, ""
	return entry
}

func originalMaterialIAMCreateIdentity(regional OriginalFoundationCompartmentRegion, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: "original-material-publication-policy", Region: foundationHomeRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(regional.OperationID, digest)}
}

func originalMaterialIAMDuplicate(record FoundationRecord, index int, id string) bool {
	for other, regional := range record.OriginalFoundationCompartments.Regions {
		if regional.SourceIAM != nil && regional.SourceIAM.Provenance != nil && regional.SourceIAM.Provenance.ResourceID == id ||
			regional.ActorReads != nil && regional.ActorReads.Provenance != nil && regional.ActorReads.Provenance.ResourceID == id ||
			regional.AdmissionReads != nil && regional.AdmissionReads.Provenance != nil && regional.AdmissionReads.Provenance.ResourceID == id ||
			other != index && regional.MaterialPublicationIAM != nil && regional.MaterialPublicationIAM.Provenance != nil && regional.MaterialPublicationIAM.Provenance.ResourceID == id {
			return true
		}
	}
	return false
}

func originalMaterialIAMReadback(entry OriginalFoundationMaterialIAM) (string, error) {
	if entry.Pending == nil || entry.Provenance == nil || !originalPublicationETag(entry.PolicyETag) {
		return "", ErrOriginalSourceProducerHold
	}
	body, err := foundationWriterPolicyBody(entry.Request)
	if err != nil {
		return "", err
	}
	wire, err := json.Marshal([]string{entry.Provenance.ResourceID, digestSource(body), entry.PolicyETag, "ACTIVE"}, json.Deterministic(true))
	return digestSource(wire), err
}
func provisionOriginalMaterialIAM(ctx context.Context, authority *HomeIAMAuthority, index int) error {
	record, etag, scopes, _, err := originalMaterialIAMPrerequisites(ctx, authority)
	if err != nil {
		return err
	}
	regional := record.OriginalFoundationCompartments.Regions[index]
	entry := regional.MaterialPublicationIAM
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
			FirstAttemptAt: time.Now().UTC(), Request: originalMaterialIAMCreateIdentity(regional, digest)}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	if entry.Provenance == nil && !time.Now().Before(entry.Pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
		entry.HoldReason = "retry-expired"
		return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
	}
	guard := func(dispatchCtx context.Context) error {
		saved, _, currentScopes, deadline, err := originalMaterialIAMPrerequisites(originalProviderCheckpointContext(dispatchCtx, ctx), authority)
		if err != nil {
			return err
		}
		current := saved.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM
		if current == nil || current.HoldReason != "" || !sameOriginalSourceValue(current, entry) || !sameOriginalSourceValue(current.scopeOnly(), currentScopes[index]) ||
			current.Pending == nil || current.Pending.Request != originalMaterialIAMCreateIdentity(regional, digest) {
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
		if !validAuxiliaryID("controller_usage_policy", id, "") || originalMaterialIAMDuplicate(record, index, id) {
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
	policyETag := deref(response.Etag)
	if !originalPublicationETag(policyETag) || entry.PolicyETag != "" && entry.PolicyETag != policyETag {
		return ErrOriginalSourceProducerHold
	}
	observed := *entry
	observed.PolicyETag = policyETag
	readback, err := originalMaterialIAMReadback(observed)
	if err != nil || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != readback {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if entry.VerifiedAt.IsZero() {
		entry.PolicyETag, entry.ReadbackSHA256, entry.VerifiedAt = policyETag, readback, time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func (record FoundationRecord) validateOriginalFoundationMaterialIAM() error {
	root := record.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	for index, regional := range root.Regions {
		entry := regional.MaterialPublicationIAM
		if entry == nil {
			continue
		}
		expected, err := originalMaterialIAMScope(record, index, entry.Recipe)
		if err != nil || !sameOriginalSourceValue(entry.scopeOnly(), expected) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		if entry.Pending == nil {
			if entry.Provenance != nil || entry.PolicyETag != "" || entry.ReadbackSHA256 != "" || !entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		body, err := foundationWriterPolicyBody(entry.Request)
		pending := *entry.Pending
		if err != nil || pending.OperationID != regional.OperationID || pending.IntentDigest != regional.IntentSHA256 ||
			pending.Request != originalMaterialIAMCreateIdentity(regional, digestSource(body)) || pending.FirstAttemptAt.IsZero() || pending.FirstAttemptAt.After(record.UpdatedAt) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		for _, upstream := range root.Regions {
			if pending.FirstAttemptAt.Before(upstream.AdmissionReads.VerifiedAt) || pending.FirstAttemptAt.Before(upstream.Vault.Vault.VerifiedAt) || pending.FirstAttemptAt.Before(upstream.Vault.Key.VerifiedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
		for _, readback := range *root.Publication.Readbacks {
			if pending.FirstAttemptAt.Before(readback.VerifiedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.HoldReason != "" && !slices.Contains([]string{"retry-expired", "create-refused", "create-unresolved", "readback-conflict"}, entry.HoldReason) {
			return ErrOriginalSourceProducerHold
		}
		if entry.Provenance != nil {
			proof := entry.Provenance
			if !sameOriginalSourceValue(proof.Create, pending) || proof.Generation != entry.Generation || proof.GrantSHA256 != entry.GrantSHA256 ||
				!validAuxiliaryID("controller_usage_policy", proof.ResourceID, "") || originalMaterialIAMDuplicate(record, index, proof.ResourceID) ||
				entry.HoldReason != "" && entry.HoldReason != "readback-conflict" {
				return ErrOriginalSourceProducerHold
			}
		}
		if entry.VerifiedAt.IsZero() != (entry.PolicyETag == "") || entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() &&
			(entry.Provenance == nil || entry.VerifiedAt.Before(pending.FirstAttemptAt) || entry.VerifiedAt.After(record.UpdatedAt)) {
			return ErrOriginalSourceProducerHold
		}
		if entry.ReadbackSHA256 != "" {
			readback, err := originalMaterialIAMReadback(*entry)
			if err != nil || entry.ReadbackSHA256 != readback {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationMaterialIAM(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		if after != nil {
			for _, regional := range after.Regions {
				if regional.MaterialPublicationIAM != nil {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		return nil
	}
	for index, regional := range before.Regions {
		old := regional.MaterialPublicationIAM
		if after == nil {
			if old != nil {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		current := after.Regions[index].MaterialPublicationIAM
		if old == nil {
			if current != nil {
				expected, err := originalMaterialIAMScope(previous, index, current.Recipe)
				if err != nil || !sameOriginalSourceValue(current, expected) {
					return errors.Join(ErrOriginalSourceProducerHold, err)
				}
			}
			continue
		}
		if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) ||
			old.Pending != nil && !sameOriginalSourceValue(old.Pending, current.Pending) || old.Provenance != nil && !sameOriginalSourceValue(old.Provenance, current.Provenance) ||
			old.PolicyETag != "" && old.PolicyETag != current.PolicyETag || old.ReadbackSHA256 != "" && old.ReadbackSHA256 != current.ReadbackSHA256 || !old.VerifiedAt.IsZero() && !old.VerifiedAt.Equal(current.VerifiedAt) ||
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
