package region

import (
	"context"
	"errors"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// OriginalMaterialPublicationScope is public DATA, never startup authority.
type OriginalMaterialPublicationScope struct {
	Target                 bootstrapmaterial.VaultTarget `json:"target"`
	PolicyID               string                        `json:"policyId"`
	PolicyETag             string                        `json:"policyEtag"`
	PolicySHA256           string                        `json:"policySha256"`
	ReadbackSHA256         string                        `json:"readbackSha256"`
	SecretNames            [8]string                     `json:"secretNames,omitzero"`
	OriginalLinkObject     string                        `json:"originalLinkObject,omitempty"`
	OriginalLinkSecretName string                        `json:"originalLinkSecretName,omitempty"`
	OriginalLinkEscrow     bootstrapmaterial.VaultTarget `json:"originalLinkEscrow,omitzero"`
}

func originalSourceMaterialPublication(grant FoundationGrant, record FoundationRecord, index int) (*OriginalFoundationMaterialIAM, error) {
	if index < 0 || index >= 3 || grant.OriginalMaterialPublicationIAM == nil {
		return nil, nil
	}
	recipe := (*grant.OriginalMaterialPublicationIAM)[index]
	// Historical seven-operation permission does not authorize policy readback.
	if recipe.Purpose != originalMaterialIAMPurposeV2 && recipe.Purpose != originalMaterialIAMPurposeV3 {
		return nil, nil
	}
	if record.validateOriginalFoundationMaterialIAM() != nil || record.OriginalFoundationCompartments == nil {
		return nil, ErrOriginalSourceActorHold
	}
	entry := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM
	if entry == nil || entry.Pending == nil || entry.Provenance == nil || entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
		return nil, nil
	}
	expected, err := originalMaterialIAMScope(record, index, recipe)
	if err != nil || !sameOriginalSourceValue(entry.scopeOnly(), expected) {
		return nil, errors.Join(ErrOriginalSourceActorHold, err)
	}
	copy := *entry
	return &copy, nil
}

func originalMaterialPublicationScope(entry OriginalFoundationMaterialIAM) (OriginalMaterialPublicationScope, error) {
	if entry.Provenance == nil || (entry.Recipe.Purpose != originalMaterialIAMPurposeV2 && entry.Recipe.Purpose != originalMaterialIAMPurposeV3) || !originalPublicationETag(entry.PolicyETag) {
		return OriginalMaterialPublicationScope{}, ErrOriginalSourceActorHold
	}
	body, err := foundationWriterPolicyBody(entry.Request)
	if err != nil {
		return OriginalMaterialPublicationScope{}, err
	}
	return OriginalMaterialPublicationScope{Target: entry.Target, PolicyID: entry.Provenance.ResourceID,
		PolicyETag: entry.PolicyETag, PolicySHA256: digestSource(body), ReadbackSHA256: entry.ReadbackSHA256}, nil
}

func verifyOriginalMaterialPublicationPolicy(ctx context.Context, factory *ociclient.Factory, entry OriginalFoundationMaterialIAM) error {
	home, err := factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	if _, err := originalMaterialPublicationScope(entry); err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(entry.Provenance.ResourceID), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return err
	}
	if deref(response.Id) != entry.Provenance.ResourceID || deref(response.CompartmentId) != deref(entry.Request.CompartmentId) ||
		deref(response.Name) != deref(entry.Request.Name) || deref(response.Description) != deref(entry.Request.Description) ||
		response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, entry.Request.Statements) ||
		!sameOriginalSourceValue(response.VersionDate, entry.Request.VersionDate) || !sameOriginalSourceValue(response.FreeformTags, entry.Request.FreeformTags) ||
		!sameOriginalSourceValue(response.DefinedTags, entry.Request.DefinedTags) || deref(response.Etag) != entry.PolicyETag {
		return ErrOriginalSourceActorHold
	}
	if entry.Recipe.Purpose == originalMaterialIAMPurposeV3 {
		group := entry.PeerDynamicGroup
		if group == nil || group.Pending == nil || group.Provenance == nil || group.VerifiedAt.IsZero() || group.HoldReason != "" {
			return ErrOriginalSourceActorHold
		}
		if _, err := verifyOriginalMaterialPeerGroup(ctx, iam, *group); err != nil {
			return errors.Join(ErrOriginalSourceActorHold, err)
		}
	}
	return ctx.Err()
}

// MaterialPublication rechecks the genuine actor and exact protected v2 policy
// before returning its target and a context guarding every publication request.
func (v VerifiedOriginalSourceActor) MaterialPublication(ctx context.Context) (OriginalMaterialPublicationScope, *ociclient.Factory, context.Context, error) {
	if ctx == nil || !v.IsVerified() || v.proof.materialPublication == nil {
		return OriginalMaterialPublicationScope{}, nil, nil, ErrOriginalSourceActorHold
	}
	entry := *v.proof.materialPublication
	guard := func(send context.Context) error {
		if err := send.Err(); err != nil {
			return err
		}
		// Retain caller guard values with the active dispatch lifetime.
		check := originalProviderCheckpointContext(send, ctx)
		if err := v.Guard(check); err != nil {
			return err
		}
		if err := verifyOriginalMaterialPublicationPolicy(check, v.proof.factory, entry); err != nil {
			return err
		}
		return ociclient.LimitAdmission(send, v.proof.scope.Deadline)
	}
	if err := guard(ctx); err != nil {
		return OriginalMaterialPublicationScope{}, nil, nil, err
	}
	scope, err := originalMaterialPublicationScope(entry)
	if err != nil {
		return OriginalMaterialPublicationScope{}, nil, nil, err
	}
	factory, guarded, err := v.GuardedFactory(ctx)
	if err != nil {
		return OriginalMaterialPublicationScope{}, nil, nil, err
	}
	return scope, factory, ociclient.WithRequestGuard(ociclient.WithAuthority(guarded, guard), guard), nil
}

// OriginalLinkPublication selects one of the signed three recipient rosters;
// only the genuine GRU original actor may publish Link leaves or private escrow.
func (v VerifiedOriginalSourceActor) OriginalLinkPublication(ctx context.Context, requestedCell oci.Region) (OriginalMaterialPublicationScope, *ociclient.Factory, context.Context, error) {
	if !v.IsVerified() || v.proof.scope.Cell != "GRU" || v.proof.materialPublication == nil || v.proof.materialPublication.Recipe.Purpose != originalMaterialIAMPurposeV3 || v.proof.materialPublication.Startup == nil {
		return OriginalMaterialPublicationScope{}, nil, nil, ErrOriginalSourceActorHold
	}
	scope, factory, guarded, err := v.MaterialPublication(ctx)
	if err != nil {
		return OriginalMaterialPublicationScope{}, nil, nil, err
	}
	for _, recipient := range v.proof.materialPublication.Startup.Regions {
		if recipient.Producer.Cell != string(requestedCell) {
			continue
		}
		if recipient.Producer.InstallationID != v.proof.intent.InstallationID || recipient.Producer.Generation != v.proof.intent.Generation || recipient.Producer.Home != v.proof.intent.Home {
			return OriginalMaterialPublicationScope{}, nil, nil, ErrOriginalSourceActorHold
		}
		scope.Target, scope.SecretNames = recipient.Target, recipient.LinkSecretNames
		scope.OriginalLinkObject, scope.OriginalLinkSecretName, scope.OriginalLinkEscrow = recipient.LinkObject, recipient.LinkEscrowSecretName, recipient.Producer.Escrow
		return scope, factory, guarded, nil
	}
	return OriginalMaterialPublicationScope{}, nil, nil, ErrOriginalSourceActorHold
}
