package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// OriginalFoundationCompartments retains finite original prerequisites.
// It has no current foundation, launch, IAM or runtime authority.
type OriginalFoundationCompartments struct {
	Publication       *OriginalFoundationPublication         `json:"publication,omitempty"`
	GrantSHA256       string                                 `json:"grantSha256"`
	BundleSHA256      string                                 `json:"bundleSha256"`
	GRUIntentSHA256   string                                 `json:"gruIntentSha256"`
	Generation        uint64                                 `json:"generation"`
	OperationID       string                                 `json:"operationId"`
	BornAt            time.Time                              `json:"bornAt"`
	UserID            string                                 `json:"userId"`
	Currency          string                                 `json:"currency"`
	MonthlyLimitMinor int64                                  `json:"monthlyLimitMinor"`
	CleanupOwner      string                                 `json:"cleanupOwner"`
	Regions           [3]OriginalFoundationCompartmentRegion `json:"regions"`
}

type OriginalFoundationCompartmentRegion struct {
	Cell                   string                            `json:"cell"`
	OCIRegion              string                            `json:"ociRegion"`
	IntentSHA256           string                            `json:"intentSha256"`
	Generation             uint64                            `json:"generation"`
	OperationID            string                            `json:"operationId"`
	ProducerIntentSHA256   string                            `json:"producerIntentSha256"`
	Compartments           [2]OriginalFoundationCompartment  `json:"compartments"`
	Network                *OriginalFoundationNetwork        `json:"network,omitempty"`
	Vault                  *OriginalFoundationVault          `json:"vault,omitempty"`
	Actor                  *OriginalFoundationActorLaunch    `json:"actor,omitempty"`
	ActorReads             *OriginalFoundationActorReads     `json:"actorReads,omitempty"`
	SourceIAM              *OriginalFoundationSourceIAM      `json:"sourceIam,omitempty"`
	AdmissionReads         *OriginalFoundationAdmissionReads `json:"admissionReads,omitempty"`
	MaterialPublicationIAM *OriginalFoundationMaterialIAM    `json:"materialPublicationIam,omitempty"`
	NetBirdManager         *OriginalFoundationNetBirdManager `json:"netbirdManager,omitempty"`
}

type OriginalFoundationCompartment struct {
	Role           string                            `json:"role"`
	SelectedID     string                            `json:"selectedId,omitempty"`
	Request        identity.CreateCompartmentDetails `json:"request"`
	Pending        *PendingFoundationCreate          `json:"pending,omitempty"`
	Provenance     *FoundationResourceProvenance     `json:"provenance,omitempty"`
	ReadbackSHA256 string                            `json:"readbackSha256,omitempty"`
	VerifiedAt     time.Time                         `json:"verifiedAt,omitzero"`
	HoldReason     string                            `json:"holdReason,omitempty"`
}

// provisionOriginalFoundationCompartments is the existing original operator's
// automatic continuation. A successful material stage, not a startup error,
// precedes the separately authenticated original full-plan create authority.
func provisionOriginalFoundationCompartments(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, bundle RetainedFoundation) error {
	version, err := decodeOriginalMaterialGrant(bundle)
	if err != nil {
		return err
	}
	if version.SchemaVersion != 3 {
		return ProvisionFoundationBundle(ctx, factory, roots, bundle)
	}
	stage, err := provisionFoundationMaterial(ctx, factory, roots, bundle)
	if err != nil {
		return err
	}
	defer stage.cancel()
	ctx, release, err := stage.authority.HomeWrite(stage.ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	if err := retainOriginalFoundationCompartments(ctx, stage.authority); err != nil {
		return err
	}
	return provisionOriginalFoundationNetwork(ctx, stage.authority)
}

func retainOriginalFoundationCompartments(ctx context.Context, authority *HomeIAMAuthority) error {
	expected, err := originalCompartmentScope(ctx, authority)
	if err != nil {
		return err
	}
	store, ok := authority.resolver.Store.(*ObjectFoundationStore)
	if !ok {
		return ErrOriginalSourceProducerHold
	}
	store.originalCompartmentScope = &expected
	record, etag, err := store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if record.OriginalFoundationCompartments == nil {
		if record.Stage != "material" || !record.netBirdMaterialOnly() {
			return ErrOriginalSourceProducerHold
		}
		initial := expected
		record.OriginalFoundationCompartments = &initial
		record.Stage = "original-foundation"
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	} else if !sameOriginalSourceValue(record.OriginalFoundationCompartments.scopeOnly(), expected) {
		return ErrOriginalSourceProducerHold
	}
	for region := range expected.Regions {
		for role := range expected.Regions[region].Compartments {
			if err := provisionOriginalCompartment(ctx, authority, region, role); err != nil {
				return err
			}
		}
	}
	return nil
}

func originalCompartmentScope(ctx context.Context, authority *HomeIAMAuthority) (OriginalFoundationCompartments, error) {
	var scope OriginalFoundationCompartments
	if authority == nil || authority.operator == nil {
		return scope, ErrOriginalSourceProducerHold
	}
	ctx = ociclient.CheckpointContext(ctx)
	if err := authority.Guard(ctx, 0); err != nil {
		return scope, err
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return scope, ErrOriginalSourceProducerHold
	}
	grant, expires, err := reader.verifyOriginalDocument(authority.operator.bundle.GrantWire)
	if err != nil {
		return scope, err
	}
	if grant.SchemaVersion != 3 || grant.Generation != 1 || grant.MonthlyLimitMinor <= 0 || grant.CleanupOwner == "" {
		return scope, ErrOriginalSourceProducerHold
	}
	if err := ValidatePreparedFoundation(grant); err != nil {
		return scope, err
	}
	if err := authority.checkOriginalSourceProducerBirth(ctx); err != nil {
		return scope, err
	}
	if err := authority.checkNetBirdMaterialOrigins(ctx, grant); err != nil {
		return scope, err
	}
	a, home, err := authority.netBirdMaterialScope(grant)
	if err != nil {
		return scope, err
	}
	record, _, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return scope, err
	}
	if err := authority.checkNetBirdMaterialBirth(record, grant, a, home); err != nil {
		return scope, err
	}
	if record.NetBirdMaterial == nil || !record.NetBirdMaterial.Complete || !record.netBirdMaterialOnly() ||
		!slices.Contains([]string{"material", "original-foundation"}, record.Stage) {
		return scope, ErrOriginalSourceProducerHold
	}
	bundleWire, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil {
		return scope, err
	}
	scope = OriginalFoundationCompartments{GrantSHA256: digestSource(authority.operator.bundle.GrantWire), BundleSHA256: digestSource(bundleWire),
		GRUIntentSHA256: record.IntentDigest, Generation: record.Generation, OperationID: record.OperationID, BornAt: record.NetBirdMaterial.BornAt,
		UserID: authority.operator.id, Currency: grant.Currency, MonthlyLimitMinor: grant.MonthlyLimitMinor, CleanupOwner: grant.CleanupOwner}
	for index, cell := range [3]string{"GRU", "SFO", "FRA"} {
		var regional *FoundationIntent
		for i := range grant.Regions {
			if grant.Regions[i].Plan["cell"] == cell {
				regional = &grant.Regions[i]
			}
		}
		if regional == nil {
			return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
		}
		var purpose OriginalSourceProducerIntent
		// Reuse only the exact retained document; online readers still reread OCI.
		if bytes.Equal(reader.retainedGrant, authority.operator.bundle.GrantWire) {
			now := time.Now()
			if ctx.Err() != nil || !now.Before(reader.expires) || !now.Before(expires) {
				return OriginalFoundationCompartments{}, errors.Join(ErrOriginalSourceProducerHold, ctx.Err())
			}
			purpose, err = originalSourceProducerIntent(grant, reader.storage, *regional)
			if err != nil || !sameOriginalSourceValue(purpose, regional.BootstrapMaterial.OriginalSourceProducer) {
				return OriginalFoundationCompartments{}, errors.Join(ErrOriginalSourceProducerHold, err)
			}
		} else {
			verified, err := reader.OriginalSourceProducer(ctx, cell)
			if err != nil || !verified.IsVerified() {
				return OriginalFoundationCompartments{}, errors.Join(ErrOriginalSourceProducerHold, err)
			}
			purpose = verified.Intent()
		}
		if purpose.OriginalUserID != scope.UserID {
			return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
		}
		intentDigest, err := FoundationIntentDigest(*regional)
		if err != nil {
			return OriginalFoundationCompartments{}, err
		}
		birth := (*record.OriginalSourceProducers)[index]
		region := OriginalFoundationCompartmentRegion{Cell: cell, OCIRegion: birth.Intent.OCIRegion, IntentSHA256: intentDigest,
			Generation: grant.Generation, OperationID: entityid.Derive("regional-foundation", grant.TenancyID, cell, fmt.Sprint(grant.Generation)), ProducerIntentSHA256: birth.IntentSHA256}
		names, namesOK := regional.Plan["preview_compartment_names"].(map[string]any)
		ids, idsOK := regional.Plan["resource_ids"].(map[string]any)
		name, nameErr := naming.RegionCell(cell).Name()
		if !namesOK || !idsOK || nameErr != nil || regional.Plan["parent_compartment_id"] != grant.ParentCompartmentID {
			return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
		}
		for slot, role := range [2]string{"control", "network"} {
			key := role + "_compartment"
			if names[role] != name+"-"+role {
				return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
			}
			selected := ""
			if value := ids[key]; value != nil {
				var valid bool
				selected, valid = value.(string)
				if !valid || !sourceCompartmentPattern.MatchString(selected) || len(selected) > 512 {
					return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
				}
			}
			if cell == "GRU" && role == "control" && selected != birth.Intent.Escrow.CompartmentOCID {
				return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
			}
			reference, err := FoundationResourceReference(cell, key)
			if err != nil || role == "control" && birth.Intent.Profile.CompartmentOCID != selected && birth.Intent.Profile.CompartmentOCID != reference {
				return OriginalFoundationCompartments{}, ErrOriginalSourceProducerHold
			}
			region.Compartments[slot] = OriginalFoundationCompartment{Role: key, SelectedID: selected,
				Request: identity.CreateCompartmentDetails{CompartmentId: new(grant.ParentCompartmentID), Name: new(name + "-" + role),
					Description: new("TerraScale " + name + " foundation (ts-orch oci-region foundation)"), DefinedTags: map[string]map[string]any{},
					FreeformTags: map[string]string{"terrascale.owner": "ts-orch", "terrascale.cell": name, "terrascale.operation": region.OperationID}}}
		}
		scope.Regions[index] = region
	}
	return scope, nil
}

func originalCompartmentRequestSHA(details identity.CreateCompartmentDetails) (string, error) {
	request := identity.CreateCompartmentRequest{CreateCompartmentDetails: details}
	httpRequest, err := request.HTTPRequest(http.MethodPost, "/20160918/compartments", nil, nil)
	if err != nil || httpRequest.Body == nil {
		return "", errors.New("original compartment SDK body is unavailable")
	}
	defer httpRequest.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(httpRequest.Body, 8193))
	if err != nil || len(wire) > 8192 {
		return "", errors.New("original compartment SDK body exceeds its finite bound")
	}
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(object, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(canonical), nil
}

func provisionOriginalCompartment(ctx context.Context, authority *HomeIAMAuthority, regionIndex, roleIndex int) error {
	expected, err := originalCompartmentScope(ctx, authority)
	if err != nil {
		return err
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if record.OriginalFoundationCompartments == nil || !sameOriginalSourceValue(record.OriginalFoundationCompartments.scopeOnly(), expected) {
		return ErrOriginalSourceProducerHold
	}
	region := record.OriginalFoundationCompartments.Regions[regionIndex]
	entry := &record.OriginalFoundationCompartments.Regions[regionIndex].Compartments[roleIndex]
	if entry.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	iam, err := authority.factory.Identity()
	if err != nil {
		return err
	}
	if err := verifyOriginalCompartmentParent(ctx, iam, record.TenancyID, record.ParentCompartmentID); err != nil {
		return err
	}
	if entry.SelectedID == "" && entry.Provenance == nil {
		digest, err := originalCompartmentRequestSHA(entry.Request)
		if err != nil {
			return err
		}
		if entry.Pending == nil {
			entry.Pending = &PendingFoundationCreate{OperationID: region.OperationID, IntentDigest: region.IntentSHA256, FirstAttemptAt: time.Now().UTC(),
				Request: originalCompartmentCreateIdentity(region, entry.Role, digest)}
			if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
				return err
			}
		}
		pending := *entry.Pending
		if !time.Now().Before(pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
			entry.HoldReason = "retry-expired"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		guard := func(ctx context.Context) error {
			dispatchCtx := ctx
			ctx = ociclient.CheckpointContext(ctx)
			currentScope, err := originalCompartmentScope(ctx, authority)
			if err != nil || !sameOriginalSourceValue(currentScope, expected) {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
			saved, _, err := authority.resolver.Store.Load(ctx, "GRU")
			if err != nil || saved.OriginalFoundationCompartments == nil {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
			current := saved.OriginalFoundationCompartments.Regions[regionIndex].Compartments[roleIndex]
			actual, err := originalCompartmentRequestSHA(entry.Request)
			if err != nil || actual != digest || current.SelectedID != "" || current.Provenance != nil || current.HoldReason != "" || !sameOriginalSourceValue(current.Pending, pending) {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
			for _, deadline := range []time.Time{authority.operator.deadline, pending.FirstAttemptAt.Add(bootstrapRetryLifetime)} {
				if err := ociclient.LimitAdmission(dispatchCtx, deadline); err != nil {
					return err
				}
			}
			return nil
		}
		if err := guard(ctx); err != nil {
			return err
		}
		// The lease coordinates writers but cannot fence a paused provider send.
		// Live activation still requires the independent dispatch contract.
		noRetry := common.NoRetryPolicy()
		createCtx := ociclient.WithAuthority(ctx, guard)
		response, err := iam.CreateCompartment(ociclient.RequestContext(createCtx), identity.CreateCompartmentRequest{CreateCompartmentDetails: entry.Request,
			OpcRetryToken: new(pending.Request.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil {
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				entry.HoldReason = "create-refused"
				return errors.Join(err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
			}
			return err
		}
		id := deref(response.Id)
		if !sourceCompartmentPattern.MatchString(id) || len(id) > 512 {
			entry.HoldReason = "create-unresolved"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		// The actual SDK return chooses the ID. Pin it before any Get; an
		// unready, missing or conflicting readback never permits another create.
		entry.Provenance = &FoundationResourceProvenance{Create: pending, ResourceID: id, Generation: region.Generation, GrantSHA256: expected.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	id := entry.SelectedID
	if entry.Provenance != nil {
		id = entry.Provenance.ResourceID
	}
	for _, ociRegion := range slices.Compact([]string{foundationHomeRegion, region.OCIRegion}) {
		regional, err := authority.factory.ForRegion(ociRegion)
		if err != nil {
			return err
		}
		reader, err := regional.Identity()
		if err != nil {
			return err
		}
		response, err := reader.GetCompartment(ociclient.RequestContext(ctx), identity.GetCompartmentRequest{CompartmentId: new(id)})
		if err != nil {
			return err
		}
		if deref(response.Id) != id || deref(response.CompartmentId) != deref(entry.Request.CompartmentId) || deref(response.Name) != deref(entry.Request.Name) || response.LifecycleState != identity.CompartmentLifecycleStateActive {
			return ErrOriginalSourceProducerHold
		}
	}
	readback, err := json.Marshal([]string{id, deref(entry.Request.CompartmentId), deref(entry.Request.Name), "ACTIVE"}, json.Deterministic(true))
	if err != nil {
		return err
	}
	if entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != digestSource(readback) {
		return ErrOriginalSourceProducerHold
	}
	if entry.VerifiedAt.IsZero() {
		entry.ReadbackSHA256, entry.VerifiedAt = digestSource(readback), time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func originalCompartmentCreateIdentity(region OriginalFoundationCompartmentRegion, role, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: role, Region: foundationHomeRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(region.OperationID, digest)}
}

func verifyOriginalCompartmentParent(ctx context.Context, iam identity.IdentityClient, tenancy, parent string) error {
	seen := map[string]bool{}
	for range 16 {
		if seen[parent] || !sourceCompartmentPattern.MatchString(parent) {
			return ErrOriginalSourceProducerHold
		}
		seen[parent] = true
		response, err := iam.GetCompartment(ociclient.RequestContext(ctx), identity.GetCompartmentRequest{CompartmentId: new(parent)})
		if err != nil {
			return err
		}
		if deref(response.Id) != parent || response.LifecycleState != identity.CompartmentLifecycleStateActive {
			return ErrOriginalSourceProducerHold
		}
		parent = deref(response.CompartmentId)
		if parent == tenancy {
			return nil
		}
	}
	return ErrOriginalSourceProducerHold
}

func checkpointOriginalCompartments(ctx context.Context, authority *HomeIAMAuthority, record *FoundationRecord, etag *string) error {
	ctx = ociclient.CheckpointContext(ctx)
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	record.UpdatedAt = time.Now().UTC()
	next, err := authority.resolver.Store.CompareAndSwap(ctx, *record, *etag)
	if err == nil {
		*etag = next
	}
	return err
}

func (scope OriginalFoundationCompartments) scopeOnly() OriginalFoundationCompartments {
	scope.Publication = nil
	for region := range scope.Regions {
		scope.Regions[region].Network = nil
		scope.Regions[region].Vault = nil
		scope.Regions[region].Actor = nil
		scope.Regions[region].ActorReads = nil
		scope.Regions[region].SourceIAM = nil
		scope.Regions[region].AdmissionReads = nil
		scope.Regions[region].MaterialPublicationIAM = nil
		scope.Regions[region].NetBirdManager = nil
		for role := range scope.Regions[region].Compartments {
			entry := &scope.Regions[region].Compartments[role]
			entry.Pending, entry.Provenance = nil, nil
			entry.ReadbackSHA256, entry.HoldReason, entry.VerifiedAt = "", "", time.Time{}
		}
	}
	return scope
}

func (r FoundationRecord) validateOriginalFoundationCompartments() error {
	j := r.OriginalFoundationCompartments
	if j == nil {
		if r.Stage == "original-foundation" {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	if r.Stage != "original-foundation" || !r.netBirdMaterialOnly() || r.OriginalSourceProducers == nil || r.NetBirdMaterial == nil || !r.NetBirdMaterial.Complete ||
		j.GrantSHA256 != r.GrantSHA256 || j.GrantSHA256 != r.NetBirdMaterial.OriginalGrantSHA256 || j.BundleSHA256 != r.NetBirdMaterial.OriginalBundleSHA256 ||
		j.GRUIntentSHA256 != r.IntentDigest || j.Generation != r.Generation || j.OperationID != r.OperationID || !j.BornAt.Equal(r.NetBirdMaterial.BornAt) ||
		j.UserID != r.NetBirdMaterial.Authority.Context.ProducerUserID || j.MonthlyLimitMinor <= 0 || (j.Currency != "USD" && j.Currency != "BRL") || j.CleanupOwner == "" {
		return ErrOriginalSourceProducerHold
	}
	for index, region := range j.Regions {
		birth := (*r.OriginalSourceProducers)[index]
		if region.Cell != [3]string{"GRU", "SFO", "FRA"}[index] || region.OCIRegion != birth.Intent.OCIRegion || region.Generation != j.Generation ||
			region.ProducerIntentSHA256 != birth.IntentSHA256 || !validFoundationDigest(region.IntentSHA256) || region.OperationID != entityid.Derive("regional-foundation", r.TenancyID, region.Cell, fmt.Sprint(region.Generation)) ||
			index == 0 && (region.IntentSHA256 != j.GRUIntentSHA256 || region.OperationID != j.OperationID) {
			return ErrOriginalSourceProducerHold
		}
		for slot, entry := range region.Compartments {
			role := [2]string{"control_compartment", "network_compartment"}[slot]
			digest, err := originalCompartmentRequestSHA(entry.Request)
			if err != nil || entry.Role != role || deref(entry.Request.CompartmentId) != r.ParentCompartmentID ||
				deref(entry.Request.Name) != strings.ToLower(region.Cell)+"-1-"+strings.TrimSuffix(role, "_compartment") ||
				entry.SelectedID != "" && (!sourceCompartmentPattern.MatchString(entry.SelectedID) || entry.Pending != nil || entry.Provenance != nil || entry.HoldReason != "") ||
				index == 0 && slot == 0 && entry.SelectedID != birth.Intent.Escrow.CompartmentOCID {
				return ErrOriginalSourceProducerHold
			}
			if entry.Pending != nil {
				p := *entry.Pending
				if entry.SelectedID != "" || p.OperationID != region.OperationID || p.IntentDigest != region.IntentSHA256 || p.Request != originalCompartmentCreateIdentity(region, role, digest) ||
					p.FirstAttemptAt.IsZero() || p.FirstAttemptAt.Before(j.BornAt) || p.FirstAttemptAt.After(r.UpdatedAt) {
					return ErrOriginalSourceProducerHold
				}
			}
			if entry.Provenance != nil {
				p := *entry.Provenance
				if entry.Pending == nil || !sameOriginalSourceValue(p.Create, entry.Pending) || p.Generation != region.Generation || p.GrantSHA256 != j.GrantSHA256 || !sourceCompartmentPattern.MatchString(p.ResourceID) || entry.HoldReason != "" {
					return ErrOriginalSourceProducerHold
				}
			}
			if entry.HoldReason != "" && (entry.Pending == nil || !slices.Contains([]string{"create-refused", "retry-expired", "create-unresolved"}, entry.HoldReason)) {
				return ErrOriginalSourceProducerHold
			}
			if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() &&
				(entry.VerifiedAt.Before(j.BornAt) || entry.VerifiedAt.After(r.UpdatedAt) || !validFoundationDigest(entry.ReadbackSHA256) || entry.SelectedID == "" && entry.Provenance == nil) {
				return ErrOriginalSourceProducerHold
			}
			if entry.ReadbackSHA256 != "" {
				id := entry.SelectedID
				if entry.Provenance != nil {
					id = entry.Provenance.ResourceID
				}
				readback, err := json.Marshal([]string{id, deref(entry.Request.CompartmentId), deref(entry.Request.Name), "ACTIVE"}, json.Deterministic(true))
				if err != nil || entry.ReadbackSHA256 != digestSource(readback) {
					return ErrOriginalSourceProducerHold
				}
			}
		}
	}
	if err := r.validateOriginalFoundationNetwork(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationVault(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationActors(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationActorReads(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationSourceIAM(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationAdmissionReads(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationPublication(); err != nil {
		return err
	}
	if err := r.validateOriginalFoundationMaterialIAM(); err != nil {
		return err
	}
	if err := r.validateOriginalNetBirdManager(); err != nil {
		return err
	}
	return r.validateOriginalNetBirdBackup()
}

func (next FoundationRecord) retainOriginalFoundationCompartments(previous FoundationRecord) error {
	old, current := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if old == nil {
		if current != nil && (previous.Stage != "material" || !previous.netBirdMaterialOnly() || previous.NetBirdMaterial == nil || !previous.NetBirdMaterial.Complete) {
			return ErrOriginalSourceProducerHold
		}
		if err := next.retainOriginalFoundationVault(previous); err != nil {
			return err
		}
		if err := next.retainOriginalFoundationActors(previous); err != nil {
			return err
		}
		if err := next.retainOriginalFoundationActorReads(previous); err != nil {
			return err
		}
		if err := next.retainOriginalFoundationSourceIAM(previous); err != nil {
			return err
		}
		if err := next.retainOriginalFoundationAdmissionReads(previous); err != nil {
			return err
		}
		if err := next.retainOriginalFoundationPublication(previous); err != nil {
			return err
		}
		if err := next.retainOriginalFoundationMaterialIAM(previous); err != nil {
			return err
		}
		if err := next.retainOriginalNetBirdManager(previous); err != nil {
			return err
		}
		return next.retainOriginalNetBirdBackup(previous)
	}
	if current == nil || !sameOriginalSourceValue(old.scopeOnly(), current.scopeOnly()) {
		return ErrOriginalSourceProducerHold
	}
	for region := range old.Regions {
		for role, before := range old.Regions[region].Compartments {
			after := current.Regions[region].Compartments[role]
			if before.Pending != nil && !sameOriginalSourceValue(before.Pending, after.Pending) ||
				before.Provenance != nil && !sameOriginalSourceValue(before.Provenance, after.Provenance) ||
				before.HoldReason != "" && before.HoldReason != after.HoldReason ||
				before.ReadbackSHA256 != "" && before.ReadbackSHA256 != after.ReadbackSHA256 ||
				!before.VerifiedAt.IsZero() && !before.VerifiedAt.Equal(after.VerifiedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	if err := next.retainOriginalFoundationNetwork(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationVault(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationActors(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationActorReads(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationSourceIAM(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationAdmissionReads(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationPublication(previous); err != nil {
		return err
	}
	if err := next.retainOriginalFoundationMaterialIAM(previous); err != nil {
		return err
	}
	if err := next.retainOriginalNetBirdManager(previous); err != nil {
		return err
	}
	return next.retainOriginalNetBirdBackup(previous)
}
