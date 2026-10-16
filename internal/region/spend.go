package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// InfrastructureSpendIntent authorizes fleet capacity explicitly inside the
// same root grant. Foundation creation's budget alone never authorizes growth.
type InfrastructureSpendIntent struct {
	BudgetID          string                   `json:"budgetId"`
	Currency          string                   `json:"currency"`
	MonthlyLimitMinor int64                    `json:"monthlyLimitMinor"`
	ScopeSHA256       string                   `json:"scopeSha256"`
	Bootstrap         *BootstrapSpendingIntent `json:"bootstrap,omitempty"`
}

// VerifiedInfrastructureSpend cannot be manufactured from an observed OCI
// resource, a foundation record, or a tenant budget.
type VerifiedInfrastructureSpend struct {
	intent        InfrastructureSpendIntent
	footprint     capacityinventory.Scope
	grantDigest   string
	installation  string
	generation    uint64
	bindings      []foundationbinding.VerifiedBindings
	bindingsAt    time.Time
	bindingSHA256 string
	resolved      map[string]string
}

func (v VerifiedInfrastructureSpend) InstallationID() string      { return v.installation }
func (v VerifiedInfrastructureSpend) Generation() uint64          { return v.generation }
func (v VerifiedInfrastructureSpend) PhysicalScopeDigest() string { return v.footprint.SHA256 }
func (v VerifiedInfrastructureSpend) BudgetID() string            { return v.intent.BudgetID }
func (v VerifiedInfrastructureSpend) ScopeDigest() string         { return v.intent.ScopeSHA256 }
func (v VerifiedInfrastructureSpend) Currency() string            { return v.intent.Currency }
func (v VerifiedInfrastructureSpend) MonthlyLimitMinor() int64    { return v.intent.MonthlyLimitMinor }
func (v VerifiedInfrastructureSpend) ExpiresAt() time.Time        { return v.footprint.ExpiresAt }
func (v VerifiedInfrastructureSpend) GrantDigest() string         { return v.grantDigest }
func (v VerifiedInfrastructureSpend) IsVerified() bool            { return v.grantDigest != "" }
func (v VerifiedInfrastructureSpend) BindingDigest() string       { return v.bindingSHA256 }
func (v VerifiedInfrastructureSpend) BootstrapReservedMinor() int64 {
	if v.intent.Bootstrap == nil {
		return 0
	}
	return v.intent.Bootstrap.ReservedMinor
}
func (v VerifiedInfrastructureSpend) BootstrapDigest() string {
	if v.intent.Bootstrap == nil {
		return ""
	}
	wire, _ := json.Marshal(v.intent.Bootstrap, json.Deterministic(true))
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
func (v VerifiedInfrastructureSpend) ValidAt(now time.Time) bool {
	return v.IsVerified() && now.Before(v.ExpiresAt()) && (len(v.bindings) == 0 || !v.bindingsAt.After(now) && now.Sub(v.bindingsAt) <= 2*time.Minute)
}
func (v VerifiedInfrastructureSpend) Footprint() capacityinventory.Scope {
	scope := v.footprint
	scope.Regions = slices.Clone(scope.Regions)
	for i := range scope.Regions {
		scope.Regions[i].CompartmentIDs = slices.Clone(scope.Regions[i].CompartmentIDs)
	}
	return scope
}

// FoundationInfrastructureScopeDigest hashes the original signed compartment
// authority. Schema 2 uses canonical logical roles for resources not yet created;
// their later physical inventory scope has a separate digest.
func FoundationInfrastructureScopeDigest(grant FoundationGrant) (string, error) {
	scope, err := infrastructureScope(grant)
	if err != nil {
		return "", err
	}
	return scope.SHA256, nil
}

func infrastructureScope(grant FoundationGrant) (capacityinventory.Scope, error) {
	footprint := ApprovedFootprint{TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Regions: grant.Regions}
	if err := validateFootprint(footprint); err != nil {
		return capacityinventory.Scope{}, err
	}
	scope := capacityinventory.Scope{TenancyID: grant.TenancyID, Currency: grant.Currency}
	for _, intent := range grant.Regions {
		ids := intent.Plan["resource_ids"].(map[string]any)
		compartments := []string{grant.ParentCompartmentID, grant.SharedCompartmentID}
		for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment"} {
			id, ok := ids[key].(string)
			if grant.SchemaVersion == 2 {
				ref, err := FoundationResourceReference(intent.Plan["cell"].(string), key)
				if err != nil {
					return capacityinventory.Scope{}, err
				}
				if ids[key] == nil || ok && id == "" {
					id, ok = ref, true
				}
				if id == ref {
					compartments = append(compartments, id)
					continue
				}
			}
			if !ok || !physicalCompartmentID(id) {
				return capacityinventory.Scope{}, errors.New("fleet spending requires exact signed compartment identities or canonical schema-2 roles")
			}
			compartments = append(compartments, id)
		}
		slices.Sort(compartments)
		compartments = slices.Compact(compartments)
		scope.Regions = append(scope.Regions, capacityinventory.RegionScope{Cell: intent.Plan["cell"].(string), OCIRegion: intent.Plan["region"].(string), CompartmentIDs: compartments})
	}
	slices.SortFunc(scope.Regions, func(a, b capacityinventory.RegionScope) int { return strings.Compare(a.Cell, b.Cell) })
	wire, err := json.Marshal(struct {
		TenancyID           string                          `json:"tenancyId"`
		ParentCompartmentID string                          `json:"parentCompartmentId"`
		SharedCompartmentID string                          `json:"sharedCompartmentId"`
		Currency            string                          `json:"currency"`
		Regions             []capacityinventory.RegionScope `json:"regions"`
	}{grant.TenancyID, grant.ParentCompartmentID, grant.SharedCompartmentID, grant.Currency, scope.Regions}, json.Deterministic(true))
	if err != nil {
		return capacityinventory.Scope{}, err
	}
	digest := sha256.Sum256(wire)
	scope.SHA256 = hex.EncodeToString(digest[:])
	return scope, nil
}

func (s *SignedFootprint) InfrastructureSpend(ctx context.Context) (VerifiedInfrastructureSpend, error) {
	return s.infrastructureSpend(ctx, nil, "")
}

func (s *SignedFootprint) infrastructureSpend(ctx context.Context, resolve func(context.Context, string, ...string) (foundationbinding.VerifiedBindings, error), bootstrapSlotID string) (VerifiedInfrastructureSpend, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	_, expires, err := s.verifyGrant(wire)
	if err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	intent := grant.InfrastructureSpend
	if intent == nil || !entityid.Valid(intent.BudgetID) || intent.Currency != grant.Currency || intent.MonthlyLimitMinor <= 0 || intent.MonthlyLimitMinor > grant.MonthlyLimitMinor {
		return VerifiedInfrastructureSpend{}, errors.New("same root grant lacks explicit fleet spend authority within its numerical budget")
	}
	scope, err := infrastructureScope(grant)
	if err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	if intent.ScopeSHA256 != scope.SHA256 {
		return VerifiedInfrastructureSpend{}, errors.New("fleet spend authority differs from exact signed regional footprint")
	}
	if err := validateBootstrapSpending(grant, scope); err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	if bootstrapSlotID != "" {
		var selected *BootstrapSlotIntent
		if intent.Bootstrap != nil {
			for _, slot := range intent.Bootstrap.Slots {
				if slot.SlotID == bootstrapSlotID {
					selected = new(slot)
					break
				}
			}
		}
		if selected == nil {
			return VerifiedInfrastructureSpend{}, errors.New("same root grant has no finite allocation for this bootstrap slot")
		}
		for _, region := range scope.Regions {
			if region.Cell == selected.Cell {
				region.CompartmentIDs = []string{selected.CompartmentID}
				scope.Regions = []capacityinventory.RegionScope{region}
				break
			}
		}
	}
	scope.ExpiresAt = expires
	digest := sha256.Sum256(wire)
	spending := VerifiedInfrastructureSpend{intent: *intent, footprint: scope, grantDigest: hex.EncodeToString(digest[:]), installation: grant.InstallationID, generation: grant.Generation}
	if err := spending.bindInfrastructureScope(ctx, resolve, bootstrapSlotID != ""); err != nil {
		return VerifiedInfrastructureSpend{}, err
	}
	return spending, nil
}

func (r FoundationResolver) InfrastructureSpend(ctx context.Context) (VerifiedInfrastructureSpend, error) {
	if signed, ok := r.Footprint.(*SignedFootprint); ok {
		return signed.infrastructureSpend(ctx, r.ResourceBindingsFor, "")
	}
	reader, ok := r.Footprint.(interface {
		InfrastructureSpend(context.Context) (VerifiedInfrastructureSpend, error)
	})
	if !ok {
		return VerifiedInfrastructureSpend{}, errors.New("foundation reader has no signed fleet spend authority")
	}
	return reader.InfrastructureSpend(ctx)
}

func physicalCompartmentID(id string) bool {
	return strings.HasPrefix(id, "ocid1.compartment.oc1..") && len(id) <= 255 && !strings.ContainsAny(id, " \t\r\n")
}

// RevalidateBindings repeats the independent grant, durable creation and SDK
// checks. It grants no spending and never changes the original signed scope.
func (v VerifiedInfrastructureSpend) RevalidateBindings(ctx context.Context) error {
	if !v.ValidAt(time.Now()) {
		return errors.New("current signed spending scope or verified physical bindings are unavailable")
	}
	for _, bindings := range v.bindings {
		if bindings.GrantSHA256() != v.grantDigest || bindings.Generation() != v.generation {
			return errors.New("physical bindings differ from the exact original grant and generation")
		}
		if err := bindings.Revalidate(ctx); err != nil {
			return err
		}
	}
	if !v.ValidAt(time.Now()) {
		return errors.New("physical binding revalidation outlived its current evidence")
	}
	return nil
}

func (v *VerifiedInfrastructureSpend) bindInfrastructureScope(ctx context.Context, resolve func(context.Context, string, ...string) (foundationbinding.VerifiedBindings, error), subset bool) error {
	type linkage struct {
		Cell, Reference, ResourceID, GrantSHA256 string
		Generation                               uint64
	}
	started := time.Now()
	var links []linkage
	physical := v.Footprint()
	v.resolved = map[string]string{}
	for i := range physical.Regions {
		region := &physical.Regions[i]
		var keys []string
		for _, id := range region.CompartmentIDs {
			if physicalCompartmentID(id) {
				continue
			}
			cell, key, err := foundationbinding.Parse(id)
			if err != nil || cell != region.Cell {
				return errors.New("spending role is not the exact canonical reference for its signed cell")
			}
			keys = append(keys, key)
		}
		var bindings foundationbinding.VerifiedBindings
		bound := false
		for j, id := range region.CompartmentIDs {
			if physicalCompartmentID(id) {
				continue
			}
			if resolve == nil {
				return errors.New("logical spending scope requires independently verified foundation bindings")
			}
			if !bound {
				var err error
				bindings, err = resolve(ctx, region.Cell, keys...)
				if err != nil {
					return err
				}
				if bindings.GrantSHA256() != v.grantDigest || bindings.Generation() != v.generation || bindings.Cell() != region.Cell {
					return errors.New("foundation bindings differ from the exact signed spending grant, generation or cell")
				}
				if !bindings.ExpiresAt().After(time.Now()) {
					return errors.New("independently verified physical bindings have expired")
				}
				if bindings.ExpiresAt().Before(physical.ExpiresAt) {
					physical.ExpiresAt = bindings.ExpiresAt()
				}
				v.bindings = append(v.bindings, bindings)
				bound = true
			}
			actual, err := bindings.Resolve(id)
			if err != nil {
				return err
			}
			if !physicalCompartmentID(actual) {
				return errors.New("verified spending compartment is not an exact physical OCI identity")
			}
			region.CompartmentIDs[j], v.resolved[id] = actual, actual
			links = append(links, linkage{region.Cell, id, actual, v.grantDigest, v.generation})
		}
		slices.Sort(region.CompartmentIDs)
		if len(slices.Compact(slices.Clone(region.CompartmentIDs))) != len(region.CompartmentIDs) {
			return errors.New("distinct signed spending roles resolved to the same compartment")
		}
	}
	if len(links) == 0 && !subset {
		return nil
	}
	if len(links) > 0 {
		wire, err := json.Marshal(links, json.Deterministic(true))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(wire)
		v.bindingSHA256 = hex.EncodeToString(digest[:])
	}
	wire, err := json.Marshal(struct {
		SignedScopeSHA256   string
		TenancyID, Currency string
		Regions             []capacityinventory.RegionScope
	}{v.ScopeDigest(), physical.TenancyID, physical.Currency, physical.Regions}, json.Deterministic(true))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(wire)
	physical.SHA256 = hex.EncodeToString(digest[:])
	v.footprint = physical
	if len(v.bindings) > 0 {
		v.bindingsAt = started
		if !v.ValidAt(time.Now()) {
			return errors.New("foundation binding observation exceeded its freshness bound")
		}
	}
	return nil
}
