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
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// InfrastructureSpendIntent authorizes fleet capacity explicitly inside the
// same root grant. Foundation creation's budget alone never authorizes growth.
type InfrastructureSpendIntent struct {
	BudgetID          string `json:"budgetId"`
	Currency          string `json:"currency"`
	MonthlyLimitMinor int64  `json:"monthlyLimitMinor"`
	ScopeSHA256       string `json:"scopeSha256"`
}

// VerifiedInfrastructureSpend cannot be manufactured from an observed OCI
// resource, a foundation record, or a tenant budget.
type VerifiedInfrastructureSpend struct {
	intent      InfrastructureSpendIntent
	footprint   capacityinventory.Scope
	grantDigest string
}

func (v VerifiedInfrastructureSpend) BudgetID() string         { return v.intent.BudgetID }
func (v VerifiedInfrastructureSpend) ScopeDigest() string      { return v.intent.ScopeSHA256 }
func (v VerifiedInfrastructureSpend) Currency() string         { return v.intent.Currency }
func (v VerifiedInfrastructureSpend) MonthlyLimitMinor() int64 { return v.intent.MonthlyLimitMinor }
func (v VerifiedInfrastructureSpend) ExpiresAt() time.Time     { return v.footprint.ExpiresAt }
func (v VerifiedInfrastructureSpend) GrantDigest() string      { return v.grantDigest }
func (v VerifiedInfrastructureSpend) IsVerified() bool         { return v.grantDigest != "" }
func (v VerifiedInfrastructureSpend) ValidAt(now time.Time) bool {
	return v.IsVerified() && now.Before(v.ExpiresAt())
}
func (v VerifiedInfrastructureSpend) Footprint() capacityinventory.Scope {
	scope := v.footprint
	scope.Regions = slices.Clone(scope.Regions)
	for i := range scope.Regions {
		scope.Regions[i].CompartmentIDs = slices.Clone(scope.Regions[i].CompartmentIDs)
	}
	return scope
}

// FoundationInfrastructureScopeDigest is the producer's canonical digest of
// every approved region and compartment. Envelope expiry separately bounds
// the sealed proof, and GrantDigest binds that exact signed envelope.
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
			if !ok || !strings.HasPrefix(id, "ocid1.compartment.oc1..") || len(id) > 255 || strings.ContainsAny(id, " \t\r\n") {
				return capacityinventory.Scope{}, errors.New("fleet spending requires exact signed regional compartment identities")
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
	scope.ExpiresAt = expires
	digest := sha256.Sum256(wire)
	return VerifiedInfrastructureSpend{intent: *intent, footprint: scope, grantDigest: hex.EncodeToString(digest[:])}, nil
}

func (r FoundationResolver) InfrastructureSpend(ctx context.Context) (VerifiedInfrastructureSpend, error) {
	reader, ok := r.Footprint.(interface {
		InfrastructureSpend(context.Context) (VerifiedInfrastructureSpend, error)
	})
	if !ok {
		return VerifiedInfrastructureSpend{}, errors.New("foundation reader has no signed fleet spend authority")
	}
	return reader.InfrastructureSpend(ctx)
}
