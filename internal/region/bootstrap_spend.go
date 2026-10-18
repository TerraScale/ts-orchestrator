package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
)

const bootstrapRetryLifetime = 23 * time.Hour

var bootstrapSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var bootstrapSlotName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// BootstrapSpendingIntent partitions the same signed infrastructure ceiling.
// Every slot is one host; home always withholds the full slice from ordinary growth.
type BootstrapSpendingIntent struct {
	ReservedMinor int64                 `json:"reservedMinor"`
	Slots         []BootstrapSlotIntent `json:"slots"`
}

type BootstrapSlotIntent struct {
	SlotID            string  `json:"slotId"`
	Cell              string  `json:"cell"`
	Role              string  `json:"role"`
	Slot              string  `json:"slot"`
	CompartmentID     string  `json:"compartmentId"`
	ProfileSHA256     string  `json:"profileSha256"`
	RecipeSHA256      string  `json:"recipeSha256"`
	Shape             string  `json:"shape"`
	OCPUs             float64 `json:"ocpus"`
	MemoryGB          float64 `json:"memoryGb"`
	BootGB            float64 `json:"bootGb"`
	MonthlyLimitMinor int64   `json:"monthlyLimitMinor"`
}

// BootstrapLaunchRequest describes the exact compiled request held by the
// foundation CAS. The provider adapter must hash and compare the actual SDK body.
type BootstrapLaunchRequest struct {
	SlotID, OperationID, Cell, CompartmentID string
	ProfileSHA256, RecipeSHA256, Shape       string
	OCPUs, MemoryGB, BootGB                  float64
	RequestSHA256, RetryToken                string
	StartedAt                                time.Time
}

// VerifiedBootstrapAllocation can only come from the same root-verified grant.
// It carries no NATS or home-writer prerequisite.
type VerifiedBootstrapAllocation struct {
	spending     VerifiedInfrastructureSpend
	slot         BootstrapSlotIntent
	originalSlot BootstrapSlotIntent
}

func BootstrapSlotID(installation, cell, role, slot string) string {
	return entityid.Derive("foundation-host-slot", installation, strings.ToUpper(cell), role, slot)
}

func BootstrapOperationID(installation, slotID string) string {
	return entityid.Derive("foundation-host-operation", installation, slotID)
}

func BootstrapRetryToken(operationID, requestSHA256 string) string {
	sum := sha256.Sum256([]byte("foundation-host-request:" + operationID + ":" + requestSHA256))
	return hex.EncodeToString(sum[:])
}

// ValidateBootstrapSpending validates explicit input before the existing root
// signing ceremony. It neither signs nor manufactures spending authority.
func ValidateBootstrapSpending(grant FoundationGrant) error {
	scope, err := infrastructureScope(grant)
	if err != nil {
		return err
	}
	return validateBootstrapSpending(grant, scope)
}

func validateBootstrapSpending(grant FoundationGrant, scope capacityinventory.Scope) error {
	spending := grant.InfrastructureSpend
	if spending == nil || spending.Bootstrap == nil {
		return nil
	}
	allocation := spending.Bootstrap
	if spending.Currency != grant.Currency || !entityid.Valid(grant.InstallationID) || grant.Generation == 0 || spending.MonthlyLimitMinor <= 0 || spending.MonthlyLimitMinor > grant.MonthlyLimitMinor || allocation.ReservedMinor <= 0 || allocation.ReservedMinor > spending.MonthlyLimitMinor || len(allocation.Slots) == 0 || len(allocation.Slots) > 64 {
		return errors.New("bootstrap allocation lacks a finite positive slice within the same infrastructure ceiling")
	}
	seen := map[string]bool{}
	var total int64
	for _, slot := range allocation.Slots {
		owned := slices.ContainsFunc(scope.Regions, func(r capacityinventory.RegionScope) bool {
			return r.Cell == slot.Cell && slices.Contains(r.CompartmentIDs, slot.CompartmentID)
		})
		if !owned || (slot.Role != "controller" && slot.Role != "netbird-manager") || !bootstrapSlotName.MatchString(slot.Slot) || slot.Role == "netbird-manager" && (slot.Slot != "netbird-manager" || slot.Cell != "GRU") ||
			slot.SlotID != BootstrapSlotID(grant.InstallationID, slot.Cell, slot.Role, slot.Slot) || seen[slot.SlotID] || !bootstrapSHA256.MatchString(slot.ProfileSHA256) || !bootstrapSHA256.MatchString(slot.RecipeSHA256) || slot.Shape == "" ||
			!positiveBootstrapDimension(slot.OCPUs) || !positiveBootstrapDimension(slot.MemoryGB) || !positiveBootstrapDimension(slot.BootGB) || slot.MonthlyLimitMinor <= 0 || slot.MonthlyLimitMinor > allocation.ReservedMinor-total {
			return errors.New("bootstrap slot differs from its exact signed identity, recipe, billing geometry or finite allocation")
		}
		seen[slot.SlotID] = true
		total += slot.MonthlyLimitMinor
	}
	return nil
}

func positiveBootstrapDimension(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func (s *SignedFootprint) BootstrapAllocation(ctx context.Context, slotID string) (VerifiedBootstrapAllocation, error) {
	spending, err := s.infrastructureSpend(ctx, nil, slotID)
	if err != nil {
		return VerifiedBootstrapAllocation{}, err
	}
	return spending.bootstrapAllocation(slotID)
}

func (r FoundationResolver) BootstrapAllocation(ctx context.Context, slotID string) (VerifiedBootstrapAllocation, error) {
	if signed, ok := r.Footprint.(*SignedFootprint); ok {
		spending, err := signed.infrastructureSpend(ctx, r.ResourceBindingsFor, slotID)
		if err != nil {
			return VerifiedBootstrapAllocation{}, err
		}
		return spending.bootstrapAllocation(slotID)
	}
	spending, err := r.InfrastructureSpend(ctx)
	if err != nil {
		return VerifiedBootstrapAllocation{}, err
	}
	return spending.bootstrapAllocation(slotID)
}

func (v VerifiedInfrastructureSpend) bootstrapAllocation(slotID string) (VerifiedBootstrapAllocation, error) {
	if v.intent.Bootstrap != nil {
		for _, original := range v.intent.Bootstrap.Slots {
			if original.SlotID == slotID {
				slot := original
				if actual, ok := v.resolved[slot.CompartmentID]; ok {
					slot.CompartmentID = actual
				}
				if !physicalCompartmentID(slot.CompartmentID) {
					return VerifiedBootstrapAllocation{}, errors.New("bootstrap slot lacks its exact independently verified physical compartment")
				}
				return VerifiedBootstrapAllocation{spending: v, slot: slot, originalSlot: original}, nil
			}
		}
	}
	return VerifiedBootstrapAllocation{}, errors.New("same root grant has no finite allocation for this bootstrap slot")
}

func (v VerifiedBootstrapAllocation) Slot() BootstrapSlotIntent       { return v.slot }
func (v VerifiedBootstrapAllocation) SignedSlot() BootstrapSlotIntent { return v.originalSlot }
func (v VerifiedBootstrapAllocation) ScopeDigest() string             { return v.spending.ScopeDigest() }
func (v VerifiedBootstrapAllocation) PhysicalScopeDigest() string {
	return v.spending.PhysicalScopeDigest()
}
func (v VerifiedBootstrapAllocation) BindingDigest() string { return v.spending.BindingDigest() }
func (v VerifiedBootstrapAllocation) Revalidate(ctx context.Context) error {
	return v.spending.RevalidateBindings(ctx)
}
func (v VerifiedBootstrapAllocation) IsVerified() bool {
	return v.spending.IsVerified() && v.slot.SlotID != ""
}
func (v VerifiedBootstrapAllocation) InstallationID() string { return v.spending.installation }
func (v VerifiedBootstrapAllocation) Generation() uint64     { return v.spending.generation }
func (v VerifiedBootstrapAllocation) BudgetID() string       { return v.spending.BudgetID() }
func (v VerifiedBootstrapAllocation) GrantDigest() string    { return v.spending.GrantDigest() }
func (v VerifiedBootstrapAllocation) TenancyID() string      { return v.spending.footprint.TenancyID }
func (v VerifiedBootstrapAllocation) Footprint() capacityinventory.Scope {
	return v.spending.Footprint()
}
func (v VerifiedBootstrapAllocation) ReservedMinor() int64 {
	return v.spending.BootstrapReservedMinor()
}
func (v VerifiedBootstrapAllocation) ExpiresAt() time.Time { return v.spending.ExpiresAt() }
func (v VerifiedBootstrapAllocation) OperationID() string {
	return BootstrapOperationID(v.InstallationID(), v.slot.SlotID)
}

func (v VerifiedBootstrapAllocation) Validate(request BootstrapLaunchRequest, quote capacityinventory.Quote, now time.Time) error {
	if !v.IsVerified() || !v.spending.ValidAt(now) {
		return errors.New("current root-signed bootstrap allocation is unavailable")
	}
	slot := v.slot
	if request.SlotID != slot.SlotID || request.OperationID != v.OperationID() || request.Cell != slot.Cell || request.CompartmentID != slot.CompartmentID || request.ProfileSHA256 != slot.ProfileSHA256 || request.RecipeSHA256 != slot.RecipeSHA256 || request.Shape != slot.Shape ||
		request.OCPUs != slot.OCPUs || request.MemoryGB != slot.MemoryGB || request.BootGB != slot.BootGB || !bootstrapSHA256.MatchString(request.RequestSHA256) || request.RetryToken != BootstrapRetryToken(request.OperationID, request.RequestSHA256) ||
		request.StartedAt.IsZero() || request.StartedAt.After(now) || !now.Before(request.StartedAt.Add(bootstrapRetryLifetime)) {
		return errors.New("bootstrap launch differs from its immutable slot or durable bounded request token")
	}
	if err := quote.Validate(v.Footprint(), slot.Cell, slot.CompartmentID, slot.Shape, slot.OCPUs, slot.MemoryGB, slot.BootGB, now); err != nil {
		return err
	}
	if quote.Currency() != v.spending.Currency() || quote.MonthlyCents() == 0 || quote.MonthlyCents() > uint64(slot.MonthlyLimitMinor) {
		return errors.New("bootstrap launch price exceeds its finite signed monthly allocation")
	}
	return nil
}
