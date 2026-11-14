package budget

import (
	"context"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

const maxInfrastructureReservations = 64

var reservationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReservationRequest names the exact operation and immutable launch recipe.
// Authority and observed costs are obtained by the home, never accepted from a worker.
type ReservationRequest struct {
	OperationID   string    `json:"operation_id"`
	RecipeSHA256  string    `json:"recipe_sha256"`
	Cell          string    `json:"cell"`
	CompartmentID string    `json:"compartment_id"`
	Shape         string    `json:"shape"`
	OCPUs         float64   `json:"ocpus"`
	MemoryGB      float64   `json:"memory_gb"`
	BootGB        float64   `json:"boot_gb"`
	MonthlyCents  uint64    `json:"monthly_cents"`
	FactsExpireAt time.Time `json:"facts_expire_at"`
}

// Reservation remains a spending commitment after launch authorization expires.
// ResourceIDs are recorded only after positive owned-resource observations.
type Reservation struct {
	OperationID            string                `json:"operation_id"`
	RecipeSHA256           string                `json:"recipe_sha256"`
	Cell                   string                `json:"cell"`
	CompartmentID          string                `json:"compartment_id"`
	Shape                  string                `json:"shape"`
	OCPUs                  float64               `json:"ocpus"`
	MemoryGB               float64               `json:"memory_gb"`
	BootGB                 float64               `json:"boot_gb"`
	MonthlyCents           uint64                `json:"monthly_cents"`
	BudgetID               string                `json:"budget_id,omitempty"`
	InfrastructureBudgetID string                `json:"infrastructure_budget_id"`
	GrantSHA256            string                `json:"grant_sha256"`
	ScopeSHA256            string                `json:"scope_sha256"`
	ResolvedScopeSHA256    string                `json:"resolved_scope_sha256,omitempty"`
	BindingSHA256          string                `json:"binding_sha256,omitempty"`
	GrantGeneration        uint64                `json:"grant_generation,omitzero"`
	QuoteSHA256            string                `json:"quote_sha256,omitempty"`
	OriginalQuote          *capacityledger.Quote `json:"original_quote,omitempty"`
	Currency               string                `json:"currency,omitempty"`
	TenancyID              string                `json:"tenancy_id,omitempty"`
	IssuedAt               time.Time             `json:"issued_at"`
	LaunchExpiresAt        time.Time             `json:"launch_expires_at"`
	ResourceIDs            []string              `json:"resource_ids,omitempty"`
	RetiredAt              time.Time             `json:"retired_at,omitzero"`
}

// FinancialReceipt copies original accounting data. The protected root handler
// must independently authenticate the home reservation before accepting it.
func (r Reservation) FinancialReceipt() (capacityledger.Receipt, error) {
	if err := originalReservationQuote(r); err != nil {
		return capacityledger.Receipt{}, err
	}
	receipt := capacityledger.Receipt{OperationID: r.OperationID, RecipeSHA256: r.RecipeSHA256, GrantSHA256: r.GrantSHA256,
		GrantGeneration: r.GrantGeneration, LogicalScopeSHA256: r.ScopeSHA256, ResolvedScopeSHA256: r.ResolvedScopeSHA256,
		BindingSHA256: r.BindingSHA256, TenancyID: r.TenancyID, QuoteSHA256: r.QuoteSHA256, ReservedAt: r.IssuedAt, Quote: r.OriginalQuote.Clone()}
	return receipt, receipt.Validate()
}

// InfrastructureSpending records the exact complete observation used by the home.
// Tenant forecast documents preserve this ledger across periodic allocations.
type InfrastructureSpending struct {
	InfrastructureBudgetID string    `json:"infrastructure_budget_id"`
	GrantSHA256            string    `json:"grant_sha256"`
	ScopeSHA256            string    `json:"scope_sha256"`
	Currency               string    `json:"currency"`
	MonthlyLimitCents      uint64    `json:"monthly_limit_cents"`
	ProjectedCents         uint64    `json:"projected_cents"`
	ObservedAt             time.Time `json:"observed_at"`
	ExpiresAt              time.Time `json:"expires_at"`
}

func validGeometry(shape string, ocpus, memoryGB, bootGB float64) bool {
	return shape != "" && ocpus > 0 && memoryGB > 0 && bootGB > 0 && !math.IsInf(ocpus, 0) && !math.IsInf(memoryGB, 0) && !math.IsInf(bootGB, 0)
}

func validateReservations(c Capacity) error {
	if c.BootstrapReservedCents > maxMonthlyCapCents || (c.BootstrapReservedCents == 0) != (c.BootstrapSHA256 == "") || c.BootstrapSHA256 != "" && !reservationDigest.MatchString(c.BootstrapSHA256) {
		return errors.New("bootstrap allocation lacks its immutable finite slice and digest")
	}
	if len(c.Reservations) > maxInfrastructureReservations {
		return errors.New("infrastructure reservation ledger exceeds its bound")
	}
	for index, r := range c.Reservations {
		if !entityid.Valid(r.OperationID) || !reservationDigest.MatchString(r.RecipeSHA256) || !reservationDigest.MatchString(r.GrantSHA256) || !reservationDigest.MatchString(r.ScopeSHA256) || r.InfrastructureBudgetID == "" || r.Cell == "" || r.CompartmentID == "" || !validGeometry(r.Shape, r.OCPUs, r.MemoryGB, r.BootGB) || r.MonthlyCents == 0 || r.MonthlyCents > maxMonthlyCapCents || r.IssuedAt.IsZero() || !r.LaunchExpiresAt.After(r.IssuedAt) || len(r.ResourceIDs) > 16 || !slices.IsSorted(r.ResourceIDs) {
			return errors.New("infrastructure reservation is invalid")
		}
		if r.GrantGeneration == 0 {
			// Historical commitments remain charged but cannot authorize a new launch.
			if r.ResolvedScopeSHA256 != "" || r.BindingSHA256 != "" || r.QuoteSHA256 != "" || r.Currency != "" || r.TenancyID != "" {
				return errors.New("historical reservation has partial original authority metadata")
			}
		} else if !reservationDigest.MatchString(r.ResolvedScopeSHA256) || !reservationDigest.MatchString(r.QuoteSHA256) || r.BindingSHA256 != "" && !reservationDigest.MatchString(r.BindingSHA256) || !currencyCode.MatchString(r.Currency) || !strings.HasPrefix(r.TenancyID, "ocid1.tenancy.") {
			return errors.New("reservation lacks exact original physical binding, grant generation or sealed quote identity")
		}
		if r.OriginalQuote != nil {
			if err := originalReservationQuote(r); err != nil {
				return err
			}
		}
		if index > 0 && c.Reservations[index-1].OperationID >= r.OperationID {
			return errors.New("infrastructure reservations must be sorted by unique operation")
		}
		for i, id := range r.ResourceIDs {
			if id == "" || i > 0 && r.ResourceIDs[i-1] == id {
				return errors.New("reservation resource identities must be nonempty and unique")
			}
		}
		if !r.RetiredAt.IsZero() && (len(r.ResourceIDs) == 0 || r.RetiredAt.Before(r.IssuedAt)) {
			return errors.New("retired reservation lacks observed resource identities")
		}
	}
	if s := c.Spending; s != nil {
		if s.InfrastructureBudgetID == "" || !reservationDigest.MatchString(s.GrantSHA256) || !reservationDigest.MatchString(s.ScopeSHA256) || !currencyCode.MatchString(s.Currency) || s.MonthlyLimitCents > maxMonthlyCapCents || s.ObservedAt.IsZero() || !s.ExpiresAt.After(s.ObservedAt) {
			return errors.New("infrastructure spending observation is invalid")
		}
	}
	return nil
}

func spendingFacts(ctx context.Context, reader *globalcontrol.Reader, proof region.VerifiedInfrastructureSpend,
	snapshot capacityinventory.Snapshot, now time.Time,
) (Budget, bool, uint64, error) {
	if reader == nil {
		return Budget{}, false, 0, errors.New("infrastructure spending requires the home global reader")
	}
	if !proof.ValidAt(now) || proof.MonthlyLimitMinor() <= 0 || uint64(proof.MonthlyLimitMinor()) > maxMonthlyCapCents {
		return Budget{}, false, 0, errors.New("no current signed infrastructure spending authority")
	}
	if err := proof.RevalidateBindings(ctx); err != nil {
		return Budget{}, false, 0, err
	}
	if checkedAt := time.Now(); checkedAt.After(now) {
		now = checkedAt
	}
	if err := snapshot.Validate(proof.Footprint(), now); err != nil {
		return Budget{}, false, 0, err
	}
	monthly, found, err := ReadBudget(ctx, reader)
	if err != nil {
		return Budget{}, false, 0, err
	}
	limit := uint64(proof.MonthlyLimitMinor())
	if found {
		if monthly.Currency != proof.Currency() {
			return Budget{}, false, 0, errors.New("tenant and infrastructure spending currencies differ")
		}
		limit = min(limit, monthly.MonthlyCapCents)
	}
	return monthly, found, limit, nil
}

// bootstrapLimit never refunds a signed bootstrap slice on renewal or expiry.
// A changed allocation needs provider-proven fencing, for which no release path exists.
func bootstrapLimit(c Capacity, proof region.VerifiedInfrastructureSpend, limit uint64) (uint64, error) {
	if c.BootstrapSHA256 != "" && c.BootstrapSHA256 != proof.BootstrapDigest() {
		return 0, errors.New("bootstrap allocation changed without provider-proven fencing")
	}
	reserved := max(c.BootstrapReservedCents, uint64(proof.BootstrapReservedMinor()))
	if reserved > limit {
		return 0, errors.New("full bootstrap allocation exceeds the current infrastructure ceiling")
	}
	return limit - reserved, nil
}

func allowedCompartment(scope capacityinventory.Scope, cell, compartment string) bool {
	return slices.ContainsFunc(scope.Regions, func(r capacityinventory.RegionScope) bool {
		return r.Cell == cell && slices.Contains(r.CompartmentIDs, compartment)
	})
}

func reservationIndex(c Capacity, operation string) int {
	return slices.IndexFunc(c.Reservations, func(r Reservation) bool { return r.OperationID == operation })
}

func snapshotResource(snapshot capacityinventory.Snapshot, reservation Reservation, id string) (capacityinventory.Resource, bool) {
	i := slices.IndexFunc(snapshot.Resources, func(resource capacityinventory.Resource) bool {
		return resource.ID == id && resource.Cell == reservation.Cell && resource.CompartmentID == reservation.CompartmentID &&
			resource.OperationID == reservation.OperationID && resource.RecipeSHA256 == reservation.RecipeSHA256
	})
	if i < 0 {
		return capacityinventory.Resource{}, false
	}
	return snapshot.Resources[i], true
}

func retiredResource(state string) bool {
	return state == "TERMINATED" || state == "DELETED"
}

// projection counts an unknown provider outcome for its full reserved amount.
// Expiry changes launch permission; it never releases a billable commitment.
func projection(c Capacity, snapshot capacityinventory.Snapshot, excludeOperation string) uint64 {
	total := snapshot.MonthlyCents
	for _, r := range c.Reservations {
		if !r.RetiredAt.IsZero() || r.OperationID == excludeOperation {
			continue
		}
		covered := len(r.ResourceIDs) > 0
		for _, id := range r.ResourceIDs {
			resource, found := snapshotResource(snapshot, r, id)
			if !found || retiredResource(resource.LifecycleState) {
				covered = false
				break
			}
		}
		if !covered {
			total = saturatingAdd(total, r.MonthlyCents)
		}
	}
	return total
}

func currentReservation(r Reservation, tenantID string, proof region.VerifiedInfrastructureSpend, now time.Time) error {
	if !r.RetiredAt.IsZero() || !now.Before(r.LaunchExpiresAt) || r.BudgetID != tenantID || r.InfrastructureBudgetID != proof.BudgetID() || r.GrantSHA256 != proof.GrantDigest() || r.ScopeSHA256 != proof.ScopeDigest() || r.ResolvedScopeSHA256 != proof.PhysicalScopeDigest() || r.BindingSHA256 != proof.BindingDigest() || r.GrantGeneration != proof.Generation() || !reservationDigest.MatchString(r.QuoteSHA256) || r.Currency != proof.Currency() || r.TenancyID != proof.Footprint().TenancyID {
		return errors.New("reservation is retired, expired or differs from current spending authority")
	}
	return originalReservationQuote(r)
}

func originalReservationQuote(r Reservation) error {
	q := r.OriginalQuote
	if q == nil {
		return errors.New("historical reservation has no retained original tariff and cannot authorize a new launch")
	}
	if err := q.Validate(); err != nil {
		return err
	}
	if q.SHA256() != r.QuoteSHA256 || q.ScopeSHA256 != r.ResolvedScopeSHA256 || q.Cell != r.Cell || q.CompartmentID != r.CompartmentID ||
		q.Shape != r.Shape || q.OCPUs != r.OCPUs || q.MemoryGB != r.MemoryGB || q.BootGB != r.BootGB || q.MonthlyCents != r.MonthlyCents || q.Currency != r.Currency ||
		r.IssuedAt.Before(q.IssuedAt) || !r.IssuedAt.Before(q.ExpiresAt) {
		return errors.New("reservation differs from its original immutable tariff and billing geometry")
	}
	return nil
}

// Revalidate checks the durable receipt against current authority and complete costs.
// The caller also fences its own regional authority immediately before mutation.
func Revalidate(ctx context.Context, reader *globalcontrol.Reader, receipt Reservation,
	proof region.VerifiedInfrastructureSpend, quote capacityinventory.Quote, snapshot capacityinventory.Snapshot, now time.Time,
) error {
	if err := quotedCandidate(proof, quote, receipt.Cell, receipt.CompartmentID, receipt.Shape, receipt.OCPUs, receipt.MemoryGB, receipt.BootGB, receipt.MonthlyCents, now); err != nil {
		return err
	}
	monthly, found, limit, err := spendingFacts(ctx, reader, proof, snapshot, now)
	if err != nil {
		return err
	}
	c, exists, err := ReadCapacity(ctx, reader)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("capacity reservation ledger is unavailable")
	}
	limit, err = bootstrapLimit(c, proof, limit)
	if err != nil {
		return err
	}
	i := reservationIndex(c, receipt.OperationID)
	if i < 0 {
		return errors.New("capacity reservation was never committed")
	}
	r := c.Reservations[i]
	if err := sameOriginalReservation(r, receipt); err != nil {
		return err
	}
	tenantID := ""
	if found {
		tenantID = monthly.ID
	}
	if err := currentReservation(r, tenantID, proof, now); err != nil {
		return err
	}
	if projection(c, snapshot, "") > limit {
		return errors.New("complete infrastructure commitments exceed the current spending ceiling")
	}
	latest, hasBudget, err := ReadBudget(ctx, reader)
	if err != nil {
		return err
	}
	if hasBudget != found || hasBudget && latest != monthly {
		return errors.New("tenant spending ceiling changed during reservation revalidation")
	}
	// Independent SDK reads can outlast the facts checked before those reads.
	checkedAt := time.Now()
	if now.After(checkedAt) {
		checkedAt = now
	}
	if err := currentReservation(r, tenantID, proof, checkedAt); err != nil {
		return err
	}
	if err := snapshot.Validate(proof.Footprint(), checkedAt); err != nil {
		return err
	}
	return quotedCandidate(proof, quote, receipt.Cell, receipt.CompartmentID, receipt.Shape, receipt.OCPUs, receipt.MemoryGB, receipt.BootGB, receipt.MonthlyCents, checkedAt)
}

// RevalidateExisting checks an already billed child's original commitment, not
// launch permission. The root caller must separately prove its exact birth.
func RevalidateExisting(ctx context.Context, reader *globalcontrol.Reader, receipt Reservation,
	proof region.VerifiedInfrastructureSpend, snapshot capacityinventory.Snapshot, now time.Time,
) error {
	monthly, found, limit, err := spendingFacts(ctx, reader, proof, snapshot, now)
	if err != nil {
		return err
	}
	c, exists, err := ReadCapacity(ctx, reader)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("capacity reservation ledger is unavailable")
	}
	limit, err = bootstrapLimit(c, proof, limit)
	if err != nil {
		return err
	}
	i := reservationIndex(c, receipt.OperationID)
	if i < 0 {
		return errors.New("capacity reservation was never committed")
	}
	r := c.Reservations[i]
	if err := sameOriginalReservation(r, receipt); err != nil {
		return err
	}
	tenantID := ""
	if found {
		tenantID = monthly.ID
	}
	if err := existingReservation(r, tenantID, proof, now); err != nil {
		return err
	}
	if projection(c, snapshot, "") > limit {
		return errors.New("complete infrastructure commitments exceed the current spending ceiling")
	}
	if err := proof.RevalidateBindings(ctx); err != nil {
		return err
	}
	current, stillExists, err := ReadCapacity(ctx, reader)
	if err != nil {
		return err
	}
	expected, expectedErr := c.Encode()
	actual, actualErr := current.Encode()
	if !stillExists || expectedErr != nil || actualErr != nil || !sameCapacity(actual, expected) {
		return errors.New("capacity commitments changed during existing commitment revalidation")
	}
	latest, hasBudget, err := ReadBudget(ctx, reader)
	if err != nil {
		return err
	}
	if hasBudget != found || hasBudget && latest != monthly {
		return errors.New("tenant spending ceiling changed during existing commitment revalidation")
	}
	checkedAt := time.Now()
	if now.After(checkedAt) {
		checkedAt = now
	}
	if err := existingReservation(r, tenantID, proof, checkedAt); err != nil {
		return err
	}
	return snapshot.Validate(proof.Footprint(), checkedAt)
}

func sameOriginalReservation(r, receipt Reservation) error {
	if err := originalReservationQuote(receipt); err != nil {
		return err
	}
	if r.OperationID != receipt.OperationID || r.RecipeSHA256 != receipt.RecipeSHA256 || r.MonthlyCents != receipt.MonthlyCents || r.Cell != receipt.Cell || r.CompartmentID != receipt.CompartmentID || r.Shape != receipt.Shape || r.OCPUs != receipt.OCPUs || r.MemoryGB != receipt.MemoryGB || r.BootGB != receipt.BootGB || r.InfrastructureBudgetID != receipt.InfrastructureBudgetID || r.GrantSHA256 != receipt.GrantSHA256 || r.ScopeSHA256 != receipt.ScopeSHA256 || r.ResolvedScopeSHA256 != receipt.ResolvedScopeSHA256 || r.BindingSHA256 != receipt.BindingSHA256 || r.GrantGeneration != receipt.GrantGeneration || r.QuoteSHA256 != receipt.QuoteSHA256 || r.Currency != receipt.Currency || r.TenancyID != receipt.TenancyID || r.BudgetID != receipt.BudgetID || !r.IssuedAt.Equal(receipt.IssuedAt) || !r.LaunchExpiresAt.Equal(receipt.LaunchExpiresAt) {
		return errors.New("capacity receipt differs from its durable reservation")
	}
	return originalReservationQuote(r)
}

func existingReservation(r Reservation, tenantID string, proof region.VerifiedInfrastructureSpend, now time.Time) error {
	if !proof.ValidAt(now) || !r.RetiredAt.IsZero() || r.IssuedAt.After(now) || r.BudgetID != tenantID || r.InfrastructureBudgetID != proof.BudgetID() ||
		r.ScopeSHA256 != proof.ScopeDigest() || r.ResolvedScopeSHA256 != proof.PhysicalScopeDigest() || r.GrantGeneration == 0 || r.GrantGeneration > proof.Generation() ||
		r.GrantGeneration == proof.Generation() && r.GrantSHA256 != proof.GrantDigest() || r.Currency != proof.Currency() || r.TenancyID != proof.Footprint().TenancyID ||
		!allowedCompartment(proof.Footprint(), r.Cell, r.CompartmentID) {
		return errors.New("existing commitment is retired or differs from current signed spending scope")
	}
	return originalReservationQuote(r)
}

func quotedCandidate(proof region.VerifiedInfrastructureSpend, quote capacityinventory.Quote,
	cell, compartment, shape string, ocpus, memoryGB, bootGB float64, monthlyCents uint64, now time.Time,
) error {
	if err := quote.Validate(proof.Footprint(), cell, compartment, shape, ocpus, memoryGB, bootGB, now); err != nil {
		return err
	}
	if quote.Currency() != proof.Currency() || quote.MonthlyCents() != monthlyCents {
		return errors.New("candidate price differs from the sealed quote or spending currency")
	}
	return nil
}
