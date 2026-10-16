package budget

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
	OperationID            string    `json:"operation_id"`
	RecipeSHA256           string    `json:"recipe_sha256"`
	Cell                   string    `json:"cell"`
	CompartmentID          string    `json:"compartment_id"`
	Shape                  string    `json:"shape"`
	OCPUs                  float64   `json:"ocpus"`
	MemoryGB               float64   `json:"memory_gb"`
	BootGB                 float64   `json:"boot_gb"`
	MonthlyCents           uint64    `json:"monthly_cents"`
	BudgetID               string    `json:"budget_id,omitempty"`
	InfrastructureBudgetID string    `json:"infrastructure_budget_id"`
	GrantSHA256            string    `json:"grant_sha256"`
	ScopeSHA256            string    `json:"scope_sha256"`
	ResolvedScopeSHA256    string    `json:"resolved_scope_sha256,omitempty"`
	BindingSHA256          string    `json:"binding_sha256,omitempty"`
	GrantGeneration        uint64    `json:"grant_generation,omitzero"`
	QuoteSHA256            string    `json:"quote_sha256,omitempty"`
	Currency               string    `json:"currency,omitempty"`
	TenancyID              string    `json:"tenancy_id,omitempty"`
	IssuedAt               time.Time `json:"issued_at"`
	LaunchExpiresAt        time.Time `json:"launch_expires_at"`
	ResourceIDs            []string  `json:"resource_ids,omitempty"`
	RetiredAt              time.Time `json:"retired_at,omitzero"`
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

func (r ReservationRequest) validate(now time.Time) error {
	if !entityid.Valid(r.OperationID) || !reservationDigest.MatchString(r.RecipeSHA256) || r.Cell == "" || r.CompartmentID == "" || !validGeometry(r.Shape, r.OCPUs, r.MemoryGB, r.BootGB) || r.MonthlyCents == 0 || r.MonthlyCents > maxMonthlyCapCents || !now.Before(r.FactsExpireAt) {
		return errors.New("capacity reservation lacks exact operation, recipe, positive known cost or current facts")
	}
	return nil
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

// retainBootstrap preserves the original allocation identity and the largest
// verified slice, including during held planning and historical observations.
func retainBootstrap(c *Capacity, proof region.VerifiedInfrastructureSpend) error {
	if !proof.IsVerified() || proof.BootstrapReservedMinor() <= 0 {
		return nil
	}
	reserved := uint64(proof.BootstrapReservedMinor())
	if reserved > maxMonthlyCapCents {
		return errors.New("bootstrap allocation exceeds the supported finite ceiling")
	}
	c.BootstrapReservedCents = max(c.BootstrapReservedCents, reserved)
	if c.BootstrapSHA256 == "" {
		c.BootstrapSHA256 = proof.BootstrapDigest()
	}
	return nil
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

// InfrastructureHeadroom filters candidates before Reserve; it never authorizes
// mutation. An exact operation retry already owns its outstanding commitment.
func InfrastructureHeadroom(ctx context.Context, reader *globalcontrol.Reader, proof region.VerifiedInfrastructureSpend,
	snapshot capacityinventory.Snapshot, operationID string, now time.Time,
) (uint64, error) {
	monthly, found, limit, err := spendingFacts(ctx, reader, proof, snapshot, now)
	if err != nil {
		return 0, err
	}
	c, _, err := ReadCapacity(ctx, reader)
	if err != nil {
		return 0, err
	}
	limit, err = bootstrapLimit(c, proof, limit)
	if err != nil {
		return 0, err
	}
	exclude := ""
	if i := reservationIndex(c, operationID); i >= 0 {
		tenantID := ""
		if found {
			tenantID = monthly.ID
		}
		if err := currentReservation(c.Reservations[i], tenantID, proof, now); err != nil {
			return 0, err
		}
		exclude = operationID
	}
	total := projection(c, snapshot, exclude)
	latest, hasBudget, err := ReadBudget(ctx, reader)
	if err != nil {
		return 0, err
	}
	if hasBudget != found || hasBudget && latest != monthly {
		return 0, errors.New("tenant spending ceiling changed during candidate selection")
	}
	if total >= limit {
		return 0, nil
	}
	return limit - total, nil
}

// Reserve appends an idempotent exact-candidate commitment under the home CAS.
// A tenant budget can tighten the signed infrastructure ceiling, never expand it.
func Reserve(ctx context.Context, reader *globalcontrol.Reader, writer *globalcontrol.Writer, epoch uint64,
	request ReservationRequest, proof region.VerifiedInfrastructureSpend, quote capacityinventory.Quote, snapshot capacityinventory.Snapshot, now time.Time,
) (Reservation, error) {
	if err := request.validate(now); err != nil {
		return Reservation{}, err
	}
	if !allowedCompartment(proof.Footprint(), request.Cell, request.CompartmentID) {
		return Reservation{}, errors.New("candidate is outside the signed infrastructure footprint")
	}
	if err := quotedCandidate(proof, quote, request.Cell, request.CompartmentID, request.Shape, request.OCPUs, request.MemoryGB, request.BootGB, request.MonthlyCents, now); err != nil {
		return Reservation{}, err
	}
	var result Reservation
	err := changeReservations(ctx, reader, writer, epoch, proof, snapshot, now, true, func(c *Capacity, monthly Budget, found bool) error {
		checkedAt := time.Now()
		if now.After(checkedAt) {
			checkedAt = now
		}
		if err := request.validate(checkedAt); err != nil {
			return err
		}
		if err := quotedCandidate(proof, quote, request.Cell, request.CompartmentID, request.Shape, request.OCPUs, request.MemoryGB, request.BootGB, request.MonthlyCents, checkedAt); err != nil {
			return err
		}
		tenantID := ""
		if found {
			tenantID = monthly.ID
		}
		if i := reservationIndex(*c, request.OperationID); i >= 0 {
			r := c.Reservations[i]
			if r.RecipeSHA256 != request.RecipeSHA256 || r.MonthlyCents != request.MonthlyCents || r.Cell != request.Cell || r.CompartmentID != request.CompartmentID || r.Shape != request.Shape || r.OCPUs != request.OCPUs || r.MemoryGB != request.MemoryGB || r.BootGB != request.BootGB {
				return errors.New("operation is already reserved for a different candidate or price")
			}
			if err := currentReservation(r, tenantID, proof, checkedAt); err != nil {
				return err
			}
			result = r
			return nil
		}
		if len(c.Reservations) >= maxInfrastructureReservations {
			// shortcut: unknown commitments remain charged; add provider-proven cancellation before reclaiming entries.
			return errors.New("infrastructure reservation ledger is full")
		}
		expires := minTime(request.FactsExpireAt, proof.ExpiresAt(), quote.ExpiresAt(), snapshot.ExpiresAt, now.Add(ReservationTTL))
		result = Reservation{OperationID: request.OperationID, RecipeSHA256: request.RecipeSHA256, Cell: request.Cell,
			CompartmentID: request.CompartmentID, Shape: request.Shape, OCPUs: request.OCPUs, MemoryGB: request.MemoryGB, BootGB: request.BootGB, MonthlyCents: request.MonthlyCents, BudgetID: tenantID,
			InfrastructureBudgetID: proof.BudgetID(), GrantSHA256: proof.GrantDigest(), ScopeSHA256: proof.ScopeDigest(),
			ResolvedScopeSHA256: proof.PhysicalScopeDigest(), BindingSHA256: proof.BindingDigest(), GrantGeneration: proof.Generation(), QuoteSHA256: quote.SHA256(), Currency: proof.Currency(), TenancyID: proof.Footprint().TenancyID, IssuedAt: now, LaunchExpiresAt: expires}
		c.Reservations = append(slices.Clone(c.Reservations), result)
		slices.SortFunc(c.Reservations, func(a, b Reservation) int { return cmp.Compare(a.OperationID, b.OperationID) })
		return nil
	})
	return result, err
}

func currentReservation(r Reservation, tenantID string, proof region.VerifiedInfrastructureSpend, now time.Time) error {
	if !r.RetiredAt.IsZero() || !now.Before(r.LaunchExpiresAt) || r.BudgetID != tenantID || r.InfrastructureBudgetID != proof.BudgetID() || r.GrantSHA256 != proof.GrantDigest() || r.ScopeSHA256 != proof.ScopeDigest() || r.ResolvedScopeSHA256 != proof.PhysicalScopeDigest() || r.BindingSHA256 != proof.BindingDigest() || r.GrantGeneration != proof.Generation() || !reservationDigest.MatchString(r.QuoteSHA256) || r.Currency != proof.Currency() || r.TenancyID != proof.Footprint().TenancyID {
		return errors.New("reservation is retired, expired or differs from current spending authority")
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
	if r.RecipeSHA256 != receipt.RecipeSHA256 || r.MonthlyCents != receipt.MonthlyCents || r.Cell != receipt.Cell || r.CompartmentID != receipt.CompartmentID || r.Shape != receipt.Shape || r.OCPUs != receipt.OCPUs || r.MemoryGB != receipt.MemoryGB || r.BootGB != receipt.BootGB || r.InfrastructureBudgetID != receipt.InfrastructureBudgetID || r.GrantSHA256 != receipt.GrantSHA256 || r.ScopeSHA256 != receipt.ScopeSHA256 || r.ResolvedScopeSHA256 != receipt.ResolvedScopeSHA256 || r.BindingSHA256 != receipt.BindingSHA256 || r.GrantGeneration != receipt.GrantGeneration || r.QuoteSHA256 != receipt.QuoteSHA256 || r.Currency != receipt.Currency || r.TenancyID != receipt.TenancyID || r.BudgetID != receipt.BudgetID || !r.IssuedAt.Equal(receipt.IssuedAt) || !r.LaunchExpiresAt.Equal(receipt.LaunchExpiresAt) {
		return errors.New("capacity receipt differs from its durable reservation")
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

// Observe binds an operation to actual priced resources. Replays must name the
// same identities. Retirement requires positive terminal observations for all IDs.
func Observe(ctx context.Context, reader *globalcontrol.Reader, writer *globalcontrol.Writer, epoch uint64,
	operationID string, resourceIDs []string, proof region.VerifiedInfrastructureSpend, snapshot capacityinventory.Snapshot, now time.Time,
) (Reservation, error) {
	ids := slices.Clone(resourceIDs)
	slices.Sort(ids)
	if len(ids) == 0 || len(ids) > 16 || slices.Contains(ids, "") || len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return Reservation{}, errors.New("observed commitment needs unique exact resource identities")
	}
	var result Reservation
	err := changeReservations(ctx, reader, writer, epoch, proof, snapshot, now, false, func(c *Capacity, _ Budget, _ bool) error {
		i := reservationIndex(*c, operationID)
		if i < 0 {
			return errors.New("no reserved operation matches the observed resources")
		}
		r := c.Reservations[i]
		if len(r.ResourceIDs) > 0 && !slices.Equal(r.ResourceIDs, ids) {
			return errors.New("reservation already names different resources")
		}
		// A node commitment includes its boot volume; an instance alone cannot retire it.
		associated := []string{}
		instance, boot := false, false
		for _, resource := range snapshot.Resources {
			if resource.OperationID == r.OperationID && resource.RecipeSHA256 == r.RecipeSHA256 && resource.Cell == r.Cell && resource.CompartmentID == r.CompartmentID {
				associated = append(associated, resource.ID)
				instance = instance || strings.HasPrefix(resource.ID, "ocid1.instance.")
				boot = boot || strings.HasPrefix(resource.ID, "ocid1.bootvolume.")
			}
		}
		slices.Sort(associated)
		if !instance || !boot || !slices.Equal(ids, associated) {
			return errors.New("observation must name every exact node and boot resource of this operation")
		}
		retired := true
		for _, id := range ids {
			resource, ok := snapshotResource(snapshot, r, id)
			if !ok {
				return fmt.Errorf("resource %s lacks positive owned-resource cost evidence", id)
			}
			retired = retired && retiredResource(resource.LifecycleState)
		}
		r.ResourceIDs = ids
		if retired && r.RetiredAt.IsZero() {
			r.RetiredAt = now
		}
		c.Reservations = slices.Clone(c.Reservations)
		c.Reservations[i] = r
		result = r
		return nil
	})
	return result, err
}

func changeReservations(ctx context.Context, reader *globalcontrol.Reader, writer *globalcontrol.Writer, epoch uint64,
	proof region.VerifiedInfrastructureSpend, snapshot capacityinventory.Snapshot, now time.Time, admit bool,
	change func(*Capacity, Budget, bool) error,
) error {
	if writer == nil || reader == nil {
		return errors.New("infrastructure reservations require the home global writer")
	}
	reader = &writer.Reader
	for range 8 {
		var monthly Budget
		var found bool
		var limit uint64
		var err error
		if admit {
			monthly, found, limit, err = spendingFacts(ctx, reader, proof, snapshot, now)
		} else {
			// Financial expiry prevents purchases, not observations of owned resources.
			if !proof.IsVerified() {
				return errors.New("owned-resource observation lacks signed footprint proof")
			}
			err = snapshot.ValidateOwned(proof.Footprint(), now)
			if err == nil {
				monthly, found, err = ReadBudget(ctx, reader)
			}
			if proof.MonthlyLimitMinor() > 0 {
				limit = uint64(proof.MonthlyLimitMinor())
			}
			if found && monthly.Currency == proof.Currency() {
				limit = min(limit, monthly.MonthlyCapCents)
			}
		}
		if err != nil {
			return err
		}
		c, exists, err := ReadCapacity(ctx, reader)
		if err != nil {
			return err
		}
		var expected []byte
		if exists {
			expected, err = c.Encode()
			if err != nil {
				return err
			}
		} else {
			c = Capacity{Schema: Schema, At: now, State: StateNone, Reason: "infrastructure commitments; tenant budget is unset"}
		}
		if admit {
			limit, err = bootstrapLimit(c, proof, limit)
			if err != nil {
				return err
			}
		} else {
			reserved := max(c.BootstrapReservedCents, uint64(proof.BootstrapReservedMinor()))
			limit -= min(limit, reserved)
		}
		if err := retainBootstrap(&c, proof); err != nil {
			return err
		}
		if err := change(&c, monthly, found); err != nil {
			return err
		}
		total := projection(c, snapshot, "")
		if admit && total > limit {
			return fmt.Errorf("infrastructure commitment %d exceeds authorized monthly ceiling %d", total, limit)
		}
		c.Spending = &InfrastructureSpending{InfrastructureBudgetID: proof.BudgetID(), GrantSHA256: proof.GrantDigest(), ScopeSHA256: proof.ScopeDigest(), Currency: proof.Currency(), MonthlyLimitCents: limit, ProjectedCents: total, ObservedAt: snapshot.ObservedAt, ExpiresAt: snapshot.ExpiresAt}
		c.ProjectedCents = max(c.ProjectedCents, total)
		if c.CapCents > 0 {
			c.Ratio = float64(c.ProjectedCents) / float64(c.CapCents)
			if c.ProjectedCents >= c.CapCents {
				c.State = StateOver
			} else if c.State == StateOK && c.Ratio >= WarnRatio {
				c.State = StateWarn
			}
		}
		payload, err := c.Encode()
		if err != nil {
			return err
		}
		_, err = writer.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, payload, func(stored []byte) error {
			if !sameCapacity(stored, expected) {
				return globalcontrol.ErrConflict
			}
			latest, hasBudget, readErr := ReadBudget(ctx, reader)
			if readErr != nil {
				return readErr
			}
			if hasBudget != found || hasBudget && latest != monthly {
				return globalcontrol.ErrConflict
			}
			return nil
		})
		if errors.Is(err, globalcontrol.ErrConflict) {
			continue
		}
		if err == nil {
			// An identical document retry can return before PutDocument's admission callback.
			latest, hasBudget, readErr := ReadBudget(ctx, reader)
			if readErr != nil {
				return readErr
			}
			if hasBudget != found || hasBudget && latest != monthly {
				continue
			}
		}
		return err
	}
	return globalcontrol.ErrConflict
}

func minTime(times ...time.Time) time.Time {
	result := times[0]
	for _, at := range times[1:] {
		if at.Before(result) {
			result = at
		}
	}
	return result
}
