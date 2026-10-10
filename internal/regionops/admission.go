package regionops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// BudgetAdmissions admits a region against the monthly budget. The price is
// the proposal's estimate; the headroom is what the global capacity document
// leaves. Without a known budget nothing is admitted.
type BudgetAdmissions struct {
	Capacity func(ctx context.Context) (budget.Capacity, bool, error)
}

func (admissions BudgetAdmissions) Estimate(ctx context.Context, record regionlifecycle.Record, now time.Time,
) (regionlifecycle.CostAdmission, error) {
	capacity, found, err := admissions.Capacity(ctx)
	if err != nil {
		return regionlifecycle.CostAdmission{}, fmt.Errorf("read capacity: %w", err)
	}
	if !found || capacity.State == budget.StateNone || capacity.State == budget.StateUnknown {
		return regionlifecycle.CostAdmission{}, errors.New("no known monthly budget: region is not admitted")
	}
	at := now.UTC()
	headroom := capacity.Headroom()
	evidence := sha256.Sum256([]byte("terrascale-region-budget-v1\x00" + record.Cell + "\x00" + record.Proposal.ID +
		"\x00" + strconv.FormatUint(capacity.CapCents, 10) + "\x00" + strconv.FormatUint(capacity.ProjectedCents, 10) +
		"\x00" + strconv.FormatUint(headroom, 10) + "\x00" + at.Format(time.RFC3339Nano)))
	return regionlifecycle.CostAdmission{EstimatedMonthlyCents: record.Proposal.EstimatedMonthlyCents,
		HeadroomCents: headroom, EvidenceDigest: hex.EncodeToString(evidence[:]), AdmittedAt: at}, nil
}
