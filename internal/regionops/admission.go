package regionops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// PriceList admits a region at its configured monthly price. The price is
// signed controller policy (the same table the planner proposes from), not a
// live OCI quote: the admission is fresh in that it is re-evaluated against
// the current fleet and HeadroomCents every time, and its evidence digest
// binds the cell, the price and the admission time. A cell without a price is
// never admitted. HeadroomCents is fixed until the monthly budget replaces it.
type PriceList struct {
	MonthlyCents  map[string]uint64
	HeadroomCents uint64
}

func (prices PriceList) Estimate(_ context.Context, record regionlifecycle.Record, now time.Time,
) (regionlifecycle.CostAdmission, error) {
	cents := prices.MonthlyCents[record.Cell]
	if cents == 0 {
		return regionlifecycle.CostAdmission{}, fmt.Errorf("region %s has no configured monthly price", record.Cell)
	}
	at := now.UTC()
	evidence := sha256.Sum256([]byte("terrascale-region-price-v1\x00" + record.Cell + "\x00" + record.Proposal.ID +
		"\x00" + strconv.FormatUint(cents, 10) + "\x00" + at.Format(time.RFC3339Nano)))
	return regionlifecycle.CostAdmission{EstimatedMonthlyCents: cents, HeadroomCents: prices.HeadroomCents,
		EvidenceDigest: hex.EncodeToString(evidence[:]), AdmittedAt: at}, nil
}
