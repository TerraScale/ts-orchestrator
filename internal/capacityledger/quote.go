// Package capacityledger preserves financial facts in the protected root ledger.
// Its serializable records are data, never independent spending authority.
package capacityledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

// Quote retains the original payable tariffs. Expiry stops new purchases, not
// accounting for a purchase which was already accepted under these prices.
type Quote struct {
	ScopeSHA256   string          `json:"scopeSha256"`
	Cell          string          `json:"cell"`
	CompartmentID string          `json:"compartmentId"`
	Shape         string          `json:"shape"`
	Currency      string          `json:"currency"`
	OCPUs         float64         `json:"ocpus"`
	MemoryGB      float64         `json:"memoryGb"`
	BootGB        float64         `json:"bootGb"`
	MonthlyCents  uint64          `json:"monthlyCents"`
	IssuedAt      time.Time       `json:"issuedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	Prices        []ocicost.Price `json:"prices"`
}

// SHA256 keeps the original capacityinventory quote identity byte-for-byte.
func (q Quote) SHA256() string {
	wire, err := json.Marshal(struct {
		ScopeSHA256, Cell, CompartmentID, Shape, Currency string
		OCPUs, MemoryGB, BootGB                           float64
		MonthlyCents                                      uint64
		IssuedAt, ExpiresAt                               time.Time
		Prices                                            []ocicost.Price
	}{q.ScopeSHA256, q.Cell, q.CompartmentID, q.Shape, q.Currency, q.OCPUs, q.MemoryGB, q.BootGB, q.MonthlyCents, q.IssuedAt, q.ExpiresAt, q.Prices}, json.Deterministic(true))
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func (q Quote) Clone() Quote {
	q.Prices = slices.Clone(q.Prices)
	return q
}

func (q Quote) Validate() error {
	monthly, known := ocicost.NodeMonthlyCents(q.Prices, q.Shape, q.OCPUs, q.MemoryGB, q.BootGB)
	if !Digest(q.ScopeSHA256) || q.Cell == "" || !strings.HasPrefix(q.CompartmentID, "ocid1.compartment.") ||
		q.Currency != "USD" && q.Currency != "BRL" || len(q.Prices) != 4 || !known || monthly == 0 || monthly != q.MonthlyCents ||
		q.IssuedAt.IsZero() || !q.ExpiresAt.After(q.IssuedAt) || q.ExpiresAt.Sub(q.IssuedAt) > 2*time.Minute {
		return errors.New("original quote lacks exact payable tariffs, billing geometry or validity")
	}
	return nil
}

func Digest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == value
}
