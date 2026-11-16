package capacityinventory

import (
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
)

// KnownLiabilities is an original-tariff subtotal, not complete accounting or
// spending authority. Unbound resources have no invented historical price.
type KnownLiabilities struct {
	ScopeSHA256, Currency string
	ObservedAt, ExpiresAt time.Time
	MonthlyCents          uint64
	Resources             []Resource
	Commitments           []capacityledger.Receipt
	UnknownOperations     []string
	UnboundResources      []string
	UnboundedCompartments []string
	Pending               []string
}
