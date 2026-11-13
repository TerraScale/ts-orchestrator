package budget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// StatusMaxAge bounds a region status; an older one is unknown spend.
	StatusMaxAge = 6 * time.Hour
	// AllowanceMaxAge bounds a capacity document; an older one is not fresh.
	AllowanceMaxAge = 5 * time.Minute
	WarnRatio       = 0.8
	ClearRatio      = 0.75
)

// ReservationTTL bounds a granted node's reservation while its region's status lags. It outlasts nodescale's
// 20-minute launch timeout, so a launch still running keeps its node reserved and a dead one frees it.
const ReservationTTL = 25 * time.Minute

// State is the budget's spend state at the time of an allocation.
type State string

const (
	StateNone    State = "none"    // no budget set
	StateUnknown State = "unknown" // some region's spend is unknown
	StateOK      State = "ok"
	StateWarn    State = "warn" // projected at least WarnRatio of the cap
	StateOver    State = "over" // projected at least the cap
)

// RegionAllowance is the most nodes one region may have until the next allocation.
type RegionAllowance struct {
	Cell      string    `json:"cell"`
	Nodes     int       `json:"nodes"`
	Want      int       `json:"want"`
	Allowance int       `json:"allowance"`
	Pressure  float64   `json:"pressure"`
	GrantedAt time.Time `json:"granted_at,omitzero"` // when the reserved grant was made; zero when none
}

// Capacity is the global capacity document the home region's leader writes.
type Capacity struct {
	Schema                 int                     `json:"schema"`
	At                     time.Time               `json:"at"`
	CapCents               uint64                  `json:"cap_cents,omitzero"`
	Currency               string                  `json:"currency,omitempty"`
	ProjectedCents         uint64                  `json:"projected_cents"`
	Ratio                  float64                 `json:"ratio"`
	State                  State                   `json:"state"`
	Reason                 string                  `json:"reason"`  // one sentence: why growth is held, or what was granted
	Regions                []RegionAllowance       `json:"regions"` // sorted by Cell
	Spending               *InfrastructureSpending `json:"infrastructure_spending,omitempty"`
	Reservations           []Reservation           `json:"reservations,omitempty"`
	BootstrapReservedCents uint64                  `json:"bootstrap_reserved_cents,omitzero"`
	BootstrapSHA256        string                  `json:"bootstrap_sha256,omitempty"`
}

// Validate requires the current schema, a reason, a budget-shaped cap and
// currency, sorted cells, and allowances of one node above the current size
// at most, with a grant time exactly when one node is allowed.
func (c Capacity) Validate() error {
	switch {
	case c.Schema != Schema:
		return fmt.Errorf("capacity schema %d is not %d", c.Schema, Schema)
	case c.At.IsZero():
		return errors.New("capacity at is required")
	case c.Reason == "":
		return errors.New("capacity reason is required")
	case math.IsNaN(c.Ratio) || math.IsInf(c.Ratio, 0) || c.Ratio < 0:
		return errors.New("capacity ratio must be a finite, non-negative number")
	}
	switch c.State {
	case StateNone:
		if c.CapCents != 0 || c.Currency != "" {
			return errors.New("capacity without a budget must not name a cap")
		}
	case StateUnknown, StateOK, StateWarn, StateOver:
		if c.CapCents == 0 || c.CapCents > maxMonthlyCapCents || !currencyCode.MatchString(c.Currency) {
			return errors.New("capacity cap and currency must match a budget")
		}
	default:
		return fmt.Errorf("capacity state %q is unknown", c.State)
	}
	for index, region := range c.Regions {
		switch {
		case region.Cell == "" || index > 0 && c.Regions[index-1].Cell >= region.Cell:
			return errors.New("capacity regions must be sorted by unique cell")
		case region.Nodes < 0 || region.Want < 0:
			return fmt.Errorf("capacity region %q has negative nodes or wants", region.Cell)
		case region.Allowance < region.Nodes || region.Allowance > region.Nodes+1:
			return fmt.Errorf("capacity allowance for %q must be its nodes or one more", region.Cell)
		case region.Allowance > region.Nodes && region.GrantedAt.IsZero(),
			region.Allowance == region.Nodes && !region.GrantedAt.IsZero():
			return fmt.Errorf("capacity grant time for %q must be set exactly when it allows one more node", region.Cell)
		}
	}
	return validateReservations(c)
}

// DecodeCapacity strictly decodes and validates a stored capacity document.
func DecodeCapacity(payload []byte) (Capacity, error) {
	var c Capacity
	if err := protocol.DecodeStrict(payload, &c, maxDocumentBytes); err != nil {
		return Capacity{}, fmt.Errorf("%w: %w", ErrInvalidCapacity, err)
	}
	if err := c.Validate(); err != nil {
		return Capacity{}, fmt.Errorf("%w: %w", ErrInvalidCapacity, err)
	}
	return c, nil
}

// ErrInvalidCapacity marks a stored capacity document that does not decode or
// validate, as opposed to one that could not be read.
var ErrInvalidCapacity = errors.New("invalid capacity document")

// Encode validates c and returns its stored form.
func (c Capacity) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return protocol.EncodeJSON(c)
}

// ReadCapacity returns the current capacity document, or false when none was
// ever written.
func ReadCapacity(ctx context.Context, reader *globalcontrol.Reader) (Capacity, bool, error) {
	document, err := reader.Document(ctx, globalcontrol.KindCapacity, protocol.GlobalScope)
	if errors.Is(err, globalcontrol.ErrNotFound) {
		return Capacity{}, false, nil
	}
	if err != nil {
		return Capacity{}, false, err
	}
	c, err := DecodeCapacity(document.Payload)
	if err != nil {
		return Capacity{}, false, err
	}
	return c, true, nil
}

func sameCapacity(stored, expected []byte) bool {
	if len(stored) == 0 || len(expected) == 0 {
		return bytes.Equal(stored, expected)
	}
	current, err := DecodeCapacity(stored)
	if err != nil {
		return false
	}
	canonical, err := current.Encode()
	return err == nil && bytes.Equal(canonical, expected)
}

// Headroom is what the cap leaves after the projection while spend is known
// and under the cap; otherwise nothing can be admitted.
func (c Capacity) Headroom() uint64 {
	if (c.State != StateOK && c.State != StateWarn) || c.ProjectedCents >= c.CapCents {
		return 0
	}
	return c.CapCents - c.ProjectedCents
}

// saturatingAdd keeps overflow from wrapping a projection back under the cap.
func saturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
