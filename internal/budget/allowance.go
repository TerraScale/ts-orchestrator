package budget

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// StatusMaxAge bounds a region status; an older one is unknown spend.
	StatusMaxAge = 6 * time.Hour
	// AllowanceMaxAge bounds a capacity document; an older one is not fresh.
	AllowanceMaxAge = 5 * time.Minute
	WarnRatio       = 0.8
	ClearRatio      = 0.75
)

// State is the budget's spend state at the time of an allocation.
type State string

const (
	StateNone    State = "none"    // no budget set
	StateUnknown State = "unknown" // some region's spend is unknown
	StateOK      State = "ok"
	StateWarn    State = "warn" // projected at least WarnRatio of the cap
	StateOver    State = "over" // projected at least the cap
)

// Region is one region's capacity status as the allocator needs it.
type Region struct {
	Cell             string
	Nodes            int
	Want             int
	Pressure         float64
	NodeMonthlyCents uint64 // list price of one more node for a month; 0 = unknown
	ProjectedCents   uint64 // max(month end, next month) of the region's own forecast
	Currency         string
	At               time.Time // when the region measured this status; zero = no status
}

// RegionAllowance is the most nodes one region may have until the next allocation.
type RegionAllowance struct {
	Cell      string  `json:"cell"`
	Nodes     int     `json:"nodes"`
	Want      int     `json:"want"`
	Allowance int     `json:"allowance"`
	Pressure  float64 `json:"pressure"`
}

// Capacity is the global capacity document the home region's leader writes.
type Capacity struct {
	Schema         int               `json:"schema"`
	At             time.Time         `json:"at"`
	CapCents       uint64            `json:"cap_cents,omitzero"`
	Currency       string            `json:"currency,omitempty"`
	ProjectedCents uint64            `json:"projected_cents"`
	Ratio          float64           `json:"ratio"`
	State          State             `json:"state"`
	Reason         string            `json:"reason"`  // one sentence: why growth is held, or what was granted
	Regions        []RegionAllowance `json:"regions"` // sorted by Cell
}

// Allocate projects the month from every region's own forecast and grants one
// node per wanting region, highest pressure first, while the projection stays
// within the cap. A region with unknown spend holds growth everywhere, since a
// partial sum cannot admit spending. A nil budget holds every region at its size.
func Allocate(budget *Budget, regions []Region, now time.Time) Capacity {
	sorted := slices.Clone(regions)
	slices.SortFunc(sorted, func(a, b Region) int { return strings.Compare(a.Cell, b.Cell) })
	capacity := Capacity{Schema: Schema, At: now, Regions: make([]RegionAllowance, len(sorted))}
	for index, region := range sorted {
		capacity.Regions[index] = RegionAllowance{
			Cell: region.Cell, Nodes: region.Nodes, Want: region.Want, Allowance: region.Nodes, Pressure: region.Pressure,
		}
	}
	if budget == nil {
		capacity.State = StateNone
		capacity.Reason = "no monthly budget is set"
		return capacity
	}
	capacity.CapCents = budget.MonthlyCapCents
	capacity.Currency = budget.Currency

	var projected uint64
	unknown := ""
	for _, region := range sorted {
		if !region.At.IsZero() && now.Sub(region.At) <= StatusMaxAge && region.Currency == budget.Currency {
			projected = saturatingAdd(projected, region.ProjectedCents)
		} else if unknown == "" {
			unknown = region.Cell
		}
	}
	capacity.ProjectedCents = projected
	capacity.Ratio = float64(projected) / float64(budget.MonthlyCapCents)
	switch {
	case unknown != "":
		capacity.State = StateUnknown
		capacity.Reason = fmt.Sprintf("%s has no fresh spend status, so growth is held in every region", unknown)
		return capacity
	case projected >= budget.MonthlyCapCents:
		capacity.State = StateOver
		capacity.Reason = "projected spend is at or over the cap, so growth is held"
		return capacity
	case capacity.Ratio >= WarnRatio:
		capacity.State = StateWarn
	default:
		capacity.State = StateOK
	}

	var candidates []int
	for index, region := range sorted {
		if region.Want > region.Nodes {
			candidates = append(candidates, index)
		}
	}
	slices.SortFunc(candidates, func(a, b int) int {
		if order := cmp.Compare(sorted[b].Pressure, sorted[a].Pressure); order != 0 {
			return order
		}
		return strings.Compare(sorted[a].Cell, sorted[b].Cell)
	})
	var grants []string
	for _, index := range candidates {
		region := sorted[index]
		next := saturatingAdd(projected, region.NodeMonthlyCents)
		if region.NodeMonthlyCents == 0 || next > budget.MonthlyCapCents {
			continue
		}
		projected = next
		capacity.Regions[index].Allowance++
		grants = append(grants, region.Cell+" +1")
	}
	switch {
	case len(grants) > 0:
		capacity.Reason = "granted " + strings.Join(grants, ", ")
	case len(candidates) == 0:
		capacity.Reason = "no region wants more nodes"
	default:
		capacity.Reason = "no more nodes fit under the cap, or their price is unknown"
	}
	return capacity
}

// Validate requires the current schema, a reason, a budget-shaped cap and
// currency, sorted cells, and allowances of one node above the current size
// at most, which is all Allocate ever grants.
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
		}
	}
	return nil
}

// DecodeCapacity strictly decodes and validates a stored capacity document.
func DecodeCapacity(payload []byte) (Capacity, error) {
	var c Capacity
	if err := protocol.DecodeStrict(payload, &c, maxDocumentBytes); err != nil {
		return Capacity{}, fmt.Errorf("decode capacity: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Capacity{}, err
	}
	return c, nil
}

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

// WriteCapacity stores c as the next capacity generation. Only the home
// region's global leader calls it.
func WriteCapacity(ctx context.Context, writer *globalcontrol.Writer, epoch uint64, c Capacity) error {
	payload, err := c.Encode()
	if err != nil {
		return err
	}
	_, err = writer.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, payload, nil)
	return err
}

// AllowanceFor is the most nodes cell may have per c, and false when c is not
// fresh at now (older, or further ahead than clock skew explains) or does not
// name cell.
func AllowanceFor(c Capacity, cell string, now time.Time) (int, bool) {
	if now.Sub(c.At) > AllowanceMaxAge || c.At.Sub(now) > AllowanceMaxAge {
		return 0, false
	}
	index := slices.IndexFunc(c.Regions, func(region RegionAllowance) bool { return region.Cell == cell })
	if index < 0 {
		return 0, false
	}
	return c.Regions[index].Allowance, true
}

// Alerting reports whether the budget alert is open, with hysteresis: it opens
// at WarnRatio and closes below ClearRatio. An unknown or unset budget keeps
// the alert as it was.
func Alerting(open bool, c Capacity) bool {
	switch c.State {
	case StateNone, StateUnknown:
		return open
	}
	if open {
		return c.Ratio >= ClearRatio
	}
	return c.Ratio >= WarnRatio
}

// saturatingAdd keeps overflow from wrapping a projection back under the cap.
func saturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
