package nodescale

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// StatusSchema is the wire version of Status. A reader refuses any other schema.
const StatusSchema = 1

// maxReasonBytes bounds Status.Reason, which the dashboard shows as it is.
const maxReasonBytes = 256

// Round trips: at most one per OCI region, each under a minute.
const (
	maxRoundTrips      = 64
	maxRoundTripMillis = 60_000
)

// InFlight is the scale action a region is running.
type InFlight struct {
	ID         string    `json:"id"`
	Kind       Action    `json:"kind"`
	Step       string    `json:"step"`
	Node       string    `json:"node,omitempty"`
	InstanceID string    `json:"instance_id,omitempty"`
	Started    time.Time `json:"started"`
}

// Status is what a region publishes in its summary for the home's allowances.
type Status struct {
	Schema         int                `json:"schema"`
	Cell           string             `json:"cell"`
	At             time.Time          `json:"at"`
	Nodes          int                `json:"nodes"`
	QuorumNodes    int                `json:"quorum_nodes"`
	PoolNodes      int                `json:"pool_nodes"`
	Want           int                `json:"want"`
	Allowance      int                `json:"allowance"`
	AllowanceFresh bool               `json:"allowance_fresh"`
	Action         Action             `json:"action"`
	Saturated      bool               `json:"saturated,omitzero"`
	Pressure       float64            `json:"pressure"`
	Signal         Signal             `json:"signal,omitempty"`
	Signals        map[Signal]float64 `json:"signals,omitempty"`
	Reason         string             `json:"reason"`
	InFlight       *InFlight          `json:"in_flight,omitempty"`
	LastChange     time.Time          `json:"last_change,omitzero"`
	// The spend below comes from the Scaler's Cost callback, which TS-807's
	// ocicost supplies: the list price of one more pool node for a month, and
	// the region's forecast with its pool nodes pending. Without it, or when
	// it fails, the spend is zero, which the home reads as unknown and holds
	// growth.
	NodeMonthlyCents uint64    `json:"node_monthly_cents,omitzero"`
	ProjectedCents   uint64    `json:"projected_cents,omitzero"`
	Currency         string    `json:"currency,omitempty"`
	CostAt           time.Time `json:"cost_at,omitzero"`
	// RTTMillis is the region's measured TCP connect time to each OCI region, from the Prober.
	RTTMillis map[string]int `json:"rtt_ms,omitempty"`
}

// Cost is a region's spend as the Scaler's Cost callback reports it.
type Cost struct {
	NodeMonthlyCents uint64
	ProjectedCents   uint64
	Currency         string
	At               time.Time
}

// currencyCode is an ISO 4217 code in upper case.
var currencyCode = regexp.MustCompile(`^[A-Z]{3}$`)

// validCurrency accepts no currency, which means spend is unknown, or an ISO 4217 code.
func validCurrency(currency string) bool {
	return currency == "" || currencyCode.MatchString(currency)
}

// Validate refuses a status the home cannot use.
func (s Status) Validate() error {
	switch {
	case s.Schema != StatusSchema:
		return fmt.Errorf("node status schema %d, want %d", s.Schema, StatusSchema)
	case !cellPattern.MatchString(s.Cell):
		return fmt.Errorf("node status cell %q is not a cell name", s.Cell)
	case s.At.IsZero():
		return errors.New("node status has no time")
	case s.Reason == "" || len(s.Reason) > maxReasonBytes:
		return fmt.Errorf("node status reason must be 1 to %d bytes", maxReasonBytes)
	case !validCurrency(s.Currency):
		return fmt.Errorf("node status currency %q is not an ISO 4217 code", s.Currency)
	}
	for _, count := range []int{s.Nodes, s.QuorumNodes, s.PoolNodes, s.Want, s.Allowance} {
		if count < 0 || count > MaxNodes+MaxPoolNodes {
			return fmt.Errorf("node status count %d is outside 0 to %d", count, MaxNodes+MaxPoolNodes)
		}
	}
	if len(s.RTTMillis) > maxRoundTrips {
		return fmt.Errorf("node status has %d round trips, at most %d", len(s.RTTMillis), maxRoundTrips)
	}
	for region, millis := range s.RTTMillis {
		if !ociRegionName.MatchString(region) || millis <= 0 || millis > maxRoundTripMillis {
			return fmt.Errorf("node status round trip to %q is %d ms", region, millis)
		}
	}
	return nil
}
