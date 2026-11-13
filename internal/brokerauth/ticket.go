package brokerauth

import (
	"errors"
	"fmt"
	"time"
)

const (
	TicketLifetime     = 10 * time.Second
	MaxTicketWireBytes = 2 * (maxAccountJWTBytes + 8192)
	MaxTicketRoundTrip = 2 * time.Second
	MaxClockError      = 250 * time.Millisecond
	MaxClockSampleAge  = time.Second
)

// ClockBound is an NTP-measured upper bound on UTC clock error. SampledAt must
// retain Go's monotonic component on the same process that checks it.
type ClockBound struct {
	SampledAt time.Time
	MaxError  time.Duration
}

type ClockProbe interface{ Measure() (ClockBound, error) }

func (b ClockBound) valid(now time.Time) bool {
	return !b.SampledAt.IsZero() && b.MaxError >= 0 && b.MaxError <= MaxClockError &&
		!now.Before(b.SampledAt) && now.Sub(b.SampledAt) <= MaxClockSampleAge
}

// MeasureHealthyClock obtains a fresh NTP bound for an authority decision.
// The probe checks kernel synchronization; this check also rejects stale or
// otherwise invalid samples from any ClockProbe implementation.
func MeasureHealthyClock(probe ClockProbe) (ClockBound, error) {
	if probe == nil {
		return ClockBound{}, errors.New("NTP clock health is unavailable")
	}
	bound, err := probe.Measure()
	if err != nil {
		return ClockBound{}, fmt.Errorf("NTP clock health is unavailable: %w", err)
	}
	if !bound.valid(time.Now()) {
		return ClockBound{}, errors.New("NTP clock health is unavailable")
	}
	return bound, nil
}
