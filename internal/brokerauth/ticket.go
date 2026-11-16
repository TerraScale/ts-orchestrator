package brokerauth

import (
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
