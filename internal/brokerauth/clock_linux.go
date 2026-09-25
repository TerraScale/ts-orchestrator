//go:build linux

package brokerauth

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// KernelClockProbe reads the kernel's synchronized-clock maximum error. It
// fails closed when NTP is absent, unhealthy, or exceeds the ticket budget.
type KernelClockProbe struct{}

func (KernelClockProbe) Measure() (ClockBound, error) {
	var state unix.Timex
	status, err := unix.Adjtimex(&state)
	sampled := time.Now()
	if err != nil || status != unix.TIME_OK ||
		state.Status&(unix.STA_UNSYNC|unix.STA_CLOCKERR) != 0 ||
		state.Maxerror < 0 || state.Maxerror > int64(MaxClockError/time.Microsecond) {
		return ClockBound{}, errors.New("kernel NTP clock error is not bounded")
	}
	return ClockBound{SampledAt: sampled, MaxError: time.Duration(state.Maxerror) * time.Microsecond}, nil
}
