//go:build linux

package vmqual

import (
	"fmt"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

func SynchronizedHostTime() (HostTimeObservation, error) {
	var state unix.Timex
	result, err := unix.Adjtimex(&state)
	if err != nil {
		return HostTimeObservation{}, fmt.Errorf("vmqual: read host adjtimex: %w", err)
	}
	return classifyHostTime(result, state)
}

func classifyHostTime(result int, state unix.Timex) (HostTimeObservation, error) {
	if result < unix.TIME_OK || result > unix.TIME_WAIT || state.Status&(unix.STA_UNSYNC|unix.STA_CLOCKERR) != 0 || state.Status&(unix.STA_INS|unix.STA_DEL) == unix.STA_INS|unix.STA_DEL || state.Maxerror < 0 || state.Maxerror > math.MaxInt64/int64(time.Microsecond) {
		return HostTimeObservation{}, fmt.Errorf("vmqual: host clock cannot serve qualification time: adjtimex state=%d status=0x%x maxerror=%dus (required synchronized with valid uncertainty and leap state)", result, state.Status, state.Maxerror)
	}
	observation := HostTimeObservation{MaximumError: time.Duration(state.Maxerror) * time.Microsecond}
	switch result {
	case unix.TIME_INS, unix.TIME_OOP:
		observation.LeapIndicator = 1
	case unix.TIME_DEL:
		observation.LeapIndicator = 2
	case unix.TIME_OK:
		if state.Status&unix.STA_INS != 0 {
			observation.LeapIndicator = 1
		}
		if state.Status&unix.STA_DEL != 0 {
			observation.LeapIndicator = 2
		}
	}
	return observation, nil
}
