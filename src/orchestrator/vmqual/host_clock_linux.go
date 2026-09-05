//go:build linux

package vmqual

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

func synchronizedHostTime() (time.Duration, error) {
	var state unix.Timex
	result, err := unix.Adjtimex(&state)
	if err != nil {
		return 0, fmt.Errorf("vmqual: read host adjtimex: %w", err)
	}
	uncertainty := time.Duration(state.Maxerror) * time.Microsecond
	if result == unix.TIME_ERROR || state.Status&unix.STA_UNSYNC != 0 || state.Maxerror < 0 || state.Maxerror > 500000 {
		return uncertainty, fmt.Errorf("vmqual: host clock cannot serve qualification time: adjtimex state=%d status=0x%x maxerror=%dus (required synchronized and <=500000us)", result, state.Status, state.Maxerror)
	}
	return uncertainty, nil
}
