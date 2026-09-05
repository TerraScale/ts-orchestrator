//go:build linux

package vmqual

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHostClockKeepsUncertaintySeparateFromGuestOffset(t *testing.T) {
	for _, microseconds := range []int64{238500, 631500, 748500, 16000000} {
		observation, err := classifyHostTime(unix.TIME_OK, unix.Timex{Maxerror: microseconds})
		if err != nil || observation.MaximumError != time.Duration(microseconds)*time.Microsecond {
			t.Fatalf("synchronized uncertainty %d: %+v %v", microseconds, observation, err)
		}
	}
	for _, state := range []unix.Timex{{Status: unix.STA_UNSYNC}, {Status: unix.STA_CLOCKERR}, {Status: unix.STA_INS | unix.STA_DEL}, {Maxerror: -1}} {
		if _, err := classifyHostTime(unix.TIME_OK, state); err == nil {
			t.Fatalf("invalid host time accepted: %+v", state)
		}
	}
	if _, err := classifyHostTime(unix.TIME_ERROR, unix.Timex{}); err == nil {
		t.Fatal("kernel TIME_ERROR accepted")
	}
}

func TestHostClockPreservesLeapState(t *testing.T) {
	for _, test := range []struct {
		state  int
		status int32
		leap   uint8
	}{
		{unix.TIME_OK, 0, 0}, {unix.TIME_INS, unix.STA_INS, 1}, {unix.TIME_DEL, unix.STA_DEL, 2},
		{unix.TIME_OOP, unix.STA_INS, 1}, {unix.TIME_WAIT, unix.STA_INS, 0},
	} {
		got, err := classifyHostTime(test.state, unix.Timex{Status: test.status})
		if err != nil || got.LeapIndicator != test.leap {
			t.Fatalf("leap state %+v: %+v %v", test, got, err)
		}
	}
}
