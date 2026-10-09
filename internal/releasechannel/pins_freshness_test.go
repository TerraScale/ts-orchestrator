package releasechannel

import (
	"testing"
	"time"
)

func TestPinInventoryFreshnessBounds(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	pins := &ReleasePins{}
	for _, tc := range []struct {
		name string
		at   time.Time
		bad  bool
	}{
		{"at maximum age", now.Add(-MaxPinAge), false},
		{"past maximum age", now.Add(-MaxPinAge - time.Nanosecond), true},
		{"at clock allowance", now.Add(PinRefreshInterval), false},
		{"past clock allowance", now.Add(PinRefreshInterval + time.Nanosecond), true},
		{"missing", time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := pins.ValidateFresh(tc.at, now); (err != nil) != tc.bad {
				t.Fatalf("freshness = %v, invalid timestamp = %v", err, tc.bad)
			}
		})
	}
}
