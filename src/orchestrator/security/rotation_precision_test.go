package security

import (
	"testing"
	"time"
)

func TestCapabilityValidityUsesWholeSeconds(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 123456789, time.UTC)
	c := &Coordinator{regions: []string{"GRU"}}
	state := c.newState(PersistedState{}, "precision", now)
	if state.NewNotBefore.Nanosecond() != 0 || state.NewExpiry.Nanosecond() != 0 || state.NewExpiry.Sub(state.NewNotBefore) != CapabilityPeriod {
		t.Fatal("consumer validity interval is not aligned to Unix seconds")
	}
	if !state.LastAt.Equal(now) {
		t.Fatal("audit/clock regression precision was lost")
	}
}
