package host

import (
	"testing"
	"time"
)

// A self-registered replacement of a host (a static C# TerraBase host)
// must not run beside the previous generation, which may run its members
// until its lease expires; a controller-launched managed host takes over.
func TestNextGenerationAcquireWaitsForTheOldSessionUnlessManaged(t *testing.T) {
	now := time.Now()
	live := session{RegistrationGeneration: 1, ExpiresAt: now.Add(sessionTTL)}
	expired := session{RegistrationGeneration: 1, ExpiresAt: now.Add(-time.Second)}
	same, next := Registration{Generation: 1}, Registration{Generation: 2}
	managed := Registration{Generation: 2, ManagedOCI: &ManagedOCIBinding{}}
	for _, test := range []struct {
		name string
		old  session
		r    Registration
		held bool
	}{
		{"same generation live", live, same, true},
		{"next generation live", live, next, true},
		{"managed next generation live", live, managed, false},
		{"same generation expired", expired, same, false},
		{"next generation expired", expired, next, false},
	} {
		if got := sessionHeld(test.old, test.r, now); got != test.held {
			t.Fatalf("%s: held=%t, want %t", test.name, got, test.held)
		}
	}
}
