package bootstrap

import (
	"strings"
	"testing"
)

// A replacement token can never equal an initial founder token: slot "b" at
// attempt 2 must not render the attempt-one token of a slot named "b-a2"
// under the same plan.
func TestReplacementTokensAreDisjointFromInitialTokens(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	verified := fixture.verify(t)
	slot := "controller-b"
	initial, err := verified.InitialManagedPeerIntent(slot, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	previous := completedManagedSlotForRetirement()
	previous.Intent.CreateKey, previous.Intent.RetryToken = initial.CreateKey, initial.RetryToken
	replacement, err := verified.ReplacementManagedPeerIntent(slot, previous, []byte("retirement"), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimPrefix(initial.CreateKey, "founder-"+slot+"-")
	collidingInitial := "founder-" + slot + "-a2-" + digest
	if replacement.CreateKey == collidingInitial || replacement.RetryToken == collidingInitial ||
		!strings.HasPrefix(replacement.CreateKey, "replace-") || replacement.CreateKey == initial.CreateKey {
		t.Fatalf("replacement token %q collides with the initial namespace (%q)", replacement.CreateKey, collidingInitial)
	}
	if replacement.CreateKey != "replace-"+slot+"-a2-"+digest {
		t.Fatalf("replacement token = %q", replacement.CreateKey)
	}
}
