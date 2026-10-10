package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// A region the identity cannot resolve is retried until the context ends, so
// shutdown is never blocked by the retry.
func TestRegionPlannerIdentityRetryStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := retryHomeIdentity(ctx, "xyz"); !errors.Is(err, context.Canceled) {
		t.Fatalf("retryHomeIdentity = %v; want the context's cancellation", err)
	}
}

func TestRolloutKnownBadFailsClosedUntilTheStoreOpens(t *testing.T) {
	t.Parallel()

	knownBad := newRolloutKnownBad()
	if knownBad == nil {
		t.Fatal("no known-bad source with the rollout store enabled")
	}
	if bad, err := knownBad.IsKnownBad(t.Context(), strings.Repeat("a", 64)); err == nil || bad {
		t.Fatalf("unopened store = %v, %v", bad, err)
	}
	if withKnownBad(placement.Config{}, knownBad).KnownBad == nil {
		t.Fatal("placement config lost the known-bad source")
	}
	// A disabled store must leave the interface nil, not a typed nil.
	if withKnownBad(placement.Config{}, nil).KnownBad != nil {
		t.Fatal("a disabled rollout store set a known-bad source")
	}
}
