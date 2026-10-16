package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	staged "github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
)

// Only failures a retry can fix are transient: an unreachable broker, a
// timeout, a leader change or an expired authority lease. Configuration,
// authorization and reply verification failures stop CD at once.
func TestTerraBaseRolloutClassifiesConnectAndStatusErrors(t *testing.T) {
	unreachable := fmt.Errorf("connect regional NATS: %w", nats.ErrNoServers)
	for name, test := range map[string]struct {
		err       error
		transient bool
	}{
		"connect unavailable":   {fmt.Errorf("wrapped: %w", errors.Join(natscell.ErrUnavailable, unreachable)), true},
		"connect deadline":      {context.DeadlineExceeded, true},
		"connect not leader":    {authority.ErrNotLeader, true},
		"connect configuration": {errors.New("regional replicas must be 1, 3, or 5"), false},
		"connect credentials":   {errors.New("read NATS credentials: no such file"), false},
	} {
		if got := staged.IsTransient(classifyConnectError(test.err)); got != test.transient {
			t.Errorf("connect %s: transient = %t, want %t", name, got, test.transient)
		}
	}
	for name, test := range map[string]struct {
		err       error
		transient bool
	}{
		"status timeout":       {fmt.Errorf("request TerraBase placement status: %w", nats.ErrTimeout), true},
		"status lease expired": {errors.New("regional authority lease is not current"), true},
		"status unauthorized":  {statusRejected{errors.New("operator is not authorized to read TerraBase placement status")}, false},
		"status unverified":    {statusRejected{fmt.Errorf("unauthenticated placement status: %w", errors.New("bad signature"))}, false},
		"status mismatch":      {statusRejected{errors.New("placement status reply answers a different request")}, false},
	} {
		classified := classifyStatusError(test.err)
		if got := staged.IsTransient(classified); got != test.transient {
			t.Errorf("%s: transient = %t, want %t", name, got, test.transient)
		}
		if !errors.Is(classified, test.err) || classified.Error() != test.err.Error() {
			t.Errorf("%s: classification changed the error: %v", name, classified)
		}
	}
}

// A promoted canary keeps Stage serving after it loses its serving proof, so
// the soak must read serving from the host's current report, and a missing
// report is a gap rather than a failure.
func TestSoakSampleRequiresTheHostsCurrentServingProof(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	member := func(host *placementHostStatus) placementMemberStatus {
		return placementMemberStatus{SeatID: "000000000077F1R6E1XPKAC2D4", Stage: string(placement.StageServing), ArtifactDigest: "c",
			Update: &placementUpdateStatus{OperationID: "0000000000VWA5N990CSNH40S5", Phase: string(placement.ManagedUpdateSeatCanaryServing)},
			Host:   host}
	}
	healthy := func() *placementHostStatus {
		return &placementHostStatus{SessionCurrent: true, ReportState: "running", ProcessPID: 77, ServingProof: true}
	}
	if sample := soakSample(member(healthy()), now); sample.Gap || !sample.Serving || sample.ProcessPID != 77 ||
		sample.OperationID != "0000000000VWA5N990CSNH40S5" || sample.Phase != string(placement.ManagedUpdateSeatCanaryServing) {
		t.Fatalf("healthy sample = %+v", sample)
	}
	wedged := healthy()
	wedged.ServingProof = false
	if sample := soakSample(member(wedged), now); sample.Gap || sample.Serving {
		t.Fatalf("a seat without a current serving proof soaked as serving: %+v", sample)
	}
	failed := healthy()
	failed.ReportState, failed.ReportError, failed.ProcessPID, failed.ServingProof = "failed", "process exited", 0, false
	if sample := soakSample(member(failed), now); sample.Gap || sample.Serving {
		t.Fatalf("a failed host report soaked as serving: %+v", sample)
	}
	stale := healthy()
	stale.SessionCurrent = false
	for name, host := range map[string]*placementHostStatus{"no host": nil, "stale session": stale,
		"no report": {SessionCurrent: true}} {
		if sample := soakSample(member(host), now); !sample.Gap || !sample.Serving || sample.ProcessPID != 0 {
			t.Fatalf("%s: sample = %+v, want a serving gap", name, sample)
		}
	}
}
