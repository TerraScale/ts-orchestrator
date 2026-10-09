package rollout

import (
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

func TestTransitionDecisionsFollowTheJournalContract(t *testing.T) {
	cases := []struct {
		from, to Phase
		kind     decisionlog.Kind
		status   decisionlog.Status
	}{
		{PhasePreflight, PhaseCanary, decisionlog.KindUpgradeStarted, decisionlog.StatusInProgress},
		{PhaseCanarySoak, PhaseBatch, decisionlog.KindCanaryPromoted, decisionlog.StatusInProgress},
		{PhaseBatchSoak, PhaseBatch, decisionlog.KindBatchPromoted, decisionlog.StatusInProgress},
		{PhaseBatchSoak, PhaseComplete, decisionlog.KindRolloutCompleted, decisionlog.StatusSucceeded},
		{PhaseCanarySoak, PhaseRollingBack, decisionlog.KindRollback, decisionlog.StatusInProgress},
		{PhaseRollingBack, PhaseRolledBack, decisionlog.KindRollback, decisionlog.StatusRolledBack},
		{PhaseBatch, PhaseFrozen, decisionlog.KindFrozen, decisionlog.StatusPending},
		{PhaseFrozen, PhaseAborted, decisionlog.KindHeld, decisionlog.StatusFailed},
		{PhaseCanary, PhaseCanarySoak, "", ""},
	}
	for _, test := range cases {
		kind, status, _ := transitionDecision(Record{Phase: test.from}, Record{RolloutID: "0000000000039PRXZD4Z9STA2E", Phase: test.to})
		if kind != test.kind || status != test.status {
			t.Errorf("%s -> %s = %q/%q, want %q/%q", test.from, test.to, kind, status, test.kind, test.status)
		}
	}
}

func TestInsightRolloutCarriesPhaseDeadline(t *testing.T) {
	started := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	view := InsightRollout(Record{RolloutID: "0000000000039PRXZD4Z9STA2E", ToDigest: "d", Phase: PhaseCanarySoak,
		PhaseStartedAt: started, PhaseDeadline: started.Add(time.Hour)})
	if view.ID != "0000000000039PRXZD4Z9STA2E" || view.Release != "d" || view.Phase != "canary-soak" || view.Done ||
		!view.PhaseDeadline.Equal(started.Add(time.Hour)) {
		t.Fatalf("insight rollout = %+v", view)
	}
	if !InsightRollout(Record{Phase: PhaseComplete}).Done {
		t.Fatal("a complete rollout must be done")
	}
}
