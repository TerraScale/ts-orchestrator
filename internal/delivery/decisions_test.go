package delivery

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

func TestDeliveryJournalsEachSettledIntentOnce(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "lab"})
	t.Cleanup(decisionlog.SetDefault(journal))

	s, ctx := testService(t, &testWriter{})
	accepted := testIntent(t, s, ctx)
	for range 2 { // the replay must not journal again
		if terminal, err := s.process(ctx, mustJSON(accepted)); !terminal || err != nil {
			t.Fatalf("terminal=%t err=%v", terminal, err)
		}
	}
	fenced, fencedCtx := testService(t, &testWriter{fenceFirst: true})
	held := testIntent(t, fenced, fencedCtx)
	for range 2 {
		if terminal, err := fenced.process(fencedCtx, mustJSON(held)); !terminal || err != nil {
			t.Fatalf("terminal=%t err=%v", terminal, err)
		}
	}
	if terminal, err := s.process(ctx, []byte("{}")); !terminal || err != nil {
		t.Fatalf("garbage terminal=%t err=%v", terminal, err)
	}

	result, _ := journal.Query(ctx, decisionlog.Query{Actors: []string{"delivery"}})
	counts := map[decisionlog.Kind]int{}
	for _, decision := range result.Decisions {
		counts[decision.Kind]++
	}
	if counts[decisionlog.KindDeliveryApplied] != 1 || counts[decisionlog.KindDeliveryHeld] != 1 ||
		counts[decisionlog.KindDeliveryRejected] != 1 || len(result.Decisions) != 3 {
		t.Fatalf("counts = %v", counts)
	}
	for _, decision := range result.Decisions {
		switch decision.Kind {
		case decisionlog.KindDeliveryApplied:
			if decision.Subject.ID != accepted.OperationID || decision.Status != decisionlog.StatusSucceeded ||
				decision.Epoch != accepted.AuthorityEpoch {
				t.Fatalf("applied = %+v", decision)
			}
		case decisionlog.KindDeliveryHeld:
			if decision.Status != decisionlog.StatusFailed || decision.Reason == "" {
				t.Fatalf("held = %+v", decision)
			}
		}
	}
}
