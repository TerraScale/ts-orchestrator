package bootstrapstart

import (
	"errors"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// A launch error does not prove that OCI created no instance (a lost
// response is ambiguous), so the journal must not say it did not.
func TestFailedFounderLaunchDoesNotClaimNoInstance(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	recordFounderLaunch(t.Context(), "gru", "deployment", "slot-2", FounderOCIAttempt{}, "",
		errors.New("context deadline exceeded"))
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindFounderLaunched}})
	if len(result.Decisions) != 1 {
		t.Fatalf("decisions = %+v", result.Decisions)
	}
	decision := result.Decisions[0]
	if decision.Status != decisionlog.StatusFailed || strings.Contains(decision.Reason, "did not create") ||
		!strings.Contains(decision.Reason, "could not be confirmed") {
		t.Fatalf("decision = %+v", decision)
	}
}
