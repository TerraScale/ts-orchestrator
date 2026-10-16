package netbird

import (
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

// A failed enrollment can fail before connecting or in cleanup after
// connecting, so its journal entry must not claim the peer is disconnected.
func TestFailedEnrollmentIsNotReportedAsDisconnected(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	recordEnrollment(t.Context(), Config{Region: "gru", ManagementURL: "https://netbird.example"},
		func() (string, error) { return "host-a", nil }, errors.New("vault: permission denied"))
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindPeerEnrolled}})
	if len(result.Decisions) != 1 {
		t.Fatalf("decisions = %+v", result.Decisions)
	}
	decision := result.Decisions[0]
	if decision.Status != decisionlog.StatusFailed || decision.Outcome == "not connected" ||
		strings.Contains(decision.Reason, "did not reach a connected") {
		t.Fatalf("decision = %+v", decision)
	}
}
