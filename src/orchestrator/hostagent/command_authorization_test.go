package hostagent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

// Unit lifecycle tests inject a test-only authority. Actual signature, live
// leader reads and durable epoch rejection are tested in nodeauthority.
type testCommandAuthorizer struct{}

func (testCommandAuthorizer) Authorize(_ context.Context, _ string, command []byte) (nodeauthority.CommandAuthorization, error) {
	return nodeauthority.CommandAuthorization{NodeID: "gru-1", AuthorityID: "gru-regional", Epoch: 1, CandidateID: "gru-controller-test", LeaseID: "test-lease", Command: command, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func testCommandAuthorityFactory(NatsConnection) (nodeauthority.CommandAuthorizer, error) {
	return testCommandAuthorizer{}, nil
}

func TestPendingDrainDoesNotMutateDuringReceiverRestart(t *testing.T) {
	for _, drain := range []bool{true, false} {
		t.Run(map[bool]string{true: "pending-drain", false: "pending-release"}[drain], func(t *testing.T) {
			harness := newTestHarness(t)
			journal, err := newCommandJournal(filepath.Join(harness.dataVolume, TsNodeComponentName, "command-journal"))
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.initialize(); err != nil {
				t.Fatal(err)
			}
			command, err := NewDrainCommand("pending-drain", drain)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := journal.begin(commandKindDrain, command.CommandId, mustJSON(t, command), nil); err != nil {
				t.Fatal(err)
			}
			before := len(harness.systemd.ops())
			_, _, _ = newTestTransport(t, harness)
			if after := len(harness.systemd.ops()); after != before {
				t.Fatalf("pending drain mutated during restart: before%d after%d", before, after)
			}
			pending, err := journal.pending()
			if err != nil || len(pending) != 1 {
				t.Fatalf("pending outcome discarded: %d %v", len(pending), err)
			}
		})
	}
}
