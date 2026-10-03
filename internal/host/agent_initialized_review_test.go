package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type failingRecoverRunner struct{ *memoryRunner }

func (failingRecoverRunner) Recover(context.Context) error {
	return errors.New("ownership lock held")
}

// The self-update activation proof is emitted from Initialized, which runs
// only after native recovery succeeded: a release whose agent cannot recover
// its workloads must never be confirmed (#127 11983).
func TestAgentSignalsInitializedOnlyAfterRecovery(t *testing.T) {
	_, conn, _, _, responseKey := testController(t)
	hostKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	newAgent := func(runner Runner, initialized func()) *Agent {
		agent, err := NewAgent(AgentConfig{NATSUserPublicKey: testNATSUserKey("node-a"), ClockCheck: func() error { return nil },
			WorkloadIdentity: testAgentIdentity(), Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
			Conn: conn, Identity: hostKey, ControllerPublicKey: responseKey.Public().(ed25519.PublicKey), Runner: runner,
			InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t), Initialized: initialized})
		if err != nil {
			t.Fatal(err)
		}
		return agent
	}
	var calls atomic.Int32
	failing := newAgent(failingRecoverRunner{&memoryRunner{observed: map[string]Observation{}}}, func() { calls.Add(1) })
	if err := failing.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "recover native workloads") {
		t.Fatalf("failed recovery = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("Initialized ran although native recovery failed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	recovered := newAgent(&memoryRunner{observed: map[string]Observation{}}, func() {
		calls.Add(1)
		cancel()
	})
	_ = recovered.Run(ctx)
	if calls.Load() != 1 {
		t.Fatalf("Initialized calls after recovery = %d, want 1", calls.Load())
	}
}
