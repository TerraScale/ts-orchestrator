package hostagent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

type closeCountingAuthority struct {
	testCommandAuthorizer
	closes int
}

func (a *closeCountingAuthority) Close() error { a.closes++; return nil }

func TestAgentStartupFailureClosesAuthority(t *testing.T) {
	for _, failure := range []string{"journal", "manifest"} {
		t.Run(failure, func(t *testing.T) {
			harness := newTestHarness(t)
			if failure == "journal" {
				journal, err := newCommandJournal(filepath.Join(harness.lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "command-journal"))
				if err != nil {
					t.Fatal(err)
				}
				if err := journal.initialize(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(journal.path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			authority := &closeCountingAuthority{}
			agent, err := NewHostAgent(HostAgentConfig{
				CommandAuthorityFactory: func(NatsConnection) (nodeauthority.CommandAuthorizer, error) { return authority, nil },
				NodeId:                  NodeId{Value: "gru-1"}, Connection: newFakeNatsConnection(), Lifecycle: harness.lifecycle,
				Facts: harness.factsSource(t), ManifestPath: filepath.Join(t.TempDir(), "missing.json"),
				ReconcileInterval: time.Second, HeartbeatInterval: time.Second, Now: time.Now,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.Start(t.Context()); err == nil {
				t.Fatal("startup failure expected")
			}
			if authority.closes != 1 {
				t.Fatalf("authority closes = %d; want 1", authority.closes)
			}
			if err := agent.Close(); err != nil {
				t.Fatal(err)
			}
			if authority.closes != 1 {
				t.Fatalf("authority closed twice: %d", authority.closes)
			}
		})
	}
}
