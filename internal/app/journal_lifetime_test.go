package app

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// A controller that returns while its caller's context is still live (a
// startup or worker error) stops its journal on close: the failed
// controller's journal is no longer the process recorder.
func TestClosingTheRuntimeStopsItsJournal(t *testing.T) {
	previous := decisionlog.Default()
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "one"}}
	telemetry, err := startRuntimeObservability(t.Context(), cfg, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	if decisionlog.Default() != telemetry.journal {
		t.Fatal("the controller journal is not the process recorder")
	}
	telemetry.close()
	deadline := time.Now().Add(5 * time.Second)
	for decisionlog.Default() == telemetry.journal {
		if time.Now().After(deadline) {
			t.Fatal("a closed runtime's journal is still the process recorder")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if decisionlog.Default() != previous {
		t.Fatal("closing did not restore the previous recorder")
	}
}
