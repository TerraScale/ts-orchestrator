package main

import (
	"io"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func TestControlCandidateDispatch(t *testing.T) {
	for _, command := range []string{transitiongrant.Mode, "plan-control-candidates", "plan-preliminary-capture"} {
		for _, args := range [][]string{{command}, {command, "--config"}, {command, "--config", ""}, {command, "--config", "/missing", "extra"}, {command, "--owner-key", "/missing"}} {
			if _, err := requestedCommand(args); err == nil {
				t.Fatalf("accepted unsupported candidate arguments %q", args)
			}
		}
		args := []string{command, "--config", "/missing-candidate-config"}
		if name, err := requestedCommand(args); err != nil || name != command || commandName(args) != command {
			t.Fatalf("dispatch %s: %s %v", command, name, err)
		}
		touched := false
		if err := execute(t.Context(), args, func(string) (string, bool) { touched = true; return "", false }, io.Discard); err == nil || touched {
			t.Fatalf("candidate fell through to ordinary composition: %v", err)
		}
	}
}
