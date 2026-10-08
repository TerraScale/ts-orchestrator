package app

import "testing"

func TestNetBirdAgentSupportProbeNeedsNoHostConfiguration(t *testing.T) {
	for _, action := range []string{"run", "rollback"} {
		if err := runNetBirdAgent(t.Context(), []string{action, "--help"}); err != nil {
			t.Fatalf("support probe tried to run %s: %v", action, err)
		}
	}
	if err := runNetBirdAgent(t.Context(), []string{"unsupported", "--help"}); err == nil {
		t.Fatal("help probe accepted an unsupported worker command")
	}
}
