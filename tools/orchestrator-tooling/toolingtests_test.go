// Go-test wrapper for the ported ToolingTests bodies. The full suite remains
// available through `orchestrator-tooling test`; the Go test runs its hermetic
// bodies directly.
package main

import (
	"context"
	"os"
	"testing"
)

var hermeticToolingTests = map[string]bool{
	"git bytes preserve non UTF-8 blob": true,
	"no python sources":                 true,
	"workspace topology lease":          true,
}

func TestToolingHermetic(t *testing.T) {
	ran := 0
	for _, test := range toolingTestSuite() {
		if !hermeticToolingTests[test.Name] {
			continue
		}
		ran++
		test := test
		t.Run(test.Name, func(t *testing.T) {
			if err := runToolingTestBody(test.Body); err != nil {
				t.Fatal(err)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no hermetic tooling tests were selected")
	}
}

func TestCommandInventoryIsExact(t *testing.T) {
	expected := map[string]bool{
		"json-format":                     true,
		"test":                            true,
		"workspace-topology-lease-holder": true,
	}
	if len(toolCommands) != len(expected) {
		t.Fatalf("command count = %d, want %d", len(toolCommands), len(expected))
	}
	for _, command := range toolCommands {
		if !expected[command.name] {
			t.Fatalf("unexpected command %q remains registered", command.name)
		}
	}
}

func TestWorkspaceTopologyLeaseHolderProcess(t *testing.T) {
	if os.Getenv("TERRASCALE_TOOLING_LEASE_HOLDER") != "1" {
		t.Skip("helper process")
	}
	arguments := []string{"--namespace", os.Getenv("TERRASCALE_TOOLING_LEASE_NAMESPACE")}
	if os.Getenv("TERRASCALE_TOOLING_LEASE_NOISY") == "true" &&
		os.Getenv("TERRASCALE_TOOLING_LEASE_IGNORE_STDIN") == "true" {
		arguments = append(arguments, "--noisy-stderr", "--ignore-stdin")
	}
	if _, err := WorkspaceTopologyLeaseHolderCommand.RunAsync(context.Background(), arguments); err != nil {
		t.Fatal(err)
	}
}
