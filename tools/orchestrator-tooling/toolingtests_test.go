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
	"git bytes preserve non UTF-8 blob":         true,
	"no python sources":                         true,
	"retired deploy handoff v1 fixtures absent": true,
	"CI result manifest":                        true,
	"workspace topology lease":                  true,
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

func TestCommandInventory(t *testing.T) {
	expected := []string{
		"ci-result-manifest",
		"json-format",
		"test",
		"workspace-topology-lease-holder",
	}
	if len(toolCommands) != len(expected) {
		t.Fatalf("expected %d commands, observed %d", len(expected), len(toolCommands))
	}
	for index, command := range toolCommands {
		if command.name != expected[index] {
			t.Fatalf("expected command %q at index %d, observed %q", expected[index], index, command.name)
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
