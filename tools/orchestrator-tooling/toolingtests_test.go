// Go-test wrapper for the ported ToolingTests bodies. The full suite remains
// available through `orchestrator-tooling test`; here only the hermetic
// bodies run, because the mutation-based validator tests require the sibling
// TerraScale workspace repositories to be checked out next to this module.
package main

import (
	"context"
	"os"
	"testing"
)

var hermeticToolingTests = map[string]bool{
	"git bytes preserve non UTF-8 blob":                  true,
	"no python sources":                                  true,
	"CI result manifest":                                 true,
	"development evidence fixed topology authorization":  true,
	"development evidence bounded execution":             true,
	"development bounded process observation":            true,
	"development validation lease":                       true,
	"development validation lease recovers stale holder": true,
	"workspace topology lease":                           true,
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

func TestRetiredDocumentCommandsAreAbsent(t *testing.T) {
	retired := map[string]bool{
		"adr-readiness":   true,
		"owner-decisions": true,
		"phase0-evidence": true,
	}
	for _, command := range toolCommands {
		if retired[command.name] {
			t.Fatalf("retired document command %q remains registered", command.name)
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
