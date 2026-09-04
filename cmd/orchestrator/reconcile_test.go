package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestReconcileDryRunPrintsThePlan(t *testing.T) {
	output := &bytes.Buffer{}
	if err := execute(context.Background(), []string{"reconcile", dryRunFlag}, func(string) (string, bool) { return "", false }, output); err != nil {
		t.Fatalf("reconcile --dry-run failed: %v", err)
	}
	plan := output.String()
	for _, want := range []string{
		`"estateVersion": 2`,
		`"kind": "create"`,
		`"kind": "bucket"`,
		`"kind": "dns-record"`,
		`"kind": "waf-rule"`,
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("dry-run plan is missing %s:\n%s", want, plan)
		}
	}
	// The plan is the whole declared estate observed empty: every declared
	// resource appears as a create.
	creates := strings.Count(plan, `"kind": "create"`)
	if creates < 40 {
		t.Fatalf("dry-run plan has %d creates, want the whole declared estate", creates)
	}
}

func TestReconcileLoopRequiresProviders(t *testing.T) {
	if err := runReconcile(context.Background(), []string{"reconcile"}, &bytes.Buffer{}); err == nil {
		t.Fatal("the running loop without provider adapters (they land with I-2) must be refused")
	}
}

func TestRequestedCommandAcceptsOnlyTheDryRunFlag(t *testing.T) {
	for _, args := range [][]string{{"reconcile"}, {"reconcile", dryRunFlag}} {
		if got, err := requestedCommand(args); err != nil || got != "reconcile" {
			t.Errorf("requestedCommand(%q) = %q, %v", args, got, err)
		}
	}
	for _, args := range [][]string{
		{"reconcile", "junk"},
		{"reconcile", dryRunFlag, "extra"},
		{"reconcile", "--dry-run", "--dry-run"},
	} {
		if got, err := requestedCommand(args); err == nil || got != "unsupported" {
			t.Errorf("requestedCommand(%q) = %q, %v; want rejection", args, got, err)
		}
	}
}
