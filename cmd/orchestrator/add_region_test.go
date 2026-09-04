package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func addRegionLookup() envLookup {
	return func(string) (string, bool) { return "", false }
}

func TestParseAddRegionArgs(t *testing.T) {
	code, dryRun, err := parseAddRegionArgs([]string{"add-region", "sfo", dryRunFlag})
	if err != nil || code != "sfo" || !dryRun {
		t.Fatalf("parse = %q, %v, %v", code, dryRun, err)
	}
	code, dryRun, err = parseAddRegionArgs([]string{"add-region", "SFO"})
	if err != nil || code != "sfo" || dryRun {
		t.Fatalf("uppercase code was not canonicalized: %q, %v, %v", code, dryRun, err)
	}
	for _, args := range [][]string{
		{"add-region"},
		{"add-region", ""},
		{"add-region", "--dry-run"},
		{"add-region", "-sfo"},
		{"add-region", "not a code"},
		{"add-region", "sfo", "--bogus"},
		{"add-region", "sfo", dryRunFlag, "extra"},
		{"run", "sfo"},
	} {
		if _, _, err := parseAddRegionArgs(args); err == nil {
			t.Errorf("parseAddRegionArgs(%q) was accepted", args)
		}
	}
}

func TestRequestedCommandAcceptsAddRegion(t *testing.T) {
	for _, args := range [][]string{{"add-region", "sfo"}, {"add-region", "fra", dryRunFlag}} {
		if got, err := requestedCommand(args); err != nil || got != "add-region" {
			t.Errorf("requestedCommand(%q) = %q, %v", args, got, err)
		}
	}
	for _, args := range [][]string{
		{"add-region"},
		{"add-region", "--dry-run"},
		{"add-region", "sfo", "junk"},
		{"add-region", "sfo", dryRunFlag, "extra"},
	} {
		if got, err := requestedCommand(args); err == nil || got != "unsupported" {
			t.Errorf("requestedCommand(%q) = %q, %v; want rejection", args, got, err)
		}
	}
}

func TestAddRegionDryRunOutputsTheRunbook(t *testing.T) {
	output := &bytes.Buffer{}
	if err := execute(context.Background(), []string{"add-region", "sfo", dryRunFlag}, addRegionLookup(), output); err != nil {
		t.Fatalf("add-region --dry-run failed: %v", err)
	}
	plan := output.String()
	for _, want := range []string{
		`"command": "add-region"`,
		`"region": "sfo"`,
		`"ociRegion": "us-sanjose-1"`,
		`"estateVersion": 2`,
		`"count": 2`,
		`"co-hosted"`,
		`"backups"`,
		`"infrequent-access"`,
		`"archive"`,
		`"litestreamTargets"`,
		`sfo.api.terrascale.tech`,
		`regions/sfo`,
		`member-control`,
		`"kind": "create"`,
		`"kind": "compute"`,
		`"kind": "bucket"`,
		`"kind": "certificate"`,
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("runbook is missing %s:\n%s", want, plan)
		}
	}
	// The runbook is scoped to the region: other regions' members and the
	// global edge inventory it does not own must not appear as actions.
	for _, forbidden := range []string{`"region": "gru"`, `"region": "fra"`, `"kind": "dns-record"`, `"kind": "waf-rule"`} {
		if strings.Contains(plan, forbidden) {
			t.Errorf("runbook leaks out-of-region scope %s:\n%s", forbidden, plan)
		}
	}
}

func TestAddRegionDryRunIsDeterministic(t *testing.T) {
	var first, second bytes.Buffer
	for _, output := range []*bytes.Buffer{&first, &second} {
		if err := execute(context.Background(), []string{"add-region", "gru", dryRunFlag}, addRegionLookup(), output); err != nil {
			t.Fatalf("add-region --dry-run failed: %v", err)
		}
	}
	if first.String() != second.String() {
		t.Fatal("add-region runbook is not deterministic")
	}
}

func TestAddRegionDryRunCoversEveryDeclaredRegion(t *testing.T) {
	for _, code := range []string{"gru", "sfo", "fra"} {
		output := &bytes.Buffer{}
		if err := execute(context.Background(), []string{"add-region", code, dryRunFlag}, addRegionLookup(), output); err != nil {
			t.Errorf("add-region %s --dry-run failed: %v", code, err)
		}
	}
}

func TestAddRegionDryRunAcceptsUppercaseCode(t *testing.T) {
	output := &bytes.Buffer{}
	if err := execute(context.Background(), []string{"add-region", "FRA", dryRunFlag}, addRegionLookup(), output); err != nil {
		t.Fatalf("uppercase region code rejected: %v", err)
	}
	if !strings.Contains(output.String(), `"region": "fra"`) {
		t.Fatalf("runbook did not canonicalize the code:\n%s", output.String())
	}
}

func TestAddRegionRefusesUnknownRegion(t *testing.T) {
	for _, args := range [][]string{{"add-region", "ord", dryRunFlag}, {"add-region", "ord"}} {
		err := execute(context.Background(), args, addRegionLookup(), &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "orchestrator add-region failed") {
			t.Errorf("execute(%q) = %v; want the redacted add-region failure", args, err)
		}
	}
}

func TestCheckAddRegionFloor(t *testing.T) {
	spec := estate.Default()
	if err := checkAddRegionFloor(spec.Regions[0]); err != nil {
		t.Fatalf("declared region refused: %v", err)
	}
	single := spec.Regions[0]
	single.Members.Count = 1
	if err := checkAddRegionFloor(single); err == nil || !strings.Contains(err.Error(), "placement requires 2") {
		t.Fatalf("single-host region error = %v; want the placement refusal", err)
	}
	uncontrolled := spec.Regions[0]
	uncontrolled.Members.ControlReplicas = 0
	if err := checkAddRegionFloor(uncontrolled); err == nil || !strings.Contains(err.Error(), "co-host") {
		t.Fatalf("uncontrolled region error = %v; want the co-hosted control refusal", err)
	}
}

func TestAddRegionRunsTheBootstrapStages(t *testing.T) {
	old := runAddRegionBootstrap
	var got provider.BootstrapRequest
	runAddRegionBootstrap = func(_ context.Context, _ func(string) (string, bool), request provider.BootstrapRequest, _ io.Writer) error {
		got = request
		return nil
	}
	t.Cleanup(func() { runAddRegionBootstrap = old })
	if err := execute(context.Background(), []string{"add-region", "fra"}, addRegionLookup(), &bytes.Buffer{}); err != nil {
		t.Fatalf("add-region failed: %v", err)
	}
	if got.Region.Code != "fra" || got.Region.Members.Count < provider.PlacementMinimumMemberHosts {
		t.Fatalf("bootstrap request = %+v; want the declared fra region with two members", got.Region)
	}
}

func TestAddRegionReportsBootstrapFailureWithoutLeaking(t *testing.T) {
	old := runAddRegionBootstrap
	boom := errors.New("bootstrap unavailable")
	runAddRegionBootstrap = func(context.Context, func(string) (string, bool), provider.BootstrapRequest, io.Writer) error {
		return boom
	}
	t.Cleanup(func() { runAddRegionBootstrap = old })
	err := execute(context.Background(), []string{"add-region", "sfo"}, addRegionLookup(), &bytes.Buffer{})
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "orchestrator add-region failed") {
		t.Fatalf("bootstrap failure = %v; want the redacted add-region failure", err)
	}
}

func TestAddRegionDryRunNeedsAnOutput(t *testing.T) {
	if err := runAddRegion(context.Background(), []string{"add-region", "sfo", dryRunFlag}, addRegionLookup(), nil); err == nil {
		t.Fatal("nil runbook output was accepted")
	}
	if err := runAddRegion(nil, []string{"add-region", "sfo", dryRunFlag}, addRegionLookup(), &bytes.Buffer{}); err == nil {
		t.Fatal("nil context was accepted")
	}
}

func TestCatalogListsAddRegion(t *testing.T) {
	var catalog bytes.Buffer
	if err := writeCatalog(&catalog); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(catalog.String(), "add-region") {
		t.Fatalf("catalog does not list add-region:\n%s", catalog.String())
	}
}
