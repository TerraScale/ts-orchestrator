package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"testing"
)

func TestBootstrapControlFilesRejectSymlinksAndSharedSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapControlFile(path, true, 100); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapControlFile(link, true, 100); err == nil {
		t.Fatal("symlink secret admitted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapControlFile(path, true, 100); err == nil {
		t.Fatal("shared secret admitted")
	}
	if _, err := readBootstrapControlFile(path, false, 2); err == nil {
		t.Fatal("oversized credential admitted")
	}
}
func TestBootstrapControlReceiptPinsGenerationToActualMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	first := bootstrapControlReceipt{Generation: 1, DeclarationSHA256: "declaration", Regions: []bootstrap.ControlRegionBinding{{Code: "gru", OCIRegion: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1..owner", MemberIDs: []string{"ocid1.instance.oc1..one"}}}}
	if err := persistBootstrapControlReceipt(path, first); err != nil {
		t.Fatal(err)
	}
	if err := persistBootstrapControlReceipt(path, first); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.DeclarationSHA256 = "changed"
	if err := persistBootstrapControlReceipt(path, changed); err == nil {
		t.Fatal("same generation declaration replacement admitted")
	}
	changed.Generation = 2
	if err := persistBootstrapControlReceipt(path, changed); err != nil {
		t.Fatal(err)
	}
	if err := persistBootstrapControlReceipt(path, first); err == nil {
		t.Fatal("receipt generation regressed")
	}
}
func TestBootstrapControlConfigUnknownFieldsFailBeforeCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadBootstrapControl(func(key string) (string, bool) { return path, key == bootstrapControlConfigEnvironment })
	if err == nil || err.Error() != "control: malformed runtime configuration" {
		t.Fatalf("unknown field error: %v", err)
	}
}

func TestDefaultControlFactoryPreflightRefusesBeforeOCI(t *testing.T) {
	original, originalFactory := runBootstrapOCI, bootstrapControlMachineFactory
	defer func() { runBootstrapOCI = original; bootstrapControlMachineFactory = originalFactory }()
	bootstrapControlMachineFactory = newBootstrapControlFactory()
	touched := false
	runBootstrapOCI = func(context.Context, func(string) (string, bool), ocireconcile.BootstrapRequest, io.Writer) error {
		touched = true
		return nil
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	base := bootstrapRunbookLookup()
	lookup := func(key string) (string, bool) {
		switch key {
		case addRegionControlJournalEnv:
			return filepath.Join(dir, "journal.json"), true
		case bootstrapControlConfigEnvironment:
			return path, true
		default:
			return base(key)
		}
	}
	if err := runBootstrap(context.Background(), []string{"bootstrap"}, lookup, io.Discard); err == nil {
		t.Fatal("invalid real runtime configuration accepted")
	}
	if touched {
		t.Fatal("OCI mutated before default factory preflight")
	}
}

func TestControlStageInitialGRUDoesNotRequireFutureLaunchRegions(t *testing.T) {
	loaded := loadedBootstrapControl{declaration: bootstrapControlConfig{Generation: 1, ReceiptFile: filepath.Join(t.TempDir(), "receipt.json"), Regions: []bootstrapControlRegion{{Code: "gru"}, {Code: "sfo"}, {Code: "fra"}}}}
	for _, region := range []string{"gru", "sfo", "fra"} {
		member := bootstrap.ControlRuntimeMember{MemberID: region + "-1", HostID: region + "-1", Region: region, ServerName: region + "-nats"}
		loaded.members = append(loaded.members, member)
		loaded.actions = append(loaded.actions, bootstrap.ControlRuntimeActionPlan{Kind: bootstrap.ControlActionStartCandidate, Region: region, TargetEpoch: 1, Handoffs: []bootstrap.ControlHostHandoff{{MemberID: member.MemberID}}})
	}
	loaded.actions = append(loaded.actions, bootstrap.ControlRuntimeActionPlan{Kind: bootstrap.ControlActionPromoteR3, Region: "gru", TargetEpoch: 2, Checks: []bootstrap.ControlStoreCheck{{Streams: []bootstrap.ControlStreamAssignment{{Name: "GLOBAL_SPEC", Replicas: 3, Servers: []string{"gru-nats", "sfo-nats", "fra-nats"}}}}}})
	complete := loaded
	regions, err := selectBootstrapControlStage(&loaded, "gru")
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 1 || regions[0].Code != "gru" || len(loaded.members) != 1 || loaded.members[0].Region != "gru" || len(loaded.actions) != 1 || loaded.actions[0].Region != "gru" {
		t.Fatalf("initial stage required future resources: regions=%+v members=%+v actions=%+v", regions, loaded.members, loaded.actions)
	}
	digest, err := bootstrapControlIntentDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistBootstrapControlReceipt(complete.declaration.ReceiptFile, bootstrapControlReceipt{Generation: 1, DeclarationSHA256: digest, Regions: []bootstrap.ControlRegionBinding{{Code: "gru"}}}); err != nil {
		t.Fatal(err)
	}
	regions, err = selectBootstrapControlStage(&complete, "sfo")
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 2 || len(complete.members) != 2 || len(complete.actions) != 2 {
		t.Fatalf("SFO stage did not retain GRU without FRA: %+v %+v %+v", regions, complete.members, complete.actions)
	}
}

func TestControlFactoryCancellationPrecedesFileOrProviderWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	touched := false
	_, err := validateBootstrapControlConfiguration(ctx, func(string) (string, bool) { touched = true; return "", false }, "gru")
	if !errors.Is(err, context.Canceled) || touched {
		t.Fatalf("cancelled validation touched input: %v %v", err, touched)
	}
	if _, err := newBootstrapControlMachine(ctx, &bootstrapControlAdmission{}, "/unused/journal"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled construction: %v", err)
	}
}

func TestBootstrapControlMemberRequiresExplicitArchitecture(t *testing.T) {
	for _, input := range []string{`{}`, `{"architecture":null}`, `{"architecture":2}`, `{"architecture":0,"unknown":true}`} {
		var member bootstrapControlMember
		if err := json.Unmarshal([]byte(input), &member); err == nil {
			t.Fatalf("invalid architecture declaration accepted: %s", input)
		}
	}
	for _, input := range []string{`{"architecture":0}`, `{"architecture":1}`} {
		var member bootstrapControlMember
		if err := json.Unmarshal([]byte(input), &member); err != nil {
			t.Fatal(err)
		}
	}
}
