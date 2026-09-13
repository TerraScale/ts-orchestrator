package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

func bootstrapRunbookLookup() envLookup {
	values := map[string]string{
		ocireconcile.OCITenancyEnvironment:      "ocid1.tenancy.oc1..aaaaaaaa",
		ocireconcile.OCIImageEnvironment:        "ocid1.image.oc1..aaaaaaaa",
		ociFallbackImageIDEnvironment:           "ocid1.image.oc1..bbbbbbbb",
		bootstrapAvailabilityDomainsEnvironment: "AD-1,AD-2",
		ocireconcile.TSNodeURLEnvironment:       "https://releases.example/ts-node",
		ocireconcile.TSNodeSHA256Environment:    strings.Repeat("a", 64),
		bootstrapReleaseKeyEnvironment:          strings.Repeat("ab", 32),
		addRegionControlJournalEnv:              "/var/lib/terrascale/control-journal.json",
	}
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestParseBootstrapArgs(t *testing.T) {
	dryRun, err := parseBootstrapArgs([]string{"bootstrap"})
	if err != nil || dryRun {
		t.Fatalf("bootstrap = %v, %v; want real run", dryRun, err)
	}
	dryRun, err = parseBootstrapArgs([]string{"bootstrap", dryRunFlag})
	if err != nil || !dryRun {
		t.Fatalf("bootstrap --dry-run = %v, %v; want dry run", dryRun, err)
	}
	secret := "super-secret-argument"
	if _, err := parseBootstrapArgs([]string{"bootstrap", secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("extra argument accepted or leaked: %v", err)
	}
	if _, err := parseBootstrapArgs(nil); err == nil {
		t.Fatal("missing command was accepted")
	}
}

func TestRequestedCommandAcceptsBootstrap(t *testing.T) {
	got, err := requestedCommand([]string{"bootstrap"})
	if err != nil || got != "bootstrap" {
		t.Fatalf("requestedCommand([bootstrap]) = %q, %v", got, err)
	}
	got, err = requestedCommand([]string{"bootstrap", dryRunFlag})
	if err != nil || got != "bootstrap" {
		t.Fatalf("requestedCommand([bootstrap --dry-run]) = %q, %v", got, err)
	}
	if _, err := requestedCommand([]string{"bootstrap", "GRU"}); err == nil {
		t.Fatal("bootstrap with a region argument was accepted")
	}
}

func TestBootstrapDryRunPrintsTheRunbook(t *testing.T) {
	var output bytes.Buffer
	if err := runBootstrap(context.Background(), []string{"bootstrap", dryRunFlag}, bootstrapRunbookLookup(), &output); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	var book bootstrapRunbook
	if err := json.Unmarshal(output.Bytes(), &book); err != nil {
		t.Fatalf("runbook is not JSON: %v", err)
	}
	if book.Command != "bootstrap" || book.Region != "gru" || book.OCIRegion != "sa-saopaulo-1" {
		t.Fatalf("runbook header = %s %s %s", book.Command, book.Region, book.OCIRegion)
	}
	wantStages := []string{"compartment", "network", "vault", "buckets", "hosts", "volumes", "control"}
	if strings.Join(book.Stages, ",") != strings.Join(wantStages, ",") {
		t.Fatalf("stages = %v, want %v", book.Stages, wantStages)
	}
	if err := book.Plan.Validate(); err != nil || book.Plan.Fingerprint == "" {
		t.Fatalf("plan is not valid: %v", err)
	}
	kinds := map[bootstrap.ResourceKind]int{}
	hosts := 0
	for _, step := range book.Plan.Steps {
		kinds[step.Kind]++
		if step.Kind == bootstrap.ResourceHost {
			hosts++
			if step.Host.CloudInit != "" {
				t.Fatalf("retired greenfield cloud-init is still present: %s", step.Host.CloudInit)
			}
		}
	}
	if kinds[bootstrap.ResourceCompartment] != 1 || kinds[bootstrap.ResourceVCN] != 1 ||
		kinds[bootstrap.ResourceNSG] != 1 || kinds[bootstrap.ResourceVault] != 1 ||
		kinds[bootstrap.ResourceBucket] != 2 || hosts != 4 {
		t.Fatalf("plan kinds = %#v", kinds)
	}
	if book.ControlPlan.Operation != bootstrap.ControlOperationBootstrap ||
		book.ControlPlan.To.Topology != bootstrap.ControlTopologyTemporaryR1 ||
		book.ControlPlan.To.Epoch != 1 || !book.Control.Fenced {
		t.Fatalf("control plan = %#v", book.ControlPlan)
	}
	sawStart, sawFence := false, false
	for _, action := range book.ControlPlan.Actions {
		sawStart = sawStart || action.Kind == bootstrap.ControlActionStartTemporaryR1
		sawFence = sawFence || action.Kind == bootstrap.ControlActionFenceR1
	}
	if !sawStart || !sawFence {
		t.Fatalf("control actions = %#v", book.ControlPlan.Actions)
	}
	if book.CloudInit.Installs != "ts-node" || book.CloudInit.Verification != "sha256+ed25519" {
		t.Fatalf("cloud-init contract = %#v", book.CloudInit)
	}
	if strings.Join(book.Members.Hosts, ",") != "gru-member-1,gru-member-2" || book.Members.Count != 2 {
		t.Fatalf("members = %#v", book.Members)
	}
	if len(book.Inputs) != len(bootstrapInputs) {
		t.Fatalf("inputs = %v", book.Inputs)
	}
}

func TestBootstrapDryRunIsDeterministic(t *testing.T) {
	var first, second bytes.Buffer
	if err := renderBootstrapRunbook(bootstrapRunbookLookup(), &first); err != nil {
		t.Fatal(err)
	}
	if err := renderBootstrapRunbook(bootstrapRunbookLookup(), &second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("runbook is not deterministic")
	}
}

func TestBootstrapDryRunNamesEveryMissingInput(t *testing.T) {
	err := renderBootstrapRunbook(func(string) (string, bool) { return "", false }, &bytes.Buffer{})
	if err == nil {
		t.Fatal("missing inputs were accepted")
	}
	for _, name := range bootstrapInputs {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("error %q does not name %s", err, name)
		}
	}
}

func TestBootstrapAvailabilityDomainsRefuseDuplicatesAndGaps(t *testing.T) {
	if _, err := bootstrapAvailabilityDomains("AD-1, AD-2 "); err != nil {
		t.Fatalf("valid domains rejected: %v", err)
	}
	for _, raw := range []string{"", "AD-1,,AD-2", "AD-1,AD-1"} {
		if _, err := bootstrapAvailabilityDomains(raw); err == nil {
			t.Fatalf("domains %q accepted", raw)
		}
	}
}

func TestBootstrapDryRunNeedsAnOutput(t *testing.T) {
	if err := renderBootstrapRunbook(bootstrapRunbookLookup(), nil); err == nil {
		t.Fatal("nil runbook output was accepted")
	}
}

func TestBootstrapRefusesBeforeOCIWhenControlCompositionIsMissing(t *testing.T) {
	oldBootstrap, oldFactory := runBootstrapOCI, bootstrapControlMachineFactory
	called := false
	runBootstrapOCI = func(context.Context, func(string) (string, bool), ocireconcile.BootstrapRequest, io.Writer) error {
		called = true
		return nil
	}
	t.Cleanup(func() {
		runBootstrapOCI = oldBootstrap
		bootstrapControlMachineFactory = oldFactory
	})
	err := runBootstrap(context.Background(), []string{"bootstrap"}, bootstrapRunbookLookup(), &bytes.Buffer{})
	var missing *BootstrapMissingStageError
	if !errors.As(err, &missing) || missing.Stage != "control" {
		t.Fatalf("missing stage error = %v; want control typed refusal", err)
	}
	if called {
		t.Fatal("OCI bootstrap ran despite a missing control composition")
	}
	err = execute(context.Background(), []string{"bootstrap"}, bootstrapRunbookLookup(), &bytes.Buffer{})
	if !errors.Is(err, ErrBootstrapMissingStage) {
		t.Fatalf("dispatch error = %v; want ErrBootstrapMissingStage", err)
	}
}

type bootstrapControlProviderFake struct {
	actions []string
}

func (p *bootstrapControlProviderFake) record(action string) error {
	p.actions = append(p.actions, action)
	return nil
}

func (p *bootstrapControlProviderFake) StartTemporaryR1(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return bootstrap.ControlReceipt{ID: "r1"}, p.record("start-r1")
}

func (p *bootstrapControlProviderFake) FenceTemporaryR1(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return bootstrap.ControlReceipt{ID: "fence"}, p.record("fence-r1")
}

func (p *bootstrapControlProviderFake) unexpected(action string) (bootstrap.ControlReceipt, error) {
	return bootstrap.ControlReceipt{}, errors.New("unexpected control action: " + action)
}

func (p *bootstrapControlProviderFake) StartCandidate(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.unexpected("start-candidate")
}
func (p *bootstrapControlProviderFake) SyncCandidate(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.unexpected("sync-candidate")
}
func (p *bootstrapControlProviderFake) VerifyCandidate(context.Context, bootstrap.ControlActionRequest) (bootstrap.CandidateEvidence, error) {
	return bootstrap.CandidateEvidence{}, errors.New("unexpected control action: verify-candidate")
}
func (p *bootstrapControlProviderFake) PromoteGlobalR3(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.unexpected("promote-r3")
}
func (p *bootstrapControlProviderFake) VerifyGlobalR3(context.Context, bootstrap.ControlActionRequest) error {
	return errors.New("unexpected control action: verify-r3")
}
func (p *bootstrapControlProviderFake) RevokeBootstrapAuthority(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.unexpected("revoke")
}
func (p *bootstrapControlProviderFake) RemoteManageRegion(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.unexpected("remote-manage")
}
func (p *bootstrapControlProviderFake) StartRegionalR3(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.unexpected("regional-r3")
}

func TestBootstrapFormsTheFencedControlGroupAfterOCI(t *testing.T) {
	oldBootstrap, oldFactory := runBootstrapOCI, bootstrapControlMachineFactory
	var order []string
	runBootstrapOCI = func(context.Context, func(string) (string, bool), ocireconcile.BootstrapRequest, io.Writer) error {
		order = append(order, "oci")
		return nil
	}
	fake := &bootstrapControlProviderFake{}
	journal := &bootstrap.MemoryControlJournal{Durable: true}
	machine, err := bootstrap.NewControlStateMachine(fake, journal, bootstrap.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapControlMachineFactory = &bootstrapControlFactory{Validate: func(context.Context, envLookup, string) (*bootstrapControlAdmission, error) {
		return &bootstrapControlAdmission{}, nil
	}, Construct: func(context.Context, *bootstrapControlAdmission, string) (*bootstrap.ControlStateMachine, error) {
		order = append(order, "control")
		return machine, nil
	}}
	t.Cleanup(func() {
		runBootstrapOCI = oldBootstrap
		bootstrapControlMachineFactory = oldFactory
	})
	if err := runBootstrap(context.Background(), []string{"bootstrap"}, bootstrapRunbookLookup(), &bytes.Buffer{}); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if strings.Join(order, ",") != "oci,control" {
		t.Fatalf("stage order = %v; want OCI stages before control formation", order)
	}
	if strings.Join(fake.actions, ",") != "start-r1,fence-r1" {
		t.Fatalf("control actions = %v", fake.actions)
	}
	if journal.Record.State.Topology != bootstrap.ControlTopologyTemporaryR1 || journal.Record.State.Epoch != 1 {
		t.Fatalf("control state = %#v", journal.Record.State)
	}
	// A re-run resumes the completed transition: no provider action repeats.
	if err := runBootstrap(context.Background(), []string{"bootstrap"}, bootstrapRunbookLookup(), &bytes.Buffer{}); err != nil {
		t.Fatalf("bootstrap re-run failed: %v", err)
	}
	if strings.Join(fake.actions, ",") != "start-r1,fence-r1" {
		t.Fatalf("control actions after re-run = %v", fake.actions)
	}
}

func TestBootstrapResumesAMidTransitionControlJournal(t *testing.T) {
	oldBootstrap, oldFactory := runBootstrapOCI, bootstrapControlMachineFactory
	runBootstrapOCI = func(context.Context, func(string) (string, bool), ocireconcile.BootstrapRequest, io.Writer) error {
		return nil
	}
	region, err := ocireconcile.DefaultBootstrapRegion()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := bootstrap.PlanControlTransition(bootstrap.ControlPlaneState{}, bootstrap.ControlTransitionRequest{
		Operation: bootstrap.ControlOperationBootstrap, Region: region.Code, MemberHosts: int(region.Members.Count),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A crash after the first action leaves the durable journal holding the
	// pre-transition state with one completed action.
	fake := &bootstrapControlProviderFake{}
	journal := &bootstrap.MemoryControlJournal{Durable: true, Record: bootstrap.ControlJournalRecord{
		PlanFingerprint: plan.Fingerprint, State: plan.From, Completed: []string{plan.Actions[0].ID},
	}}
	machine, err := bootstrap.NewControlStateMachine(fake, journal, bootstrap.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapControlMachineFactory = &bootstrapControlFactory{Validate: func(context.Context, envLookup, string) (*bootstrapControlAdmission, error) {
		return &bootstrapControlAdmission{}, nil
	}, Construct: func(context.Context, *bootstrapControlAdmission, string) (*bootstrap.ControlStateMachine, error) {
		return machine, nil
	}}
	t.Cleanup(func() {
		runBootstrapOCI = oldBootstrap
		bootstrapControlMachineFactory = oldFactory
	})
	if err := runBootstrap(context.Background(), []string{"bootstrap"}, bootstrapRunbookLookup(), &bytes.Buffer{}); err != nil {
		t.Fatalf("bootstrap resume failed: %v", err)
	}
	if strings.Join(fake.actions, ",") != "fence-r1" {
		t.Fatalf("resumed control actions = %v; want only the remaining fence action", fake.actions)
	}
	if journal.Record.State.Topology != bootstrap.ControlTopologyTemporaryR1 || journal.Record.State.Epoch != 1 {
		t.Fatalf("resumed control state = %#v", journal.Record.State)
	}
}

func TestBootstrapDispatchDryRunThroughExecute(t *testing.T) {
	var output bytes.Buffer
	if err := execute(context.Background(), []string{"bootstrap", dryRunFlag}, bootstrapRunbookLookup(), &output); err != nil {
		t.Fatalf("dispatch dry run failed: %v", err)
	}
	if !strings.Contains(output.String(), `"command": "bootstrap"`) {
		t.Fatalf("dispatch output is not the runbook:\n%s", output.String())
	}
}

func TestCatalogListsBootstrap(t *testing.T) {
	var catalog bytes.Buffer
	if err := writeCatalog(&catalog); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(catalog.String(), "bootstrap") {
		t.Fatalf("catalog does not list bootstrap:\n%s", catalog.String())
	}
}
