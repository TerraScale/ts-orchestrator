package main

// Command bootstrap is the I-2 greenfield entry point (D-67): one run from
// the owner's machine takes an empty tenancy to the fenced, temporary
// pre-customer GRU R1. The OCI stages create the compartment, VCN, NSGs,
// vault, buckets, and the first two GRU member hosts whose cloud-init
// installs only ts-node; the hosts then fetch the orchestrator and TerraBase
// through ts-node and form the control group.
//
// --dry-run renders the runbook — the ordered plan steps with the exact
// cloud-init, the fenced control-group transition, and every required
// non-secret input — while resolving no credentials and making no provider
// calls. Without --dry-run the command refuses before the first provider
// mutation when the durable control composition is missing, then runs the
// OCI stages and the control-group transition in that order.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

// bootstrapStages is the converge order one bootstrap run follows: the OCI
// provider aggregate internally converges network, vault, buckets, hosts and
// volumes after the compartment; control is the fenced temporary R1 the
// first hosts form. The order is part of the runbook contract.
var bootstrapStages = []string{"compartment", "network", "vault", "buckets", "hosts", "volumes", "control"}

const (
	// bootstrapAvailabilityDomainsEnvironment lists the tenancy's GRU
	// availability domains, comma-separated. Hosts land in separate failure
	// domains (D-65); the planner refuses an empty or duplicated list.
	bootstrapAvailabilityDomainsEnvironment = "TS_ORCH_OCI_AVAILABILITY_DOMAINS"
	// bootstrapReleaseKeyEnvironment pins the Ed25519 public key that
	// verifies the ts-node release signature inside cloud-init. A digest
	// alone is not an authentication mechanism, so the key is required.
	bootstrapReleaseKeyEnvironment = "TS_ORCH_RELEASE_PUBLIC_KEY"
)

// bootstrapInputs are the non-secret environment inputs a bootstrap runbook
// needs. Credential material is resolved only by the real run, loudly, from
// its own variables.
var bootstrapInputs = []string{
	ocireconcile.OCITenancyEnvironment,
	ocireconcile.OCIImageEnvironment,
	ociFallbackImageIDEnvironment,
	bootstrapAvailabilityDomainsEnvironment,
	ocireconcile.TSNodeURLEnvironment,
	ocireconcile.TSNodeSHA256Environment,
	bootstrapReleaseKeyEnvironment,
}

// runBootstrapOCI is the OCI provider boundary for the estate stages; a
// variable so command tests can prove ordering without provider credentials.
// The reconcilers themselves are never replaced.
var runBootstrapOCI = ocireconcile.RunOCIBootstrapFromEnvironment

// bootstrapControlMachineFactory composes the durable, fenced control state
// machine from reviewed declarations and owner credential references.
var bootstrapControlMachineFactory = newBootstrapControlFactory()

// ErrBootstrapMissingStage classifies a composition refusal for callers that
// prefer errors.Is; BootstrapMissingStageError carries the exact stage.
var ErrBootstrapMissingStage = errors.New("bootstrap required stage is missing")

// BootstrapMissingStageError is returned when command composition does not
// provide a required stage. It is typed so callers can report an actionable
// wiring failure without inspecting arbitrary text.
type BootstrapMissingStageError struct {
	Stage  string
	Detail string
}

func (e *BootstrapMissingStageError) Error() string {
	if e == nil || e.Stage == "" {
		return "bootstrap required stage is missing"
	}
	if e.Detail != "" {
		return "bootstrap required stage is missing: " + e.Stage + " (" + e.Detail + ")"
	}
	return "bootstrap required stage is missing: " + e.Stage
}

func (e *BootstrapMissingStageError) Is(target error) bool {
	return target == ErrBootstrapMissingStage
}

func bootstrapMissingStage(stage string, err error) error {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	return &BootstrapMissingStageError{Stage: stage, Detail: detail}
}

// runBootstrap dispatches the bootstrap command: a dry run renders the
// runbook; a real run provisions the estate and forms the control group.
func runBootstrap(ctx context.Context, args []string, lookup envLookup, output io.Writer) error {
	if ctx == nil {
		return errors.New("bootstrap: context is nil")
	}
	dryRun, err := parseBootstrapArgs(args)
	if err != nil {
		return err
	}
	if dryRun {
		return renderBootstrapRunbook(lookup, output)
	}
	return runBootstrapProvision(ctx, lookup, output)
}

// parseBootstrapArgs accepts `bootstrap` and `bootstrap --dry-run`. Anything
// else is rejected here so credential-like arguments are never echoed.
func parseBootstrapArgs(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "bootstrap" {
		return false, errors.New("bootstrap: command is required")
	}
	if len(args) == 1 {
		return false, nil
	}
	if len(args) == 2 && args[1] == dryRunFlag {
		return true, nil
	}
	return false, errors.New("bootstrap: command accepts only --dry-run")
}

// bootstrapConfigFromEnv assembles the greenfield planner input from the
// declared closed GRU shape plus the required non-secret inputs. Missing
// variables are named all at once; malformed values fail closed without
// echoing the offending value.
func bootstrapConfigFromEnv(lookup envLookup) (bootstrap.BootstrapConfig, error) {
	if lookup == nil {
		return bootstrap.BootstrapConfig{}, errors.New("bootstrap: environment lookup is nil")
	}
	values := make(map[string]string, len(bootstrapInputs))
	var missing []string
	for _, name := range bootstrapInputs {
		value, present := lookup(name)
		value = strings.TrimSpace(value)
		if !present || value == "" {
			missing = append(missing, name)
			continue
		}
		values[name] = value
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return bootstrap.BootstrapConfig{}, errors.New("bootstrap requires non-secret inputs: set " + strings.Join(missing, ", "))
	}
	domains, err := bootstrapAvailabilityDomains(values[bootstrapAvailabilityDomainsEnvironment])
	if err != nil {
		return bootstrap.BootstrapConfig{}, err
	}
	artifactURL := values[ocireconcile.TSNodeURLEnvironment]
	config := bootstrap.DefaultBootstrapConfig()
	config.TenancyID = values[ocireconcile.OCITenancyEnvironment]
	config.ImageID = values[ocireconcile.OCIImageEnvironment]
	config.FallbackImageID = values[ociFallbackImageIDEnvironment]
	config.AvailabilityDomains = domains
	config.CloudInit = bootstrap.CloudInitConfig{
		ArtifactURL:        artifactURL,
		SignatureURL:       artifactURL + ".sig",
		SHA256:             values[ocireconcile.TSNodeSHA256Environment],
		SignaturePublicKey: values[bootstrapReleaseKeyEnvironment],
	}
	if err := config.Validate(); err != nil {
		return bootstrap.BootstrapConfig{}, errors.New("bootstrap inputs are malformed; nothing was provisioned")
	}
	return config, nil
}

// bootstrapAvailabilityDomains parses the comma-separated domain list. Empty
// entries and duplicates are refused: two hosts must mean two failure
// domains, never one domain listed twice.
func bootstrapAvailabilityDomains(raw string) ([]string, error) {
	seen := make(map[string]bool)
	var domains []string
	for _, domain := range strings.Split(raw, ",") {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.ContainsAny(domain, "\r\n\x00") || len(domain) > 256 {
			return nil, errors.New("bootstrap availability domains are invalid")
		}
		if seen[domain] {
			return nil, errors.New("bootstrap availability domains are invalid")
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	if len(domains) == 0 || len(domains) > 16 {
		return nil, errors.New("bootstrap availability domains are invalid")
	}
	return domains, nil
}

// bootstrapRunbook is the --dry-run output: the complete greenfield contract
// for one bootstrap run. The plan steps reuse the pure planner verbatim so
// the runbook cannot drift from what a journal-driven execution would do.
type bootstrapRunbook struct {
	Command       string                    `json:"command"`
	Region        string                    `json:"region"`
	OCIRegion     string                    `json:"ociRegion"`
	EstateVersion uint32                    `json:"estateVersion"`
	Stages        []string                  `json:"stages"`
	Members       bootstrapRunbookMembers   `json:"members"`
	CloudInit     bootstrapRunbookCloudInit `json:"cloudInit"`
	Control       bootstrapRunbookControl   `json:"control"`
	Inputs        []string                  `json:"inputs"`
	Plan          bootstrap.Plan            `json:"plan"`
	ControlPlan   bootstrap.ControlPlan     `json:"controlPlan"`
}

type bootstrapRunbookMembers struct {
	Count               uint16   `json:"count"`
	PrimaryShape        string   `json:"primaryShape"`
	FallbackShape       string   `json:"fallbackShape"`
	OCPUs               float64  `json:"ocpus"`
	MemoryGiB           float64  `json:"memoryGiB"`
	DataVolumeGiB       uint64   `json:"dataVolumeGiB"`
	Hosts               []string `json:"hosts"`
	AvailabilityDomains []string `json:"availabilityDomains"`
}

// bootstrapRunbookCloudInit states the D-67 host contract: cloud-init
// installs only ts-node, verification is digest plus signature, and every
// later artifact — the orchestrator and TerraBase included — is fetched by
// ts-node after handoff, never by cloud-init.
type bootstrapRunbookCloudInit struct {
	Installs            string   `json:"installs"`
	Verification        string   `json:"verification"`
	FetchesAfterHandoff []string `json:"fetchesAfterHandoff"`
}

type bootstrapRunbookControl struct {
	Mode               string `json:"mode"`
	Phase              string `json:"phase"`
	Epoch              uint64 `json:"epoch"`
	Region             string `json:"region"`
	Fenced             bool   `json:"fenced"`
	BootstrapAuthority string `json:"bootstrapAuthority"`
}

// renderBootstrapRunbook writes the deterministic greenfield runbook. It
// resolves no credentials and makes no provider calls.
func renderBootstrapRunbook(lookup envLookup, output io.Writer) error {
	if output == nil {
		return errors.New("bootstrap: runbook output is nil")
	}
	config, err := bootstrapConfigFromEnv(lookup)
	if err != nil {
		return err
	}
	region, err := ocireconcile.DefaultBootstrapRegion()
	if err != nil {
		return err
	}
	book, err := buildBootstrapRunbook(config, region)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(book)
}

func buildBootstrapRunbook(config bootstrap.BootstrapConfig, region estate.Region) (bootstrapRunbook, error) {
	if region.OCIName != config.OCIRegion {
		return bootstrapRunbook{}, errors.New("bootstrap: declared home region disagrees with the greenfield shape")
	}
	if region.Members.Count != bootstrap.BootstrapHostCount {
		return bootstrapRunbook{}, errors.New("bootstrap: declared home region must start with exactly two member hosts")
	}
	plan, err := bootstrap.PlanBootstrap(config)
	if err != nil {
		return bootstrapRunbook{}, err
	}
	controlPlan, err := bootstrap.PlanControlTransition(bootstrap.ControlPlaneState{}, bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationBootstrap,
		Region:      region.Code,
		MemberHosts: int(region.Members.Count),
	})
	if err != nil {
		return bootstrapRunbook{}, err
	}
	var hosts []string
	for _, step := range plan.Steps {
		if step.Kind == bootstrap.ResourceHost {
			hosts = append(hosts, step.Name)
		}
	}
	if len(hosts) != bootstrap.BootstrapHostCount {
		return bootstrapRunbook{}, errors.New("bootstrap: plan does not create the first two GRU hosts")
	}
	fenced := false
	for _, action := range controlPlan.Actions {
		if action.Kind == bootstrap.ControlActionFenceR1 {
			fenced = true
		}
	}
	inputs := append([]string(nil), bootstrapInputs...)
	sort.Strings(inputs)
	return bootstrapRunbook{
		Command:       "bootstrap",
		Region:        region.Code,
		OCIRegion:     config.OCIRegion,
		EstateVersion: estate.SchemaVersion,
		Stages:        append([]string(nil), bootstrapStages...),
		Members: bootstrapRunbookMembers{
			Count:               bootstrap.BootstrapHostCount,
			PrimaryShape:        config.PrimaryShape,
			FallbackShape:       config.FallbackShape,
			OCPUs:               config.OCPUs,
			MemoryGiB:           config.MemoryGiB,
			DataVolumeGiB:       config.DataVolumeGiB,
			Hosts:               hosts,
			AvailabilityDomains: append([]string(nil), config.AvailabilityDomains...),
		},
		CloudInit: bootstrapRunbookCloudInit{
			Installs:            "ts-node",
			Verification:        "sha256+ed25519",
			FetchesAfterHandoff: []string{"orchestrator", "terrabase"},
		},
		Control: bootstrapRunbookControl{
			Mode:               string(controlPlan.To.Topology),
			Phase:              string(controlPlan.To.Phase),
			Epoch:              controlPlan.To.Epoch,
			Region:             region.Code,
			Fenced:             fenced,
			BootstrapAuthority: "retired-after-r3-promotion",
		},
		Inputs:      inputs,
		Plan:        plan,
		ControlPlan: controlPlan,
	}, nil
}

// runBootstrapProvision is the real bootstrap run: refuse before the first
// provider mutation when the control composition is missing, converge the
// OCI estate, then form the fenced control group. Discovering an unwired
// control stage after half an estate exists would be a partial build
// reported as a safe failure.
func runBootstrapProvision(ctx context.Context, lookup envLookup, output io.Writer) error {
	if lookup == nil {
		return errors.New("bootstrap: environment lookup is nil")
	}
	region, err := ocireconcile.DefaultBootstrapRegion()
	if err != nil {
		return err
	}
	admission, err := validateBootstrapComposition(ctx, lookup, region.Code)
	if err != nil {
		return err
	}
	defer admission.Close()
	request := admission.provision
	if err := runBootstrapOCI(ctx, lookup, request, output); err != nil {
		return err
	}
	return formBootstrapControlGroup(ctx, lookup, region, admission)
}

func validateBootstrapComposition(ctx context.Context, lookup envLookup, region string) (*bootstrapControlAdmission, error) {
	path, present := lookup(addRegionControlJournalEnv)
	if !present || strings.TrimSpace(path) == "" {
		return nil, bootstrapMissingStage("control", errors.New("durable control journal is required"))
	}
	factory := bootstrapControlMachineFactory
	if factory == nil || factory.Validate == nil || factory.Construct == nil {
		return nil, bootstrapMissingStage("control", errors.New("authoritative control composition is unavailable"))
	}
	admission, err := factory.Validate(ctx, lookup, region)
	if err != nil {
		return nil, bootstrapMissingStage("control", err)
	}
	if admission == nil {
		return nil, bootstrapMissingStage("control", errors.New("validated control admission is unavailable"))
	}
	return admission, nil
}

// formBootstrapControlGroup executes the fenced bootstrap-gru-r1 transition
// — start the temporary pre-customer R1, then fence it — through the durable
// control journal. The journal decides the resume mode: an in-progress
// transition finishes its remaining idempotent actions, and a control plane
// that already reached the temporary R1 (or a later topology) makes the
// re-run a no-op instead of re-forming or regressing the group.
func formBootstrapControlGroup(ctx context.Context, lookup envLookup, region estate.Region, admission *bootstrapControlAdmission) error {
	value, present := lookup(addRegionControlJournalEnv)
	path := strings.TrimSpace(value)
	if !present || path == "" {
		return bootstrapMissingStage("control", errors.New("durable control journal is required"))
	}
	machine, err := bootstrapControlMachineFactory.Construct(ctx, admission, path)
	if err != nil {
		return fmt.Errorf("bootstrap control: %w", err)
	}
	if machine == nil {
		return errors.New("bootstrap control: control machine is unavailable")
	}
	defer closeBootstrapControlMachine(machine)
	prior, err := machine.Journal.Load(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap control: %w", err)
	}
	if prior.State.AlreadyBootstrapped() {
		return nil
	}
	request := bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationBootstrap,
		Region:      region.Code,
		MemberHosts: int(region.Members.Count),
	}
	if _, err := machine.Execute(ctx, prior.State, request); err != nil {
		return fmt.Errorf("bootstrap control %s: %w", region.Code, err)
	}
	return nil
}
