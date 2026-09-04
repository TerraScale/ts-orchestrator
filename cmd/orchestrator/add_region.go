// Command add-region is the I-5 single-command region bring-up: one call
// takes an empty OCI region to serving members. It reuses the declared
// estate types for what must exist and the provider/reconciler seams for how
// it gets there; it never reimplements a reconciler.
//
// With --dry-run it renders the runbook (stages, members, co-hosted
// control, object storage with lifecycle rules, Litestream targets, routes,
// probes, and the region-scoped reconcile actions) and changes nothing.
// Without --dry-run it validates the same estate slice, admits the region,
// and runs every stage in order. Missing composition is a refusal before the
// first mutation, rather than a false "serving" result.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
	runtimeprobe "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// addRegionLitestreamPurpose is the estate bucket purpose carrying
// Litestream segments. The D-29 tiering (24 h to Infrequent Access, 7 days
// to Archive) rides that bucket's lifecycle rules.
const addRegionLitestreamPurpose = "database-backup"

// addRegionStages is the converge order one add-region run follows. The OCI
// provider seam internally converges network, vault, buckets, hosts and
// volumes; certificates must precede edge publication, and probes are the
// final serving gate. The order is part of the runbook contract.
var addRegionStages = []string{"network", "vault", "buckets", "hosts", "volumes", "certificates", "edge", "probes"}

const (
	addRegionStageRetryBudget = 8
	addRegionStageRetryDelay  = time.Second
)

var addRegionCodePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

// runAddRegionBootstrap executes the OCI stages for one region. It is a
// variable so dry-run-adjacent tests can stub the provider boundary; the
// reconcilers themselves are never replaced here.
var runAddRegionBootstrap = provider.RunOCIBootstrapFromEnvironment

// addRegionStageFunc is the narrow composition seam for stages that are not
// part of the OCI bootstrap aggregate. Production composition is expected to
// provide these with the existing certificate reconciler, Cloudflare
// reconciler, and member health/probe implementations. Keeping the seam in
// this command package lets tests prove ordering without provider calls.
type addRegionStageFunc func(context.Context, envLookup, estate.Spec, estate.Region, io.Writer) error

var (
	runAddRegionCertificates addRegionStageFunc = addRegionCertificatesFromEnvironment
	runAddRegionEdge         addRegionStageFunc = addRegionEdgeFromEnvironment
	runAddRegionProbes       addRegionStageFunc = addRegionProbesFromHost
	// Control topology is provider-neutral and is intentionally an optional
	// composition seam. A deployment that has not yet supplied its control
	// provider still gets the same fail-closed OCI/cert/edge/probe checks; a
	// supplied implementation executes the fenced R1/candidate/R3 transition
	// inside the durable OCI stage.
	runAddRegionControl     addRegionStageFunc = addRegionControlFromEnvironment
	waitAddRegionRetry                         = waitAddRegionRetryContext
	newAddRegionCertificate                    = newAddRegionCertificateReconciler
	newAddRegionCloudflare                     = newAddRegionCloudflareController
)

// ErrAddRegionMissingStage classifies a composition refusal for callers that
// prefer errors.Is; AddRegionMissingStageError carries the exact stage.
var ErrAddRegionMissingStage = errors.New("add-region required stage is missing")

// AddRegionMissingStageError is returned when command composition does not
// provide a required stage. It is deliberately typed so callers can report
// an actionable wiring failure without inspecting arbitrary text.
type AddRegionMissingStageError struct {
	Stage  string
	Detail string
}

func (e *AddRegionMissingStageError) Error() string {
	if e == nil || e.Stage == "" {
		return "add-region required stage is missing"
	}
	if e.Detail != "" {
		return "add-region required stage is missing: " + e.Stage + " (" + e.Detail + ")"
	}
	return "add-region required stage is missing: " + e.Stage
}

func (e *AddRegionMissingStageError) Is(target error) bool {
	return target == ErrAddRegionMissingStage
}

// AddRegionRetryableError marks an asynchronous provider state. The command
// re-observes by invoking the same stage, with a bounded wait between tries.
// State is safe provider status (for example "accepted" or "in-progress").
type AddRegionRetryableError struct {
	Stage string
	State string
	Err   error
}

func (e *AddRegionRetryableError) Error() string {
	if e == nil {
		return "add-region stage is retryable"
	}
	if e.Stage == "" {
		return "add-region stage is retryable (" + e.State + ")"
	}
	return "add-region " + e.Stage + " is not ready (" + e.State + ")"
}

func (e *AddRegionRetryableError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func waitAddRegionRetryContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func addRegionMissingStage(stage string, err error) error {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	return &AddRegionMissingStageError{Stage: stage, Detail: detail}
}

const (
	addRegionEstateFileEnvironment = "TS_ORCH_OCI_ESTATE_FILE"
	addRegionKeyIDEnvironment      = "TS_ORCH_OCI_KEY_ID"
	addRegionKeyFileEnvironment    = "TS_ORCH_OCI_PRIVATE_KEY_FILE"
	addRegionAuthorityEnvironment  = "TS_ORCH_OCI_CERTIFICATE_AUTHORITY_ID"
	addRegionCFTokenEnvironment    = "CLOUDFLARE_API_TOKEN"
	addRegionCFZoneEnvironment     = "TS_ORCH_CLOUDFLARE_ZONE_ID"
	addRegionCFAccountEnvironment  = "TS_ORCH_CLOUDFLARE_ACCOUNT_ID"
	addRegionCFMembersEnvironment  = "TS_ORCH_CLOUDFLARE_MEMBERS_JSON"
	addRegionCFEgressEnvironment   = "TS_ORCH_CLOUDFLARE_TAILSCALE_EGRESS_JSON"
)

// addRegionCertificatesFromEnvironment composes the existing OCI
// certificate gateway and reconciler. Certificate issuance is asynchronous:
// an applied create/renew is deliberately reported as retryable until a
// fresh observation proves ACTIVE and the declared SAN set.
func addRegionCertificatesFromEnvironment(ctx context.Context, lookup envLookup, spec estate.Spec, region estate.Region, _ io.Writer) error {
	reconciler, err := newAddRegionCertificate(spec, region, lookup)
	if err != nil {
		return addRegionMissingStage("certificates", err)
	}
	observed, err := reconciler.Observe(ctx, region)
	if err != nil {
		return err
	}
	plan, err := reconciler.Reconcile(ctx, region, observed)
	if err != nil {
		return err
	}
	if !plan.Empty() {
		if err := reconciler.Apply(ctx, region, observed, plan); err != nil {
			return err
		}
		return &AddRegionRetryableError{Stage: "certificates", State: "accepted"}
	}
	for _, declared := range region.Certificates {
		display := provider.CertDisplayName(region.Code, declared.Name)
		for _, cert := range observed.Certs {
			if cert.DisplayName == display && cert.LifecycleState != "ACTIVE" {
				return &AddRegionRetryableError{Stage: "certificates", State: strings.ToLower(cert.LifecycleState)}
			}
		}
	}
	return nil
}

// addRegionEdgeFromEnvironment uses the production Cloudflare constructor
// and zone reconciler. The edge pass is intentionally after certificates so
// pinned hostnames are never published without their member TLS material.
func addRegionEdgeFromEnvironment(ctx context.Context, lookup envLookup, spec estate.Spec, _ estate.Region, output io.Writer) error {
	controller, err := newAddRegionCloudflare(spec, lookup)
	if err != nil {
		return addRegionMissingStage("edge", err)
	}
	plan, err := cloudflare.ReconcileZone(ctx, controller.Client, controller.Zone)
	if err != nil {
		return err
	}
	if output != nil {
		_, _ = fmt.Fprint(output, plan)
	}
	return cloudflare.Apply(ctx, plan)
}

func newAddRegionCertificateReconciler(spec estate.Spec, region estate.Region, lookup envLookup) (*provider.CertReconciler, error) {
	if lookup == nil {
		return nil, errors.New("environment lookup is nil")
	}
	estateFile, err := addRegionRequiredEnv(lookup, addRegionEstateFileEnvironment)
	if err != nil {
		return nil, err
	}
	keyID, err := addRegionRequiredEnv(lookup, addRegionKeyIDEnvironment)
	if err != nil {
		return nil, err
	}
	keyFile, err := addRegionRequiredEnv(lookup, addRegionKeyFileEnvironment)
	if err != nil {
		return nil, err
	}
	authorityID, err := addRegionRequiredEnv(lookup, addRegionAuthorityEnvironment)
	if err != nil {
		return nil, err
	}
	declared, err := provider.LoadOCIEstateSpec(estateFile)
	if err != nil {
		return nil, err
	}
	if declared.Region != region.OCIName {
		return nil, fmt.Errorf("OCI estate region does not match %s", region.Code)
	}
	reader, err := provider.NewOCIEstateHTTPReader(declared, keyID, keyFile)
	if err != nil {
		return nil, err
	}
	core := reader.Transports[provider.OCIServiceCore]
	if core == nil {
		return nil, errors.New("OCI core transport is unavailable")
	}
	config, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceCertificates, declared.Region, "https://certificates."+declared.Region+".oci.oraclecloud.com")
	if err != nil {
		return nil, err
	}
	certs, err := provider.NewOCIHTTPTransport(config, core.Client, core.Signer)
	if err != nil {
		return nil, err
	}
	gateway, err := provider.NewOCICertificatesGateway(certs, declared.ControlCompartmentID, authorityID)
	if err != nil {
		return nil, err
	}
	return &provider.CertReconciler{Gateway: gateway}, nil
}

type addRegionCloudflareController struct {
	Client *cloudflare.Client
	Zone   *cloudflare.Zone
}

func newAddRegionCloudflareController(spec estate.Spec, lookup envLookup) (*addRegionCloudflareController, error) {
	if lookup == nil {
		return nil, errors.New("environment lookup is nil")
	}
	token, err := addRegionRequiredEnv(lookup, addRegionCFTokenEnvironment)
	if err != nil {
		return nil, err
	}
	zoneID, err := addRegionRequiredEnv(lookup, addRegionCFZoneEnvironment)
	if err != nil {
		return nil, err
	}
	accountID, err := addRegionRequiredEnv(lookup, addRegionCFAccountEnvironment)
	if err != nil {
		return nil, err
	}
	membersRaw, err := addRegionRequiredEnv(lookup, addRegionCFMembersEnvironment)
	if err != nil {
		return nil, err
	}
	egressRaw, err := addRegionRequiredEnv(lookup, addRegionCFEgressEnvironment)
	if err != nil {
		return nil, err
	}
	var members cloudflare.Members
	if err := json.Unmarshal([]byte(membersRaw), &members); err != nil || len(members) == 0 {
		return nil, errors.New("Cloudflare member address configuration is invalid")
	}
	var egress []string
	if err := json.Unmarshal([]byte(egressRaw), &egress); err != nil || len(egress) == 0 {
		return nil, errors.New("Cloudflare Tailscale egress configuration is invalid")
	}
	zone, err := cloudflare.Production(members, egress)
	if err != nil {
		return nil, err
	}
	if zone.ZoneName != spec.Cloudflare.Zone {
		return nil, errors.New("Cloudflare zone does not match the declared estate")
	}
	return &addRegionCloudflareController{Client: cloudflare.NewClient(token, zoneID, accountID), Zone: zone}, nil
}

func addRegionRequiredEnv(lookup envLookup, name string) (string, error) {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("required configuration %s is missing", name)
	}
	return value, nil
}

// addRegionProbesFromHost is the production host/runtime probe. A serving
// result requires Linux, systemd PID 1, cgroup v2, and both native systemd
// tools; any missing bit fails closed.
func addRegionProbesFromHost(ctx context.Context, _ envLookup, _ estate.Spec, _ estate.Region, _ io.Writer) error {
	if ctx == nil {
		return errors.New("add-region probes: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	evidence := (runtimeprobe.LinuxSystemdHostProbe{}).Probe()
	if !evidence.IsAdmitted() {
		return errors.New("add-region probes: host failed systemd admission")
	}
	return nil
}

// addRegionRunbook is the --dry-run output: the complete I-5 runbook for
// one region. Buckets, routes, and certificates reuse the estate types
// verbatim so the runbook cannot drift from the declaration.
type addRegionRunbook struct {
	Command           string             `json:"command"`
	Region            string             `json:"region"`
	OCIRegion         string             `json:"ociRegion"`
	EstateVersion     uint32             `json:"estateVersion"`
	Stages            []string           `json:"stages"`
	Members           addRegionMembers   `json:"members"`
	Control           addRegionControl   `json:"control"`
	ObjectStorage     []estate.Bucket    `json:"objectStorage"`
	LitestreamTargets []estate.Bucket    `json:"litestreamTargets"`
	Routes            addRegionRoutes    `json:"routes"`
	Probes            addRegionProbes    `json:"probes"`
	Admission         addRegionAdmission `json:"admission"`
	Actions           []reconcile.Action `json:"actions"`
}

type addRegionMembers struct {
	Count         uint16 `json:"count"`
	PrimaryShape  string `json:"primaryShape"`
	FallbackShape string `json:"fallbackShape"`
	OCPUs         uint16 `json:"ocpus"`
	MemoryGiB     uint16 `json:"memoryGiB"`
	BootVolumeGiB uint16 `json:"bootVolumeGiB"`
	DataVolumeGiB uint32 `json:"dataVolumeGiB"`
}

type addRegionControl struct {
	Mode     string `json:"mode"`
	Replicas uint16 `json:"replicas"`
	// Placement makes the D-65 topology explicit in the operator-facing
	// runbook: launch control replicas share member hosts; they are not
	// dedicated control instances.
	Placement        string   `json:"placement"`
	Topology         string   `json:"topology"`
	CandidateRegions []string `json:"candidateRegions,omitempty"`
	Promotion        string   `json:"promotion,omitempty"`
	Authority        string   `json:"authority"`
}

type addRegionRoutes struct {
	DNSRecords   []estate.DNSRecord   `json:"dnsRecords"`
	WorkerRoutes []estate.WorkerRoute `json:"workerRoutes"`
}

type addRegionProbeKV struct {
	Map   string `json:"map"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type addRegionProbes struct {
	KV           []addRegionProbeKV   `json:"kv"`
	Certificates []estate.Certificate `json:"certificates"`
	MemberFloor  int                  `json:"memberFloor"`
}

type addRegionAdmission struct {
	ResidencyRegion    string `json:"residencyRegion"`
	MemberHosts        int    `json:"memberHosts"`
	MinimumMemberHosts int    `json:"minimumMemberHosts"`
}

// runAddRegion provisions one declared region from an empty OCI region to
// serving members. Dry runs render the runbook; real runs delegate to the
// OCI bootstrap stages after the same estate validation.
func runAddRegion(ctx context.Context, args []string, lookup envLookup, output io.Writer) error {
	if ctx == nil {
		return errors.New("add-region: context is nil")
	}
	code, dryRun, err := parseAddRegionArgs(args)
	if err != nil {
		return err
	}
	spec, region, err := lookupAddRegionRegion(code)
	if err != nil {
		return err
	}
	if err := checkAddRegionFloor(region); err != nil {
		return err
	}
	if err := checkAddRegionAdmission(spec, region); err != nil {
		return err
	}
	if dryRun {
		if output == nil {
			return errors.New("add-region: runbook output is nil")
		}
		return renderAddRegionRunbook(spec, region, output)
	}
	if lookup == nil {
		return errors.New("add-region: environment lookup is nil")
	}
	// Refuse before OCI is touched. Running the provider aggregate and only
	// then discovering that certificates, edge, or probes are unwired would
	// leave a region partially built while claiming the command failed safely.
	if err := validateAddRegionStages(lookup, spec, region); err != nil {
		return err
	}
	stages := []struct {
		name string
		run  addRegionStageFunc
	}{
		{"oci", func(ctx context.Context, _ envLookup, _ estate.Spec, region estate.Region, output io.Writer) error {
			if err := runAddRegionBootstrap(ctx, lookup, provider.BootstrapRequest{Region: region}, output); err != nil {
				return err
			}
			if runAddRegionControl != nil {
				if err := runAddRegionControl(ctx, lookup, spec, region, output); err != nil {
					return err
				}
			}
			return nil
		}},
		{"certificates", runAddRegionCertificates},
		{"edge", runAddRegionEdge},
		{"probes", runAddRegionProbes},
	}
	for _, stage := range stages {
		if err := runAddRegionStage(ctx, stage.name, stage.run, lookup, spec, region, output); err != nil {
			return err
		}
	}
	return nil
}

func checkAddRegionAdmission(spec estate.Spec, region estate.Region) error {
	declared := false
	for _, candidate := range spec.Regions {
		if candidate.Code == region.Code && candidate.OCIName == region.OCIName {
			declared = true
			break
		}
	}
	if !declared {
		return fmt.Errorf("add-region %s residency admission failed: region is not declared in the estate", region.Code)
	}
	// CheckPlacement is the provider's residency admission seam. A region is
	// admitted only as itself, with the declared host count; this keeps a
	// bring-up from silently widening a placement scope or admitting a one-host
	// failure domain.
	lock, err := provider.NewPlacementLock([]string{region.Code})
	if err != nil {
		return fmt.Errorf("add-region %s residency admission failed: %w", region.Code, err)
	}
	if err := provider.CheckPlacement(lock, []string{region.Code}, map[string]int{region.Code: int(region.Members.Count)}); err != nil {
		return fmt.Errorf("add-region %s residency admission failed: %w", region.Code, err)
	}
	if spec.HomeRegion == region.Code && region.Members.ControlReplicas != 1 {
		return fmt.Errorf("add-region %s refused: home region must co-host one control replica", region.Code)
	}
	return nil
}

func validateAddRegionStages(lookup envLookup, spec estate.Spec, region estate.Region) error {
	if runAddRegionBootstrap == nil {
		return &AddRegionMissingStageError{Stage: "oci"}
	}
	for _, stage := range []struct {
		name string
		run  addRegionStageFunc
	}{
		{"certificates", runAddRegionCertificates},
		{"edge", runAddRegionEdge},
		{"probes", runAddRegionProbes},
	} {
		if stage.run == nil {
			return &AddRegionMissingStageError{Stage: stage.name}
		}
	}
	// Constructors perform only local validation and transport composition;
	// they do not issue requests. Running them here ensures missing production
	// configuration is reported before OCI provisioning begins. Tests may
	// inject a stage function, in which case that injected seam owns its setup.
	if sameAddRegionStage(runAddRegionCertificates, addRegionCertificatesFromEnvironment) {
		if _, err := newAddRegionCertificate(spec, region, lookup); err != nil {
			return addRegionMissingStage("certificates", err)
		}
	}
	if sameAddRegionStage(runAddRegionEdge, addRegionEdgeFromEnvironment) {
		if _, err := newAddRegionCloudflare(spec, lookup); err != nil {
			return addRegionMissingStage("edge", err)
		}
	}
	return nil
}

func sameAddRegionStage(left, right addRegionStageFunc) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return reflect.ValueOf(left).Pointer() == reflect.ValueOf(right).Pointer()
}

func runAddRegionStage(ctx context.Context, name string, stage addRegionStageFunc, lookup envLookup, spec estate.Spec, region estate.Region, output io.Writer) error {
	if ctx == nil {
		return errors.New("add-region: context is nil")
	}
	if stage == nil {
		return &AddRegionMissingStageError{Stage: name}
	}
	if lookup == nil {
		return errors.New("add-region: environment lookup is nil")
	}
	for attempt := 1; attempt <= addRegionStageRetryBudget; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := stage(ctx, lookup, spec, region, output)
		if err == nil {
			return nil
		}
		var retry *AddRegionRetryableError
		if errors.As(err, &retry) {
			if retry != nil && retry.Stage != "" && retry.Stage != name {
				return fmt.Errorf("add-region %s received retry state for %s: %w", name, retry.Stage, err)
			}
		} else {
			// The OCI work-request adapter uses this error when the outcome is
			// still unknown. Re-enter the stage to observe the same intent.
			var unknown *provider.ProviderOutcomeUnknownError
			if !errors.As(err, &unknown) {
				return fmt.Errorf("add-region %s failed: %w", name, err)
			}
		}
		if attempt == addRegionStageRetryBudget {
			return fmt.Errorf("add-region %s retry budget exhausted: %w", name, err)
		}
		if waitAddRegionRetry == nil {
			return errors.New("add-region retry wait seam is missing")
		}
		if err := waitAddRegionRetry(ctx, addRegionStageRetryDelay); err != nil {
			return fmt.Errorf("add-region %s wait failed: %w", name, err)
		}
	}
	return fmt.Errorf("add-region %s retry budget exhausted", name)
}

// parseAddRegionArgs accepts `add-region <code>` and
// `add-region <code> --dry-run`. The code is canonicalized to the estate's
// lowercase form; anything flag-shaped is rejected here so credential-like
// arguments are never echoed.
func parseAddRegionArgs(args []string) (string, bool, error) {
	if len(args) < 2 || args[0] != "add-region" {
		return "", false, errors.New("add-region: region code is required")
	}
	if len(args) > 3 {
		return "", false, errors.New("add-region: command accepts only a region code and --dry-run")
	}
	code := strings.ToLower(strings.TrimSpace(args[1]))
	if !validAddRegionCode(code) {
		return "", false, errors.New("add-region: region code is invalid")
	}
	if len(args) == 2 {
		return code, false, nil
	}
	if args[2] != dryRunFlag {
		return "", false, errors.New("add-region: command accepts only a region code and --dry-run")
	}
	return code, true, nil
}

func validAddRegionCode(code string) bool {
	return code != "" && len(code) <= 63 && addRegionCodePattern.MatchString(code)
}

// lookupAddRegionRegion resolves a code against the declared estate. A code
// with no estate entry is refused: adding a region is one estate entry plus
// a release, never an invented declaration at the command line.
func lookupAddRegionRegion(code string) (estate.Spec, estate.Region, error) {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if !validAddRegionCode(normalized) {
		return estate.Spec{}, estate.Region{}, errors.New("add-region: region code is invalid")
	}
	spec := estate.Default()
	if err := spec.Validate(); err != nil {
		return estate.Spec{}, estate.Region{}, err
	}
	for _, region := range spec.Regions {
		if region.Code == normalized {
			return spec, region, nil
		}
	}
	return estate.Spec{}, estate.Region{}, errors.New("add-region: unknown region " + normalized + ": declare it in the estate first")
}

// checkAddRegionFloor enforces the D-65 estate shape (two member hosts with
// a co-hosted control replica) that placement also requires: a region below
// the member floor is refused, never partially built.
func checkAddRegionFloor(region estate.Region) error {
	if region.Members.Count < provider.PlacementMinimumMemberHosts {
		return fmt.Errorf("add-region %s refused: region has %d member hosts, placement requires %d", region.Code, region.Members.Count, provider.PlacementMinimumMemberHosts)
	}
	// GRU/SFO/FRA are the permanent global control group at launch. A later
	// region is deliberately remote-managed with no co-hosted replica until a
	// separate regional declaration qualifies at least three hosts.
	if launchControlRegion(region.Code) && region.Members.ControlReplicas != 1 {
		return fmt.Errorf("add-region %s refused: region must co-host one launch control replica", region.Code)
	}
	if !launchControlRegion(region.Code) && region.Members.ControlReplicas > 0 && region.Members.Count < 3 {
		return fmt.Errorf("add-region %s refused: regional R3 requires at least three eligible hosts", region.Code)
	}
	return nil
}

func launchControlRegion(code string) bool {
	return code == "gru" || code == "sfo" || code == "fra"
}

func addRegionControlFor(region estate.Region) addRegionControl {
	control := addRegionControl{Replicas: region.Members.ControlReplicas, Authority: "global-r3", Placement: "remote-managed", Topology: "remote-managed"}
	switch {
	case region.Code == "gru":
		control.Mode = "temporary-r1"
		control.Authority = "bootstrap"
		control.Placement = "co-hosted-on-member-hosts"
		control.Topology = "co-hosted"
	case region.Code == "sfo" || region.Code == "fra":
		control.Mode = "candidate-r1"
		control.CandidateRegions = []string{"sfo", "fra"}
		control.Promotion = "fenced-atomic-global-r3"
		control.Placement = "co-hosted-on-member-hosts"
		control.Topology = "co-hosted"
	case region.Members.ControlReplicas == 0:
		control.Mode = "remote-managed"
		control.Replicas = 0
	default:
		control.Mode = "regional-r3"
		control.Authority = "regional"
	}
	return control
}

// addRegionControlFromEnvironment is the default no-credential control
// boundary. Real deployments replace this seam with a ControlStateMachine
// adapter; the command never constructs provider clients or handles secrets.
func addRegionControlFromEnvironment(context.Context, envLookup, estate.Spec, estate.Region, io.Writer) error {
	return nil
}

// renderAddRegionRunbook writes the deterministic I-5 runbook for one
// region: stages, serving members, co-hosted control, object storage with
// lifecycle rules, Litestream targets, routes, probes, and the
// region-scoped reconcile actions an empty OCI region needs. It resolves no
// credentials and makes no provider calls.
func renderAddRegionRunbook(spec estate.Spec, region estate.Region, output io.Writer) error {
	if output == nil {
		return errors.New("add-region: runbook output is nil")
	}
	book, err := buildAddRegionRunbook(spec, region)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(book)
}

func buildAddRegionRunbook(spec estate.Spec, region estate.Region) (addRegionRunbook, error) {
	if err := spec.Validate(); err != nil {
		return addRegionRunbook{}, err
	}
	if err := checkAddRegionFloor(region); err != nil {
		return addRegionRunbook{}, err
	}
	if err := checkAddRegionAdmission(spec, region); err != nil {
		return addRegionRunbook{}, err
	}
	// Prove the declared buckets render to provider lifecycle specs before
	// the runbook claims them: object storage with lifecycle rules is a
	// precondition, not an aspiration.
	for _, bucket := range region.Buckets {
		if _, err := provider.LifecycleRuleSpecs(bucket); err != nil {
			return addRegionRunbook{}, err
		}
	}
	declared, err := reconcile.Declared(spec)
	if err != nil {
		return addRegionRunbook{}, err
	}
	plan, err := reconcile.Diff(declared, reconcile.State{})
	if err != nil {
		return addRegionRunbook{}, err
	}
	var actions []reconcile.Action
	for _, action := range plan.Actions {
		if action.Ref.Region == region.Code {
			actions = append(actions, action)
		}
	}
	if len(actions) == 0 {
		return addRegionRunbook{}, errors.New("add-region: declared estate has no resources for region " + region.Code)
	}
	var litestream []estate.Bucket
	for _, bucket := range region.Buckets {
		if bucket.Purpose == addRegionLitestreamPurpose {
			litestream = append(litestream, bucket)
		}
	}
	book := addRegionRunbook{
		Command:       "add-region",
		Region:        region.Code,
		OCIRegion:     region.OCIName,
		EstateVersion: estate.SchemaVersion,
		Stages:        append([]string(nil), addRegionStages...),
		Members: addRegionMembers{
			Count:         region.Members.Count,
			PrimaryShape:  region.Members.PrimaryShape,
			FallbackShape: region.Members.FallbackShape,
			OCPUs:         region.Members.OCPUs,
			MemoryGiB:     region.Members.MemoryGiB,
			BootVolumeGiB: region.Members.BootVolumeGiB,
			DataVolumeGiB: region.Members.DataVolumeGiB,
		},
		Control:           addRegionControlFor(region),
		ObjectStorage:     append([]estate.Bucket(nil), region.Buckets...),
		LitestreamTargets: litestream,
		Routes:            addRegionRoutesFor(spec, region.Code),
		Probes:            addRegionProbesFor(spec, region),
		Admission: addRegionAdmission{
			ResidencyRegion:    region.Code,
			MemberHosts:        int(region.Members.Count),
			MinimumMemberHosts: provider.PlacementMinimumMemberHosts,
		},
		Actions: actions,
	}
	return book, nil
}

// addRegionRoutesFor collects the edge state that serves one region: the
// region's pinned API record plus the shared first-contact and reactive
// entry points, and every declared Worker route.
func addRegionRoutesFor(spec estate.Spec, code string) addRegionRoutes {
	zone := spec.Cloudflare.Zone
	var dns []estate.DNSRecord
	for _, record := range spec.Cloudflare.DNSRecords {
		if record.Name == "api."+zone || record.Name == "sync.api."+zone || record.Name == code+".api."+zone {
			dns = append(dns, record)
		}
	}
	return addRegionRoutes{
		DNSRecords:   dns,
		WorkerRoutes: append([]estate.WorkerRoute(nil), spec.Cloudflare.WorkerRoutes...),
	}
}

// addRegionProbesFor collects what proves one region serves: its KV health
// and placement entries, its member certificates, and the placement member
// floor the region must sustain.
func addRegionProbesFor(spec estate.Spec, region estate.Region) addRegionProbes {
	var kv []addRegionProbeKV
	for _, mapping := range spec.Cloudflare.KVMaps {
		for _, entry := range mapping.Entries {
			if entry.Key == "regions/"+region.Code || entry.Key == "placement/control" {
				kv = append(kv, addRegionProbeKV{Map: mapping.Name, Key: entry.Key, Value: entry.Value})
			}
		}
	}
	return addRegionProbes{
		KV:           kv,
		Certificates: append([]estate.Certificate(nil), region.Certificates...),
		MemberFloor:  provider.PlacementMinimumMemberHosts,
	}
}
