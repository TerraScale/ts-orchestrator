package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// OCI bootstrap (D-67): create the compartment, then drive the reconcilers
// in dependency order — network, vault, buckets, member hosts, data volumes
// — until every stage converges. This is the executor half; the pure
// greenfield planner lives in the bootstrap package and composes these
// gateways. The real run needs the owner's OCI API key (O-4/I-7); without
// it, bootstrap fails loudly before any request is signed.

const (
	bootstrapDefaultMaxPasses    = 32
	bootstrapDefaultStageTimeout = 30 * time.Minute
	bootstrapDefaultPollBase     = time.Second
	bootstrapDefaultPollMaximum  = 30 * time.Second
	bootstrapMaximumPasses       = 1024
)

// BootstrapConvergenceConfig controls how long an OCI stage may wait for
// asynchronous work requests and how often it re-observes them. Zero fields
// select production defaults; non-zero values are useful for deterministic
// tests and controlled operators' runbooks.
type BootstrapConvergenceConfig struct {
	Deadline    time.Duration
	MaxPasses   int
	PollInitial time.Duration
	PollMaximum time.Duration
}

func (c BootstrapConvergenceConfig) normalized() BootstrapConvergenceConfig {
	if c.Deadline == 0 {
		c.Deadline = bootstrapDefaultStageTimeout
	}
	if c.MaxPasses == 0 {
		c.MaxPasses = bootstrapDefaultMaxPasses
	}
	if c.PollInitial == 0 {
		c.PollInitial = bootstrapDefaultPollBase
	}
	if c.PollMaximum == 0 {
		c.PollMaximum = bootstrapDefaultPollMaximum
	}
	return c
}

func (c BootstrapConvergenceConfig) validate() error {
	if c.Deadline < 0 || c.MaxPasses < 0 || c.MaxPasses > bootstrapMaximumPasses || c.PollInitial < 0 || c.PollMaximum < 0 || (c.PollInitial > 0 && c.PollMaximum > 0 && c.PollMaximum < c.PollInitial) {
		return &errs.Argument{Message: "bootstrap convergence settings are invalid"}
	}
	return nil
}

// Environment variables holding the owner's OCI bootstrap credentials and
// the ts-node release the first hosts install. The private key reuses the
// orchestrator-wide variable.
const (
	OCITenancyEnvironment     = "TS_ORCH_OCI_TENANCY"
	OCIUserEnvironment        = "TS_ORCH_OCI_USER"
	OCIFingerprintEnvironment = "TS_ORCH_OCI_FINGERPRINT"
	OCIRegionEnvironment      = "TS_ORCH_OCI_REGION"
	OCIPrivateKeyEnvironment  = "TS_ORCH_OCI_PRIVATE_KEY_FILE"
	OCIImageEnvironment       = "TS_ORCH_OCI_IMAGE_ID"
	TSNodeVersionEnvironment  = "TS_ORCH_TS_NODE_VERSION"
	TSNodeSHA256Environment   = "TS_ORCH_TS_NODE_SHA256"
	TSNodeURLEnvironment      = "TS_ORCH_TS_NODE_URL"
)

// BootstrapCredentials is the owner's OCI API key scope. It never appears in
// logs: only its absence does, loudly.
type BootstrapCredentials struct {
	TenancyOCID    string
	UserOCID       string
	Fingerprint    string
	PrivateKeyPath string
	Region         string
}

// SigningKeyID is the OCI request-signing key id for a user API key. The
// signing scheme is the same one instance principals use, so the standard
// signer serves both.
func (c BootstrapCredentials) SigningKeyID() string {
	return c.TenancyOCID + "/" + c.UserOCID + "/" + c.Fingerprint
}

// BootstrapCredentialsFromEnv reads and validates every required credential.
// The error names all missing variables at once so one run surfaces the
// whole gap.
func BootstrapCredentialsFromEnv(lookup func(string) (string, bool)) (BootstrapCredentials, error) {
	if lookup == nil {
		return BootstrapCredentials{}, &errs.Argument{Param: "lookup", Message: "environment lookup is required"}
	}
	values := map[string]string{}
	var missing []string
	for _, name := range []string{OCITenancyEnvironment, OCIUserEnvironment, OCIFingerprintEnvironment, OCIPrivateKeyEnvironment, OCIRegionEnvironment} {
		value, present := lookup(name)
		if !present || strings.TrimSpace(value) == "" {
			missing = append(missing, name)
			continue
		}
		values[name] = strings.TrimSpace(value)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return BootstrapCredentials{}, &errs.Argument{Message: "bootstrap requires OCI credentials: set " + strings.Join(missing, ", ")}
	}
	credentials := BootstrapCredentials{
		TenancyOCID:    values[OCITenancyEnvironment],
		UserOCID:       values[OCIUserEnvironment],
		Fingerprint:    values[OCIFingerprintEnvironment],
		PrivateKeyPath: values[OCIPrivateKeyEnvironment],
		Region:         values[OCIRegionEnvironment],
	}
	if !isOCID(credentials.TenancyOCID, "tenancy") || !isOCID(credentials.UserOCID, "user") ||
		!validOCIFingerprint(credentials.Fingerprint) {
		return BootstrapCredentials{}, &errs.Argument{Message: "bootstrap OCI credentials are malformed"}
	}
	return credentials, nil
}

// validOCIFingerprint accepts both the colon-separated form emitted by the
// OCI console (16 hexadecimal byte pairs) and the legacy unseparated form
// accepted by older bootstrap environments. OCI fingerprints are hexadecimal
// identifiers, not fixed-width lowercase tokens.
func validOCIFingerprint(value string) bool {
	if len(value) == 32 {
		for _, char := range value {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
		return true
	}
	parts := strings.Split(value, ":")
	if len(parts) != 16 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		for _, char := range part {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}
	return true
}

// DefaultBootstrapRegion returns the declared home Region from the default
// estate (D-65: GRU with two Ampere members). Bootstrap runs against one
// Region; add-region drives the rest through the reconcile loop.
func DefaultBootstrapRegion() (estate.Region, error) {
	spec := estate.Default()
	for _, region := range spec.Regions {
		if region.Code == spec.HomeRegion {
			return region, nil
		}
	}
	return estate.Region{}, &InvalidDataError{Message: "default estate has no home region"}
}

// BootstrapRequest is the non-secret bootstrap input.
type BootstrapRequest struct {
	Region          estate.Region
	CompartmentName string
	ImageID         string
	TSNodeVersion   string
	TSNodeSHA256    string
	TSNodeURL       string
	Convergence     BootstrapConvergenceConfig
}

func (r BootstrapRequest) validate() error {
	if r.Region.Members.Count < PlacementMinimumMemberHosts || r.Region.Members.PrimaryShape == "" || r.Region.Members.PrimaryShape == r.Region.Members.FallbackShape {
		return &errs.Argument{Message: "bootstrap region must declare two member hosts on distinct shapes"}
	}
	if !isOCID(r.ImageID, "image") {
		return &errs.Argument{Message: "bootstrap requires an Ubuntu arm64 image identity"}
	}
	if !validEstateName(r.CompartmentName) {
		return &errs.Argument{Message: "bootstrap compartment name is invalid"}
	}
	if _, err := TSNodeCloudInit(r.TSNodeVersion, r.TSNodeSHA256, r.TSNodeURL); err != nil {
		return err
	}
	if err := r.Convergence.validate(); err != nil {
		return err
	}
	return nil
}

// BootstrapGateways carries one real or fake gateway per reconciler. The
// compartment already exists: the environment runner creates it through the
// identity service before constructing these.
type BootstrapGateways struct {
	Network NetworkGateway
	Compute ComputeGateway
	Block   BlockStorageGateway
	Object  ObjectStorageGateway
	Vault   VaultGateway
}

func (g BootstrapGateways) validate() error {
	if g.Network == nil || g.Compute == nil || g.Block == nil || g.Object == nil || g.Vault == nil {
		return &errs.Argument{Message: "bootstrap requires every OCI gateway"}
	}
	return nil
}

// RunOCIBootstrap drives the reconcilers in dependency order until every
// stage converges: network → vault → buckets → member hosts → data volumes.
// Each pass is observe → plan → apply; a stage that cannot converge within
// the pass budget fails the whole run loudly instead of half-building.
func RunOCIBootstrap(ctx context.Context, request BootstrapRequest, gateways BootstrapGateways, progress io.Writer) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return classifyBootstrapOutcome(err)
	}
	if err := request.validate(); err != nil {
		return err
	}
	if err := gateways.validate(); err != nil {
		return err
	}
	cloudInit, err := TSNodeCloudInit(request.TSNodeVersion, request.TSNodeSHA256, request.TSNodeURL)
	if err != nil {
		return err
	}
	network := &NetworkReconciler{Gateway: gateways.Network}
	vault := &VaultReconciler{Vault: gateways.Vault}
	object := &ObjectStorageReconciler{Object: gateways.Object}
	compute := &ComputeReconciler{Compute: gateways.Compute, Network: gateways.Network}
	block := &BlockStorageReconciler{Block: gateways.Block, Compute: gateways.Compute}
	if err := convergeStage(ctx, "network", network, request.Region, progress, request.Convergence); err != nil {
		return err
	}
	if err := convergeStage(ctx, "vault", vault, request.Region, progress, request.Convergence); err != nil {
		return err
	}
	if err := convergeStage(ctx, "buckets", object, request.Region, progress, request.Convergence); err != nil {
		return err
	}
	if err := convergeStage(ctx, "hosts", compute, ComputeDeclared{Region: request.Region, ImageID: request.ImageID, CloudInitBase64: cloudInit}, progress, request.Convergence); err != nil {
		return err
	}
	return convergeStage(ctx, "volumes", block, request.Region, progress, request.Convergence)
}

// convergeStage replans one reconciler until its plan is empty. Async OCI
// resources (vaults, keys, instances) reach their terminal states between
// passes.
func convergeStage[D any, O any](ctx context.Context, stage string, reconciler OCIReconciler[D, O], declared D, progress io.Writer, settings ...BootstrapConvergenceConfig) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if reconciler == nil {
		return &InvalidOperationError{Message: "bootstrap reconciler is unavailable: " + stage}
	}
	config := BootstrapConvergenceConfig{}
	if len(settings) > 0 {
		config = settings[0]
	}
	if err := config.validate(); err != nil {
		return err
	}
	config = config.normalized()
	stageCtx, cancel := context.WithTimeout(ctx, config.Deadline)
	defer cancel()
	for pass := 1; pass <= config.MaxPasses; pass++ {
		if err := stageCtx.Err(); err != nil {
			return fmt.Errorf("bootstrap %s polling cancelled: %w", stage, classifyBootstrapOutcome(err))
		}
		observed, err := reconciler.Observe(stageCtx, declared)
		if err != nil {
			return fmt.Errorf("bootstrap %s observe failed: %w", stage, classifyBootstrapOutcome(err))
		}
		plan, err := reconciler.Reconcile(stageCtx, declared, observed)
		if err != nil {
			return fmt.Errorf("bootstrap %s reconcile failed: %w", stage, classifyBootstrapOutcome(err))
		}
		if plan.Empty() {
			if converger, ok := any(reconciler).(bootstrapConverger); ok {
				converged, convergenceErr := converger.bootstrapConverged(observed, declared)
				if convergenceErr != nil {
					return fmt.Errorf("bootstrap %s convergence check failed: %w", stage, classifyBootstrapOutcome(convergenceErr))
				}
				if !converged {
					if err := waitBootstrapPoll(stageCtx, pass, config); err != nil {
						return fmt.Errorf("bootstrap %s polling cancelled: %w", stage, classifyBootstrapOutcome(err))
					}
					continue
				}
			}
			return nil
		}
		for _, action := range plan.Actions {
			if progress != nil {
				if _, writeErr := fmt.Fprintf(progress, "bootstrap %s: %s\n", stage, action.Summary()); writeErr != nil {
					return fmt.Errorf("bootstrap %s progress failed: %w", stage, writeErr)
				}
			}
		}
		if err := reconciler.Apply(stageCtx, declared, observed, plan); err != nil {
			return fmt.Errorf("bootstrap %s apply failed: %w", stage, classifyBootstrapOutcome(err))
		}
		if pass < config.MaxPasses {
			if err := waitBootstrapPoll(stageCtx, pass, config); err != nil {
				return fmt.Errorf("bootstrap %s polling cancelled: %w", stage, classifyBootstrapOutcome(err))
			}
		}
	}
	if err := stageCtx.Err(); err != nil {
		return fmt.Errorf("bootstrap %s polling cancelled: %w", stage, classifyBootstrapOutcome(err))
	}
	return classifyBootstrapOutcome(&ProviderOutcomeUnknownError{Message: "bootstrap stage did not converge within its polling budget: " + stage})
}

// bootstrapConverger lets asynchronous resource reconcilers distinguish an
// empty action plan from a usable resource. A pending OCI operation must be
// observed again before the dependent stage is allowed to run.
type bootstrapConverger interface {
	bootstrapConverged(observed, declared any) (bool, error)
}

func waitBootstrapPoll(ctx context.Context, pass int, settings ...BootstrapConvergenceConfig) error {
	config := BootstrapConvergenceConfig{}
	if len(settings) > 0 {
		config = settings[0]
	}
	config = config.normalized()
	multiplier := time.Duration(1)
	for shift := 1; shift < pass && shift < 62; shift++ {
		multiplier *= 2
	}
	delay := config.PollInitial * multiplier
	if delay < 0 || delay/multiplier != config.PollInitial {
		delay = config.PollMaximum
	}
	if delay > config.PollMaximum {
		delay = config.PollMaximum
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// classifyBootstrapOutcome marks transport/deadline outcomes as unknown. A
// mutating OCI request may have been accepted before its response was lost;
// add-region must retry the same declared intent after re-observation instead
// of treating that state as a failed partial build.
func classifyBootstrapOutcome(err error) error {
	if err == nil {
		return nil
	}
	var unknown *ProviderOutcomeUnknownError
	if errors.As(err, &unknown) {
		return err
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &bootstrapOutcomeUnknownError{
		ProviderOutcomeUnknownError: &ProviderOutcomeUnknownError{Message: "OCI bootstrap operation outcome is unknown; retry the same declaration"},
		cause:                       err,
	}
}

type bootstrapOutcomeUnknownError struct {
	*ProviderOutcomeUnknownError
	cause error
}

func (e *bootstrapOutcomeUnknownError) Unwrap() error { return e.cause }

func (e *bootstrapOutcomeUnknownError) As(target any) bool {
	if destination, ok := target.(**ProviderOutcomeUnknownError); ok {
		*destination = e.ProviderOutcomeUnknownError
		return true
	}
	return errors.As(e.cause, target)
}

// IdentityGateway is the OCI identity seam bootstrap needs before anything
// else: the compartment every other resource lands in.
type IdentityGateway interface {
	EnsureCompartment(ctx context.Context, name string) (string, error)
}

// OCIIdentityGateway is the real identity gateway over the signed transport.
type OCIIdentityGateway struct {
	Identity  *OCIHTTPTransport
	TenancyID string
}

var _ IdentityGateway = (*OCIIdentityGateway)(nil)

// NewOCIIdentityGateway validates the identity transport and tenancy scope.
func NewOCIIdentityGateway(identity *OCIHTTPTransport, tenancyID string) (*OCIIdentityGateway, error) {
	if identity == nil || identity.Config.Service != OCIServiceIdentity {
		return nil, &errs.Argument{Message: "identity gateway requires the identity transport"}
	}
	if !isOCID(tenancyID, "tenancy") {
		return nil, &errs.Argument{Message: "identity gateway requires a tenancy identity"}
	}
	return &OCIIdentityGateway{Identity: identity, TenancyID: tenancyID}, nil
}

// EnsureCompartment returns the ACTIVE compartment's id, creating it when
// absent. Creation is asynchronous, so an existing in-flight compartment is
// adopted and polled rather than creating a duplicate.
func (g *OCIIdentityGateway) EnsureCompartment(ctx context.Context, name string) (string, error) {
	if g == nil || g.Identity == nil {
		return "", &InvalidOperationError{Message: "identity gateway is unavailable"}
	}
	if ctx == nil {
		return "", &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if !validEstateName(name) {
		return "", &errs.Argument{Message: "compartment name is invalid"}
	}
	type compartment struct {
		ID             string `json:"id"`
		LifecycleState string `json:"lifecycleState"`
	}
	listCompartments := func() ([]compartment, error) {
		query := url.Values{}
		query.Set("compartmentId", g.TenancyID)
		query.Set("name", name)
		var list struct {
			Items []compartment `json:"items"`
		}
		if err := doOCIJSON(ctx, g.Identity, http.MethodGet, "/20160918/compartments?"+query.Encode(), nil, nil, &list); err != nil {
			return nil, err
		}
		return list.Items, nil
	}
	findCompartment := func(items []compartment) (string, string, error) {
		var found *compartment
		for i := range items {
			item := items[i]
			if item.LifecycleState == "DELETED" {
				continue
			}
			if !isOCID(item.ID, "compartment") {
				return "", "", &InvalidDataError{Message: "OCI compartment response is invalid"}
			}
			if found != nil {
				return "", "", &InvalidDataError{Message: "multiple compartments share the declared name"}
			}
			found = &item
		}
		if found == nil {
			return "", "", nil
		}
		return found.ID, found.LifecycleState, nil
	}
	waitForCompartment := func() (string, error) {
		for pass := 1; pass <= bootstrapDefaultMaxPasses; pass++ {
			items, err := listCompartments()
			if err != nil {
				return "", err
			}
			id, state, err := findCompartment(items)
			if err != nil {
				return "", err
			}
			switch state {
			case "ACTIVE":
				return id, nil
			case "CREATING", "UPDATING", "DELETING":
				if err := waitBootstrapPoll(ctx, pass); err != nil {
					return "", err
				}
			case "FAILED", "ERROR":
				return "", &InvalidDataError{Message: "OCI compartment creation failed"}
			case "":
				// A create that disappears before becoming ACTIVE has an
				// ambiguous provider outcome. Do not issue another create from
				// this invocation; add-region will re-observe the same intent.
				return "", &ProviderOutcomeUnknownError{Message: "OCI compartment outcome is unknown before it became ACTIVE"}
			default:
				return "", &InvalidDataError{Message: "OCI compartment lifecycle state is unusable"}
			}
		}
		return "", &InvalidOperationError{Message: "OCI compartment did not become ACTIVE within the polling budget"}
	}
	items, err := listCompartments()
	if err != nil {
		return "", err
	}
	if id, state, findErr := findCompartment(items); findErr != nil {
		return "", findErr
	} else if state != "" {
		if state == "ACTIVE" {
			return id, nil
		}
		if state == "FAILED" || state == "ERROR" {
			return "", &InvalidDataError{Message: "OCI compartment creation failed"}
		}
		activeID, err := waitForCompartment()
		if err != nil {
			return "", err
		}
		if activeID != "" {
			return activeID, nil
		}
	}
	var created struct {
		ID             string `json:"id"`
		LifecycleState string `json:"lifecycleState"`
	}
	if err := doOCIJSON(ctx, g.Identity, http.MethodPost, "/20160918/compartments", struct {
		CompartmentID string `json:"compartmentId"`
		Name          string `json:"name"`
		Description   string `json:"description"`
	}{CompartmentID: g.TenancyID, Name: name, Description: "TerraScale estate (orchestrator-managed)"}, map[string]string{"opc-retry-token": name}, &created); err != nil {
		return "", err
	}
	if !isOCID(created.ID, "compartment") {
		return "", &InvalidDataError{Message: "OCI compartment create response is invalid"}
	}
	if created.LifecycleState == "ACTIVE" {
		return created.ID, nil
	}
	return waitForCompartment()
}

// RunOCIBootstrapFromEnvironment is the whole bootstrap entry point behind
// the subcommand: read credentials loudly, sign with the owner's API key,
// ensure the compartment, build the service gateways, and run the stages.
func RunOCIBootstrapFromEnvironment(ctx context.Context, lookup func(string) (string, bool), request BootstrapRequest, progress io.Writer) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return classifyBootstrapOutcome(err)
	}
	credentials, err := BootstrapCredentialsFromEnv(lookup)
	if err != nil {
		return err
	}
	if request.Region.OCIName == "" {
		if region, regionErr := DefaultBootstrapRegion(); regionErr == nil {
			request.Region = region
		}
	}
	if request.ImageID == "" {
		if image, present := lookup(OCIImageEnvironment); present {
			request.ImageID = strings.TrimSpace(image)
		}
	}
	if request.TSNodeVersion == "" {
		if value, present := lookup(TSNodeVersionEnvironment); present {
			request.TSNodeVersion = strings.TrimSpace(value)
		}
	}
	if request.TSNodeSHA256 == "" {
		if value, present := lookup(TSNodeSHA256Environment); present {
			request.TSNodeSHA256 = strings.TrimSpace(value)
		}
	}
	if request.TSNodeURL == "" {
		if value, present := lookup(TSNodeURLEnvironment); present {
			request.TSNodeURL = strings.TrimSpace(value)
		}
	}
	if request.CompartmentName == "" {
		request.CompartmentName = "terrascale"
	}
	if err := request.validate(); err != nil {
		return err
	}
	if request.Region.OCIName != credentials.Region {
		return &errs.Argument{Message: "bootstrap region credentials and declared estate region disagree"}
	}
	key, err := readRSAPrivateKey(credentials.PrivateKeyPath)
	if err != nil {
		return err
	}
	signer, err := NewInstancePrincipalSigner(credentials.SigningKeyID(), key)
	if err != nil {
		return err
	}
	newTransport := func(service OCIService) (*OCIHTTPTransport, error) {
		host, _ := ociServiceHost(service, credentials.Region)
		if host == "" {
			host = "bootstrap-management.kms." + credentials.Region + ".oraclecloud.com"
		}
		config, err := NewOCIServiceTransportConfig(service, credentials.Region, "https://"+host)
		if err != nil {
			return nil, err
		}
		return NewOCIHTTPTransport(config, nil, signer)
	}
	core, err := newTransport(OCIServiceCore)
	if err != nil {
		return err
	}
	identityTransport, err := newTransport(OCIServiceIdentity)
	if err != nil {
		return err
	}
	identity, err := NewOCIIdentityGateway(identityTransport, credentials.TenancyOCID)
	if err != nil {
		return err
	}
	compartmentID, err := identity.EnsureCompartment(ctx, request.CompartmentName)
	if err != nil {
		return fmt.Errorf("bootstrap compartment failed: %w", classifyBootstrapOutcome(err))
	}
	network, err := NewOCINetworkGateway(core, compartmentID)
	if err != nil {
		return err
	}
	compute, err := NewOCIMemberGateway(core, compartmentID, request.ImageID)
	if err != nil {
		return err
	}
	block, err := NewOCIBlockStorageGateway(core, compartmentID)
	if err != nil {
		return err
	}
	objectTransport, err := newTransport(OCIServiceObjectStorage)
	if err != nil {
		return err
	}
	object, err := NewOCIObjectStorageGateway(objectTransport, compartmentID)
	if err != nil {
		return err
	}
	vaultTransport, err := newTransport(OCIServiceVault)
	if err != nil {
		return err
	}
	managementTransport, err := newTransport(OCIServiceVaultManagement)
	if err != nil {
		return err
	}
	vault, err := NewOCIVaultGateway(vaultTransport, managementTransport, credentials.Region, compartmentID)
	if err != nil {
		return err
	}
	return RunOCIBootstrap(ctx, request, BootstrapGateways{Network: network, Compute: compute, Block: block, Object: object, Vault: vault}, progress)
}
