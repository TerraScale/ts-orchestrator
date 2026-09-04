package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// OCI bootstrap (D-67): create the compartment, then drive the reconcilers
// in dependency order — network, vault, buckets, member hosts, data volumes
// — until every stage converges. This is the executor half; the pure
// greenfield planner lives in the bootstrap package and composes these
// gateways. The real run needs the owner's OCI API key (O-4/I-7); without
// it, bootstrap fails loudly before any request is signed.

const bootstrapMaxPasses = 8

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
		return err
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
	if err := convergeStage(ctx, "network", network, request.Region, progress); err != nil {
		return err
	}
	if err := convergeStage(ctx, "vault", vault, request.Region, progress); err != nil {
		return err
	}
	if err := convergeStage(ctx, "buckets", object, request.Region, progress); err != nil {
		return err
	}
	if err := convergeStage(ctx, "hosts", compute, ComputeDeclared{Region: request.Region, ImageID: request.ImageID, CloudInitBase64: cloudInit}, progress); err != nil {
		return err
	}
	return convergeStage(ctx, "volumes", block, request.Region, progress)
}

// convergeStage replans one reconciler until its plan is empty. Async OCI
// resources (vaults, keys, instances) reach their terminal states between
// passes.
func convergeStage[D any, O any](ctx context.Context, stage string, reconciler OCIReconciler[D, O], declared D, progress io.Writer) error {
	for pass := 1; pass <= bootstrapMaxPasses; pass++ {
		observed, err := reconciler.Observe(ctx, declared)
		if err != nil {
			return fmt.Errorf("bootstrap %s observe failed: %w", stage, err)
		}
		plan, err := reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			return fmt.Errorf("bootstrap %s reconcile failed: %w", stage, err)
		}
		if plan.Empty() {
			return nil
		}
		for _, action := range plan.Actions {
			if progress != nil {
				if _, writeErr := fmt.Fprintf(progress, "bootstrap %s: %s\n", stage, action.Summary()); writeErr != nil {
					return fmt.Errorf("bootstrap %s progress failed: %w", stage, writeErr)
				}
			}
		}
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			return fmt.Errorf("bootstrap %s apply failed: %w", stage, err)
		}
	}
	return &InvalidOperationError{Message: "bootstrap stage did not converge within its pass budget: " + stage}
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
// absent. Creation is asynchronous: a just-created compartment may still be
// CREATING, and the stage that needs it fails loudly on the first pass —
// rerunning bootstrap converges, which is its normal operating mode.
func (g *OCIIdentityGateway) EnsureCompartment(ctx context.Context, name string) (string, error) {
	if !validEstateName(name) {
		return "", &errs.Argument{Message: "compartment name is invalid"}
	}
	query := url.Values{}
	query.Set("compartmentId", g.TenancyID)
	query.Set("name", name)
	var list struct {
		Items []struct {
			ID             string `json:"id"`
			LifecycleState string `json:"lifecycleState"`
		} `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Identity, http.MethodGet, "/20160918/compartments?"+query.Encode(), nil, nil, &list); err != nil {
		return "", err
	}
	for _, item := range list.Items {
		if isOCID(item.ID, "compartment") && item.LifecycleState == "ACTIVE" {
			return item.ID, nil
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
	}{CompartmentID: g.TenancyID, Name: name, Description: "TerraScale estate (orchestrator-managed)"}, nil, &created); err != nil {
		return "", err
	}
	if !isOCID(created.ID, "compartment") {
		return "", &InvalidDataError{Message: "OCI compartment create response is invalid"}
	}
	return created.ID, nil
}

// RunOCIBootstrapFromEnvironment is the whole bootstrap entry point behind
// the subcommand: read credentials loudly, sign with the owner's API key,
// ensure the compartment, build the service gateways, and run the stages.
func RunOCIBootstrapFromEnvironment(ctx context.Context, lookup func(string) (string, bool), request BootstrapRequest, progress io.Writer) error {
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
		return fmt.Errorf("bootstrap compartment failed: %w", err)
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
