package provider

import (
	"context"
	"net/http"
	"net/url"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The vault reconciler creates and repairs the Region's default vault and
// its keys (D-65/D-70): one software-protected DEFAULT vault — never a
// Virtual Private Vault — holding one AES-256 key per declared purpose
// (the Region KEK that wraps per-database DEKs). Vault and key creation
// are asynchronous on OCI, so a CREATING resource plans nothing and the
// next pass finishes the job.

// DefaultVaultName derives the deterministic vault display name for a
// Region code.
func DefaultVaultName(regionCode string) string { return "terrascale-" + regionCode + "-vault" }

const (
	vaultTypeDefault         = "DEFAULT"
	vaultTypeVirtualPrivate  = "VIRTUAL_PRIVATE"
	vaultKeyAlgorithmAES     = "AES"
	vaultKeyLengthBits       = 256
	vaultKeyProtectionSecret = "SOFTWARE"
)

type ObservedVault struct {
	ID                 string
	DisplayName        string
	VaultType          string
	LifecycleState     string
	ManagementEndpoint string
}

type ObservedKey struct {
	ID             string
	DisplayName    string
	LifecycleState string
}

type VaultObserved struct {
	Vault *ObservedVault
	Keys  []ObservedKey
}

// VaultGateway is the OCI vault seam. Keys go through each vault's own
// management endpoint, so the gateway receives the observed vault.
type VaultGateway interface {
	ListVaults(ctx context.Context) ([]ObservedVault, error)
	CreateVault(ctx context.Context, name string) (ObservedVault, error)
	ListKeys(ctx context.Context, vault ObservedVault) ([]ObservedKey, error)
	CreateKey(ctx context.Context, vault ObservedVault, keyName string) (ObservedKey, error)
}

type CreateVaultAction struct{ Name string }

func (a CreateVaultAction) Kind() OCIActionKind { return OCIActionCreateVault }
func (a CreateVaultAction) Summary() string     { return "create software-protected vault " + a.Name }

type CreateVaultKeyAction struct {
	VaultName string
	KeyName   string
}

func (a CreateVaultKeyAction) Kind() OCIActionKind { return OCIActionCreateVaultKey }
func (a CreateVaultKeyAction) Summary() string {
	return "create AES-256 key " + a.KeyName + " in vault " + a.VaultName
}

// VaultReconciler converges one Region's vault and keys toward the
// declaration.
type VaultReconciler struct {
	Vault VaultGateway
}

var _ OCIReconciler[estate.Region, VaultObserved] = (*VaultReconciler)(nil)

func (r *VaultReconciler) Observe(ctx context.Context, declared estate.Region) (VaultObserved, error) {
	if r == nil || r.Vault == nil {
		return VaultObserved{}, &InvalidOperationError{Message: "vault reconciler is unavailable"}
	}
	if ctx == nil {
		return VaultObserved{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return VaultObserved{}, err
	}
	vaults, err := r.Vault.ListVaults(ctx)
	if err != nil {
		return VaultObserved{}, err
	}
	observed := VaultObserved{}
	for i := range vaults {
		if vaults[i].DisplayName == DefaultVaultName(declared.Code) && vaults[i].LifecycleState != "DELETED" && vaults[i].LifecycleState != "DELETING" {
			if observed.Vault != nil {
				return VaultObserved{}, &InvalidDataError{Message: "multiple vaults share the declared name"}
			}
			vault := vaults[i]
			observed.Vault = &vault
		}
	}
	if observed.Vault == nil || observed.Vault.LifecycleState != "ACTIVE" {
		return observed, nil
	}
	if observed.Keys, err = r.Vault.ListKeys(ctx, *observed.Vault); err != nil {
		return VaultObserved{}, err
	}
	return observed, nil
}

func (r *VaultReconciler) Reconcile(ctx context.Context, declared estate.Region, observed VaultObserved) (OCIPlan, error) {
	if ctx == nil {
		return OCIPlan{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return OCIPlan{}, err
	}
	plan := OCIPlan{}
	if observed.Vault == nil {
		plan.Actions = append(plan.Actions, CreateVaultAction{Name: DefaultVaultName(declared.Code)})
		return plan, nil
	}
	if observed.Vault.VaultType == vaultTypeVirtualPrivate {
		// D-65 forbids Virtual Private Vaults; adopting one silently would
		// put the estate on a paid tier it never declared.
		return OCIPlan{}, &InvalidDataError{Message: "observed vault is a Virtual Private Vault, which the estate never declares"}
	}
	if observed.Vault.LifecycleState != "ACTIVE" {
		// Creation or restoration is in flight; keys wait for an ACTIVE
		// vault, and the next reconcile pass picks them up.
		return plan, nil
	}
	keys := make(map[string]bool, len(observed.Keys))
	for _, key := range observed.Keys {
		if key.LifecycleState == "ENABLED" || key.LifecycleState == "CREATING" || key.LifecycleState == "PENDING_DELETION" {
			keys[key.DisplayName] = true
		}
	}
	for _, declaredKey := range declared.VaultKeys {
		if !keys[declaredKey.Name] {
			plan.Actions = append(plan.Actions, CreateVaultKeyAction{VaultName: observed.Vault.DisplayName, KeyName: declaredKey.Name})
		}
	}
	return plan, nil
}

func (r *VaultReconciler) Apply(ctx context.Context, declared estate.Region, observed VaultObserved, plan OCIPlan) error {
	if r == nil || r.Vault == nil {
		return &InvalidOperationError{Message: "vault reconciler is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	vault := observed.Vault
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case CreateVaultAction:
			created, err := r.Vault.CreateVault(ctx, a.Name)
			if err != nil {
				return err
			}
			vault = &created
		case CreateVaultKeyAction:
			if vault == nil || vault.LifecycleState != "ACTIVE" || vault.DisplayName != a.VaultName {
				return &InvalidOperationError{Message: "key create requires an active declared vault"}
			}
			if _, err := r.Vault.CreateKey(ctx, *vault, a.KeyName); err != nil {
				return err
			}
		default:
			return &InvalidOperationError{Message: "vault reconciler received a foreign action"}
		}
	}
	return nil
}

// OCIVaultGateway is the real vault gateway: vault lifecycle over the
// vaults service transport, key management over each vault's own
// management endpoint.
type OCIVaultGateway struct {
	Vaults        *OCIHTTPTransport
	Management    *OCIHTTPTransport // used only to validate endpoint shape
	Region        string
	CompartmentID string
}

var _ VaultGateway = (*OCIVaultGateway)(nil)

// NewOCIVaultGateway validates the vaults transport and compartment scope.
// The management transport seeds endpoint validation for per-vault key
// clients.
func NewOCIVaultGateway(vaults, management *OCIHTTPTransport, region, compartmentID string) (*OCIVaultGateway, error) {
	if vaults == nil || vaults.Config.Service != OCIServiceVault {
		return nil, &errs.Argument{Message: "vault gateway requires the vaults transport"}
	}
	if management == nil || management.Config.Service != OCIServiceVaultManagement {
		return nil, &errs.Argument{Message: "vault gateway requires a vault-management transport"}
	}
	if len(region) < 1 || len(region) > 63 || !regionPattern.MatchString(region) {
		return nil, &errs.Argument{Message: "vault gateway requires a canonical region"}
	}
	if !isOCID(compartmentID, "compartment") {
		return nil, &errs.Argument{Message: "vault gateway requires a compartment identity"}
	}
	return &OCIVaultGateway{Vaults: vaults, Management: management, Region: region, CompartmentID: compartmentID}, nil
}

type ociVaultDocument struct {
	ID                 string `json:"id"`
	DisplayName        string `json:"displayName"`
	VaultType          string `json:"vaultType"`
	LifecycleState     string `json:"lifecycleState"`
	ManagementEndpoint string `json:"managementEndpoint"`
}

func observedVault(document ociVaultDocument) (ObservedVault, error) {
	if !isOCID(document.ID, "vault") {
		return ObservedVault{}, &InvalidDataError{Message: "OCI vault response is invalid"}
	}
	return ObservedVault{ID: document.ID, DisplayName: document.DisplayName, VaultType: document.VaultType, LifecycleState: document.LifecycleState, ManagementEndpoint: document.ManagementEndpoint}, nil
}

func (g *OCIVaultGateway) ListVaults(ctx context.Context) ([]ObservedVault, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	var list struct {
		Items []ociVaultDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Vaults, http.MethodGet, "/20180608/vaults?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	vaults := make([]ObservedVault, 0, len(list.Items))
	for _, item := range list.Items {
		vault, err := observedVault(item)
		if err != nil {
			return nil, err
		}
		vaults = append(vaults, vault)
	}
	return vaults, nil
}

func (g *OCIVaultGateway) CreateVault(ctx context.Context, name string) (ObservedVault, error) {
	if !validEstateName(name) {
		return ObservedVault{}, &errs.Argument{Message: "vault create request is invalid"}
	}
	var document ociVaultDocument
	if err := doOCIJSON(ctx, g.Vaults, http.MethodPost, "/20180608/vaults", struct {
		CompartmentID string `json:"compartmentId"`
		DisplayName   string `json:"displayName"`
		VaultType     string `json:"vaultType"`
	}{CompartmentID: g.CompartmentID, DisplayName: name, VaultType: vaultTypeDefault}, nil, &document); err != nil {
		return ObservedVault{}, err
	}
	created, err := observedVault(document)
	if err != nil {
		return ObservedVault{}, err
	}
	if created.VaultType == vaultTypeVirtualPrivate {
		return ObservedVault{}, &InvalidDataError{Message: "OCI created a vault type the estate never declares"}
	}
	return created, nil
}

// keyTransport derives the per-vault management transport, validated
// against the gateway's region so a hostile vault document cannot redirect
// signed key requests elsewhere.
func (g *OCIVaultGateway) keyTransport(vault ObservedVault) (*OCIHTTPTransport, error) {
	if !isOCID(vault.ID, "vault") || vault.LifecycleState != "ACTIVE" {
		return nil, &errs.Argument{Message: "key request requires an active vault"}
	}
	config, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, g.Region, vault.ManagementEndpoint)
	if err != nil {
		return nil, &InvalidDataError{Message: "vault management endpoint is invalid for the region"}
	}
	return NewOCIHTTPTransport(config, g.Management.Client, g.Management.Signer)
}

type ociKeyDocument struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	LifecycleState string `json:"lifecycleState"`
}

func (g *OCIVaultGateway) ListKeys(ctx context.Context, vault ObservedVault) ([]ObservedKey, error) {
	transport, err := g.keyTransport(vault)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	var list struct {
		Items []ociKeyDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, transport, http.MethodGet, "/20180608/keys?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	keys := make([]ObservedKey, 0, len(list.Items))
	for _, item := range list.Items {
		if !isOCID(item.ID, "key") {
			return nil, &InvalidDataError{Message: "OCI key response is invalid"}
		}
		keys = append(keys, ObservedKey{ID: item.ID, DisplayName: item.DisplayName, LifecycleState: item.LifecycleState})
	}
	return keys, nil
}

func (g *OCIVaultGateway) CreateKey(ctx context.Context, vault ObservedVault, keyName string) (ObservedKey, error) {
	if !validEstateName(keyName) {
		return ObservedKey{}, &errs.Argument{Message: "key create request is invalid"}
	}
	transport, err := g.keyTransport(vault)
	if err != nil {
		return ObservedKey{}, err
	}
	var document ociKeyDocument
	if err := doOCIJSON(ctx, transport, http.MethodPost, "/20180608/keys", struct {
		CompartmentID string `json:"compartmentId"`
		DisplayName   string `json:"displayName"`
		KeyShape      struct {
			Algorithm  string `json:"algorithm"`
			Length     int    `json:"length"`
			Protection string `json:"protectionMode"`
		} `json:"keyShape"`
		VaultID string `json:"vaultId"`
	}{CompartmentID: g.CompartmentID, DisplayName: keyName, VaultID: vault.ID, KeyShape: struct {
		Algorithm  string `json:"algorithm"`
		Length     int    `json:"length"`
		Protection string `json:"protectionMode"`
	}{Algorithm: vaultKeyAlgorithmAES, Length: vaultKeyLengthBits, Protection: vaultKeyProtectionSecret}}, nil, &document); err != nil {
		return ObservedKey{}, err
	}
	if !isOCID(document.ID, "key") {
		return ObservedKey{}, &InvalidDataError{Message: "OCI key create response is invalid"}
	}
	return ObservedKey{ID: document.ID, DisplayName: document.DisplayName, LifecycleState: document.LifecycleState}, nil
}
