// Package vaultsecret keeps TerraScale's secrets in OCI Vault: one naming
// scheme, create-once storage and reads that never print a value.
package vaultsecret

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// VaultClient is the part of the OCI Vault management API that stores secrets.
type VaultClient interface {
	ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error)
	CreateSecret(context.Context, ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error)
}

// BundleClient reads secret contents.
type BundleClient interface {
	GetSecretBundleByName(context.Context, ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error)
}

// Target is where a new secret goes: its compartment, which decides who may
// read it, and the Vault and master key that hold it.
type Target struct {
	CompartmentID, VaultID, KeyID string
}

var (
	secretOCIDRE = regexp.MustCompile(`^ocid1\.vaultsecret\.oc1\.[a-z0-9-]+\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	nameRE       = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Name is the Vault secret holding key of scope, a cell such as gru-1: the
// scope, then the key lower-cased with hyphens for underscores. The key
// starts with its service, so TS_AUTH_MASTER_KEY of gru-1 is
// gru-1-ts-auth-master-key.
func Name(scope, key string) string {
	return scope + "-" + strings.ToLower(strings.ReplaceAll(key, "_", "-"))
}

// Stored is one secret of the Vault; it never carries the value.
type Stored struct {
	Secret  string `json:"secret"`
	ID      string `json:"id"`
	Created bool   `json:"created"`
	// Provisioning is true when an existing OCI secret is still becoming
	// readable. It is internal state, so it never appears in CLI output.
	Provisioning bool `json:"-"`
}

// Ensure stores value as secret name unless the Vault holds a secret of that
// name. value runs only when the secret is absent, so an existing secret is
// never regenerated, replaced or rotated. OCI keeps secret names unique in a
// Vault, so two runs cannot both create one.
func Ensure(ctx context.Context, client VaultClient, target Target, name, description string, value func(context.Context) (string, error)) (Stored, error) {
	stored := Stored{Secret: name}
	if err := safeEnv(); err != nil {
		return stored, err
	}
	id, provisioning, err := lookup(ctx, client, target, name)
	if err != nil || id != "" {
		stored.ID = id
		stored.Provisioning = provisioning
		return stored, err
	}
	secret, err := value(ctx)
	if err != nil {
		return stored, err
	}
	content := base64.StdEncoding.EncodeToString([]byte(secret))
	response, err := client.CreateSecret(ctx, ocivault.CreateSecretRequest{
		CreateSecretDetails: ocivault.CreateSecretDetails{
			CompartmentId: new(target.CompartmentID), VaultId: new(target.VaultID), KeyId: new(target.KeyID),
			SecretName: new(name), Description: new(description),
			SecretContent: ocivault.Base64SecretContentDetails{Content: new(content), Stage: ocivault.SecretContentDetailsStageCurrent},
		},
		// The SDK retries a lost response with the same token, which OCI
		// answers with the first result instead of a second secret.
		OpcRetryToken: new(uuid.New().String()),
	})
	if err != nil {
		if id, provisioning, lookupErr := lookup(ctx, client, target, name); lookupErr == nil && id != "" {
			stored.ID, stored.Provisioning = id, provisioning
			return stored, nil
		}
		return stored, fmt.Errorf("create Vault secret %s failed", name)
	}
	if response.Id == nil || !secretOCIDRE.MatchString(*response.Id) {
		return stored, fmt.Errorf("create Vault secret %s: OCI returned no secret OCID", name)
	}
	stored.ID, stored.Created = *response.Id, true
	return stored, nil
}

// lookup returns the OCID of the active secret name, or "" when the Vault has
// none. A secret of that name in any other state needs an operator: it may be
// pending deletion, and OCI refuses its name until it is deleted.
func lookup(ctx context.Context, client VaultClient, target Target, name string) (string, bool, error) {
	found := ""
	provisioning := false
	request := ocivault.ListSecretsRequest{CompartmentId: new(target.CompartmentID), VaultId: new(target.VaultID), Name: new(name)}
	for range 32 {
		response, err := client.ListSecrets(ctx, request)
		if err != nil {
			return "", false, fmt.Errorf("list Vault secret %s failed", name)
		}
		for _, item := range response.Items {
			if item.SecretName == nil || *item.SecretName != name {
				continue
			}
			if item.Id == nil || !secretOCIDRE.MatchString(*item.Id) || found != "" ||
				item.LifecycleState != ocivault.SecretSummaryLifecycleStateActive &&
					item.LifecycleState != ocivault.SecretSummaryLifecycleStateCreating {
				return "", false, fmt.Errorf("Vault secret %s exists in state %s; inspect it before rerunning", name, item.LifecycleState)
			}
			found = *item.Id
			provisioning = item.LifecycleState == ocivault.SecretSummaryLifecycleStateCreating
		}
		if response.OpcNextPage == nil {
			return found, provisioning, nil
		}
		request.Page = response.OpcNextPage
	}
	return "", false, fmt.Errorf("list Vault secret %s: too many pages", name)
}

// Read reads the current version of secret name. Errors name the secret,
// never its content.
func Read(ctx context.Context, client BundleClient, vaultID, name string) (string, error) {
	response, err := readBundle(ctx, client, vaultID, name)
	if err != nil {
		return "", err
	}
	return decodeBundle(response.SecretBundle, name)
}

// VersionedValue binds a value to its authoritative OCI secret version.
type VersionedValue struct {
	Value    string `json:"-"`
	SecretID string
	Number   int64
}

// ReadVersioned returns the value and metadata from one CURRENT bundle.
func ReadVersioned(ctx context.Context, client BundleClient, vaultID, name string) (VersionedValue, error) {
	response, err := readBundle(ctx, client, vaultID, name)
	if err != nil {
		return VersionedValue{}, err
	}
	bundle := response.SecretBundle
	if bundle.SecretId == nil || *bundle.SecretId == "" || bundle.VersionNumber == nil || *bundle.VersionNumber <= 0 {
		return VersionedValue{}, fmt.Errorf("Vault secret %s has no authoritative version", name)
	}
	value, err := decodeBundle(bundle, name)
	if err != nil {
		return VersionedValue{}, err
	}
	if strings.ContainsRune(value, 0) {
		return VersionedValue{}, fmt.Errorf("Vault secret %s does not fit an environment variable", name)
	}
	return VersionedValue{Value: value, SecretID: *bundle.SecretId, Number: *bundle.VersionNumber}, nil
}

func readBundle(ctx context.Context, client BundleClient, vaultID, name string) (ocisecrets.GetSecretBundleByNameResponse, error) {
	if err := safeEnv(); err != nil {
		return ocisecrets.GetSecretBundleByNameResponse{}, err
	}
	response, err := client.GetSecretBundleByName(ctx, ocisecrets.GetSecretBundleByNameRequest{
		SecretName: new(name), VaultId: new(vaultID), Stage: ocisecrets.GetSecretBundleByNameStageCurrent,
	})
	if err != nil {
		return response, &readError{name: name, cause: err}
	}
	return response, nil
}

// Keep the SDK error available for retry classification, without printing
// a response body that might contain secret material.
type readError struct {
	name  string
	cause error
}

func (e *readError) Error() string {
	if Absent(e.cause) {
		return "Vault secret " + e.name + " does not exist"
	}
	return "read Vault secret " + e.name + " failed"
}
func (e *readError) Unwrap() error    { return e.cause }
func (e *readError) GoString() string { return e.Error() }

func decodeBundle(bundle ocisecrets.SecretBundle, name string) (string, error) {
	var content *string
	switch bundle := bundle.SecretBundleContent.(type) {
	case ocisecrets.Base64SecretBundleContentDetails:
		content = bundle.Content
	case *ocisecrets.Base64SecretBundleContentDetails:
		if bundle != nil {
			content = bundle.Content
		}
	}
	if content == nil {
		return "", fmt.Errorf("Vault secret %s has no base64 content", name)
	}
	if len(*content) > base64.StdEncoding.EncodedLen(maxValue) {
		return "", fmt.Errorf("Vault secret %s exceeds %d bytes", name, maxValue)
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*content)
	if err != nil {
		return "", fmt.Errorf("Vault secret %s is not base64", name)
	}
	if len(value) > maxValue {
		return "", fmt.Errorf("Vault secret %s exceeds %d bytes", name, maxValue)
	}
	return string(value), nil
}

// ReadRefVersioned resolves one versioned secret with the instance principal.
func ReadRefVersioned(ctx context.Context, ref Ref) (VersionedValue, error) {
	if err := safeEnv(); err != nil {
		return VersionedValue{}, err
	}
	if ref.region() == "" {
		return VersionedValue{}, fmt.Errorf("Vault secret %s names no regional Vault", ref.Name)
	}
	factory, err := ociclient.InstancePrincipal(ref.region())
	if err != nil {
		return VersionedValue{}, err
	}
	client, err := SecretsClient(factory)
	if err != nil {
		return VersionedValue{}, err
	}
	return ReadVersioned(ctx, client, ref.Vault, ref.Name)
}

// ReadBack reads a secret that may have been created a moment ago: a new
// secret can take some seconds to become readable.
func ReadBack(ctx context.Context, client BundleClient, vaultID, name string, created bool) (string, error) {
	for attempt := 1; ; attempt++ {
		value, err := Read(ctx, client, vaultID, name)
		if err == nil || !created || attempt == 30 || !retrySecretRead(err) {
			return value, err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// Ref names a Vault secret a host reads each time it starts a workload. A
// profile's secrets map environment keys to refs, so desired state, config
// digests and reports carry names, never values, and a rotated secret takes
// effect at the next restart without a new signature.
type Ref struct {
	Vault string `json:"vault"`
	Name  string `json:"name"`
}

// FileKey reports whether a secret's key names a file: the host writes the
// value to a file only the workload user reads and sets the key to its path
// (TS-651), so the value never enters an environment.
func FileKey(key string) bool { return strings.HasSuffix(key, "_FILE") }

// MaxRefs bounds a workload's secrets, as profiles bound their environment.
const MaxRefs = 64

// maxResolved bounds a workload's resolved secrets together, below the
// native exec request limit, so an oversized set fails before the launch.
const maxResolved = 96 << 10

var (
	vaultOCIDRE = regexp.MustCompile(`^ocid1\.vault\.oc1\.([a-z0-9-]+)\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	envKeyRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// infrastructure are the cell's own secret families (docs/secrets.md).
	// A role that is, extends or prefixes one names no secrets, so no
	// workload reaches the NetBird, origin, trust or Cloudflare secrets its
	// host may read.
	infrastructure = []string{"api", "cloudflare", "netbird", "orch", "trust", "ts-dashboard", "ts-orchestrator"}
)

// region is the OCI region of the ref's Vault, or "" when the OCID names none.
func (r Ref) region() string {
	match := vaultOCIDRE.FindStringSubmatch(r.Vault)
	if match == nil || len(r.Vault) > 255 || !catalog.IsOCIRegion(match[1]) {
		return ""
	}
	return match[1]
}

// ValidateRefs checks the secrets of role in cell. Each key is an environment
// name that env does not also set. Each ref names a Vault in the cell's own
// OCI region and a secret <cell>-<n>-<role>-<key>, so a profile reaches only
// its own role's secrets even where its host may read more: controllers read
// their whole compartment. Names are prefixes, so the controller also refuses
// a role with secrets beside a role that extends its name (role "foo" would
// otherwise reach "foo-bar"'s), and only a root may add or change a ref
// (cellspec.AuthorityChanges), which pins the Vault.
func ValidateRefs(cell, role string, refs map[string]Ref, env map[string]string) error {
	if len(refs) > MaxRefs {
		return fmt.Errorf("%s has more than %d Vault secrets", role, MaxRefs)
	}
	if len(refs) != 0 && slices.ContainsFunc(infrastructure, func(family string) bool {
		return role == family || strings.HasPrefix(role, family+"-") || strings.HasPrefix(family, role+"-")
	}) {
		return fmt.Errorf("role %s shares a name with the cell's infrastructure secrets and names no Vault secrets", role)
	}
	return ValidateDeliveryRefs(cell, role, refs, env)
}

// ValidateDeliveryRefs binds a privileged delivery to one regional service.
// Workload profiles also apply ValidateRefs's infrastructure-name restriction.
func ValidateDeliveryRefs(cell, service string, refs map[string]Ref, env map[string]string) error {
	if len(refs) > MaxRefs || !nameRE.MatchString(service) {
		return errors.New("Vault delivery needs a service name and at most 64 references")
	}
	entry, known := catalog.LookupName(cell)
	files := map[string]bool{}
	for key, ref := range refs {
		if !known || ref.region() != entry.OCIRegion {
			return fmt.Errorf("Vault secret %s of %s must name a Vault in cell %s's region", key, service, cell)
		}
		if !envKeyRE.MatchString(key) {
			return fmt.Errorf("Vault secret key %q of %s is not an environment name", key, service)
		}
		if _, set := env[key]; set {
			return fmt.Errorf("%s sets %s both in env and as a Vault secret", service, key)
		}
		if files[strings.ToLower(key)] {
			return errors.New("Vault secret keys must name distinct files after lowercasing")
		}
		files[strings.ToLower(key)] = true
		rest, inCell := strings.CutPrefix(ref.Name, cell+"-")
		secretKey, ofService := strings.CutPrefix(rest, service+"-")
		if !ofService {
			// Existing signed profiles retain their cell-number namespace.
			index, legacy, _ := strings.Cut(rest, "-")
			secretKey, ofService = strings.CutPrefix(legacy, service+"-")
			ofService = ofService && index != "" && index[0] != '0' && strings.Trim(index, "0123456789") == ""
		}
		if len(ref.Name) > 255 || !nameRE.MatchString(ref.Name) || !inCell || !ofService || secretKey == "" {
			return fmt.Errorf("Vault secret %s of %s must name %s-%s-<purpose> or an existing %s-<n>-%s-<purpose>", key, service, cell, service, cell, service)
		}
	}
	return nil
}

// Resolve reads the current value of every ref; client opens the secrets API
// of a Vault's region. Errors name keys and secrets, never values.
func Resolve(ctx context.Context, refs map[string]Ref, client func(region string) (BundleClient, error)) (map[string]string, error) {
	// Before client fetches an instance principal.
	if err := safeEnv(); err != nil {
		return nil, err
	}
	values := make(map[string]string, len(refs))
	total := 0
	for key, ref := range refs {
		region := ref.region()
		if region == "" {
			return nil, fmt.Errorf("Vault secret %s names no regional Vault", key)
		}
		bundles, err := client(region)
		if err != nil {
			return nil, fmt.Errorf("Vault secret %s: %w", key, err)
		}
		value, err := Read(ctx, bundles, ref.Vault, ref.Name)
		if err != nil {
			return nil, err
		}
		// exec refuses a NUL in the environment.
		if len(value) > maxValue || strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("Vault secret %s does not fit an environment variable", ref.Name)
		}
		if total += len(key) + len(value); total > maxResolved {
			return nil, fmt.Errorf("Vault secrets exceed %d bytes together", maxResolved)
		}
		values[key] = value
	}
	return values, nil
}

// ReadRefs resolves refs with the instance principal, as a host does.
func ReadRefs(ctx context.Context, refs map[string]Ref) (map[string]string, error) {
	return Resolve(ctx, refs, func(region string) (BundleClient, error) {
		factory, err := ociclient.InstancePrincipal(region)
		if err != nil {
			return nil, err
		}
		return SecretsClient(factory)
	})
}

// safeEnv refuses OCI SDK settings that log request and response bodies or
// redirect endpoints and TLS trust: secret contents would leak.
func safeEnv() error {
	for _, variable := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(variable); set {
			return fmt.Errorf("OCI Vault access refuses to run while %s is set", variable)
		}
	}
	return nil
}

func retrySecretRead(err error) bool {
	var serviceErr common.ServiceError
	if !errors.As(err, &serviceErr) {
		return false
	}
	status := serviceErr.GetHTTPStatusCode()
	return status == http.StatusNotFound || status == http.StatusConflict
}

// Absent reports whether Vault answered that the secret does not exist.
func Absent(err error) bool {
	var serviceErr common.ServiceError
	return errors.As(err, &serviceErr) && serviceErr.GetHTTPStatusCode() == http.StatusNotFound
}
