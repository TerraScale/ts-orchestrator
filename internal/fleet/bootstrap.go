package fleet

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const bootstrapParent = "TerraScale"

type bootstrap struct {
	ctx     context.Context
	out     io.Writer
	staging Staging
	tenancy string
	iam     identity.IdentityClient
	local   identity.IdentityClient
	vaults  keymanagement.KmsVaultClient
	factory *ociclient.Factory
}

func Bootstrap(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: ts-orch region bootstrap")
	}
	document, err := decode()
	if err != nil {
		return err
	}
	f, err := factory(ctx, document.Staging.OCIRegion)
	if err != nil {
		return err
	}
	b := &bootstrap{ctx: ctx, out: out, staging: document.Staging, factory: f}
	if b.tenancy, err = f.Provider().TenancyOCID(); err != nil {
		return err
	}
	home, err := f.HomeRegion(ctx, b.tenancy)
	if err != nil {
		return err
	}
	homeFactory, err := f.ForRegion(home)
	if err != nil {
		return err
	}
	if b.iam, err = homeFactory.Identity(); err != nil {
		return err
	}
	if b.local, err = f.Identity(); err != nil {
		return err
	}
	if b.vaults, err = keymanagement.NewKmsVaultClientWithConfigurationProvider(f.Provider()); err != nil {
		return err
	}
	b.vaults.SetRegion(f.Region())
	f.Configure(&b.vaults.BaseClient, ociclient.ServiceKMS)
	compartment, err := b.compartment()
	if err != nil {
		return err
	}
	if err := b.replicated(compartment); err != nil {
		return err
	}
	vault, err := b.vault(compartment)
	if err != nil {
		return err
	}
	keys, err := b.keys(vault)
	if err != nil {
		return err
	}
	key, err := b.key(keys, compartment, b.staging.Label+"-key", keymanagement.CreateKeyDetailsProtectionModeSoftware,
		keymanagement.KeyShape{Algorithm: keymanagement.KeyShapeAlgorithmAes, Length: common.Int(32)})
	if err != nil {
		return err
	}
	signer, err := b.key(keys, compartment, b.staging.Label+"-release-signer", keymanagement.CreateKeyDetailsProtectionModeHsm,
		keymanagement.KeyShape{Algorithm: keymanagement.KeyShapeAlgorithmEcdsa, Length: common.Int(32), CurveId: keymanagement.KeyShapeCurveIdP256})
	if err != nil {
		return err
	}
	public, err := signerPublicKey(b.ctx, keys, signer)
	if err != nil {
		return err
	}
	namespace, err := b.bucket(compartment)
	if err != nil {
		return err
	}
	group := "ts-orch-" + b.staging.Label
	if err := b.dynamicGroup(group, compartment); err != nil {
		return err
	}
	if err := b.policy(group, compartment, strings.NewReplacer("{group}", group, "{compartment}", compartment, "{vault}", deref(vault.Id), "{key}", deref(key.Id),
		"{signer}", deref(signer.Id), "{bucket}", b.staging.GateBucket())); err != nil {
		return err
	}
	var stale []error
	for _, field := range []struct{ name, document, live string }{
		{"compartment_id", b.staging.CompartmentID, compartment},
		{"vault_id", b.staging.VaultID, deref(vault.Id)},
		{"key_id", b.staging.KeyID, deref(key.Id)},
		{"signer_key_id", b.staging.SignerKeyID, deref(signer.Id)},
		{"signer_public_key", b.staging.SignerPublicKey, public},
		{"namespace", b.staging.Namespace, namespace},
	} {
		if field.document != field.live {
			stale = append(stale, fmt.Errorf("fleet document staging.%s is %s; set it to %s", field.name, field.document, field.live))
		}
	}
	return errors.Join(stale...)
}

func (b *bootstrap) report(verb, kind, name, id string) error {
	_, err := fmt.Fprintf(b.out, "%-9s %-14s %s %s\n", verb, kind, name, id)
	return err
}

func (b *bootstrap) compartment() (string, error) {
	parents, err := b.iam.ListCompartments(b.ctx, identity.ListCompartmentsRequest{CompartmentId: &b.tenancy, Name: common.String(bootstrapParent),
		LifecycleState: identity.CompartmentLifecycleStateActive})
	if err != nil {
		return "", fmt.Errorf("list compartments: %w", err)
	}
	if len(parents.Items) != 1 {
		return "", fmt.Errorf("want one active compartment %s in the tenancy, found %d", bootstrapParent, len(parents.Items))
	}
	name := b.staging.Label + "-1-control"
	existing, err := b.iam.ListCompartments(b.ctx, identity.ListCompartmentsRequest{CompartmentId: parents.Items[0].Id, Name: &name,
		LifecycleState: identity.CompartmentLifecycleStateActive})
	if err != nil {
		return "", fmt.Errorf("list compartments: %w", err)
	}
	if len(existing.Items) == 1 {
		return deref(existing.Items[0].Id), b.report("unchanged", "compartment", name, deref(existing.Items[0].Id))
	}
	created, err := b.iam.CreateCompartment(b.ctx, identity.CreateCompartmentRequest{CreateCompartmentDetails: identity.CreateCompartmentDetails{
		CompartmentId: parents.Items[0].Id, Name: &name, Description: common.String("TerraScale staging region " + b.staging.Label)}})
	if err != nil {
		return "", fmt.Errorf("create compartment %s: %w", name, err)
	}
	got, err := b.iam.GetCompartment(b.ctx, identity.GetCompartmentRequest{CompartmentId: created.Id,
		RequestMetadata: until(func(r identity.GetCompartmentResponse) bool {
			return r.LifecycleState == identity.CompartmentLifecycleStateActive
		})})
	if err != nil || got.LifecycleState != identity.CompartmentLifecycleStateActive {
		return "", errors.Join(fmt.Errorf("compartment %s is %s, not ACTIVE", name, got.LifecycleState), err)
	}
	return deref(created.Id), b.report("created", "compartment", name, deref(created.Id))
}

func (b *bootstrap) replicated(compartment string) error {
	got, err := b.local.GetCompartment(b.ctx, identity.GetCompartmentRequest{CompartmentId: &compartment,
		RequestMetadata: until(func(r identity.GetCompartmentResponse) bool {
			return r.LifecycleState == identity.CompartmentLifecycleStateActive
		})})
	if err != nil || got.LifecycleState != identity.CompartmentLifecycleStateActive {
		return errors.Join(fmt.Errorf("compartment %s is not yet ACTIVE in %s", compartment, b.staging.OCIRegion), err)
	}
	return nil
}

func (b *bootstrap) vault(compartment string) (keymanagement.Vault, error) {
	name := b.staging.Label + "-vault"
	listed, err := b.vaults.ListVaults(b.ctx, keymanagement.ListVaultsRequest{CompartmentId: &compartment})
	if err != nil {
		return keymanagement.Vault{}, fmt.Errorf("list vaults: %w", err)
	}
	live := slices.DeleteFunc(listed.Items, func(v keymanagement.VaultSummary) bool {
		return deref(v.DisplayName) != name || v.LifecycleState != keymanagement.VaultSummaryLifecycleStateActive && v.LifecycleState != keymanagement.VaultSummaryLifecycleStateCreating
	})
	if len(live) > 1 {
		return keymanagement.Vault{}, fmt.Errorf("%d live vaults are named %s", len(live), name)
	}
	verb, id := "unchanged", ""
	if len(live) == 1 {
		id = deref(live[0].Id)
	} else {
		created, err := b.vaults.CreateVault(b.ctx, keymanagement.CreateVaultRequest{CreateVaultDetails: keymanagement.CreateVaultDetails{
			CompartmentId: &compartment, DisplayName: &name, VaultType: keymanagement.CreateVaultDetailsVaultTypeDefault}})
		if err != nil {
			return keymanagement.Vault{}, fmt.Errorf("create vault %s: %w", name, err)
		}
		verb, id = "created", deref(created.Id)
	}
	got, err := b.vaults.GetVault(b.ctx, keymanagement.GetVaultRequest{VaultId: &id,
		RequestMetadata: until(func(r keymanagement.GetVaultResponse) bool {
			return r.LifecycleState == keymanagement.VaultLifecycleStateActive
		})})
	if err != nil || got.LifecycleState != keymanagement.VaultLifecycleStateActive {
		return keymanagement.Vault{}, errors.Join(fmt.Errorf("vault %s is %s, not ACTIVE", name, got.LifecycleState), err)
	}
	return got.Vault, b.report(verb, "vault", name, id)
}

func (b *bootstrap) keys(vault keymanagement.Vault) (keymanagement.KmsManagementClient, error) {
	if err := resolvable(b.ctx, deref(vault.ManagementEndpoint)); err != nil {
		return keymanagement.KmsManagementClient{}, err
	}
	keys, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(b.factory.Provider(), deref(vault.ManagementEndpoint))
	if err != nil {
		return keymanagement.KmsManagementClient{}, err
	}
	b.factory.Configure(&keys.BaseClient, ociclient.ServiceKMS)
	return keys, nil
}

func (b *bootstrap) key(keys keymanagement.KmsManagementClient, compartment, name string, protection keymanagement.CreateKeyDetailsProtectionModeEnum, shape keymanagement.KeyShape) (keymanagement.Key, error) {
	listed, err := keys.ListKeys(b.ctx, keymanagement.ListKeysRequest{CompartmentId: &compartment})
	if err != nil {
		return keymanagement.Key{}, fmt.Errorf("list keys: %w", err)
	}
	live := slices.DeleteFunc(listed.Items, func(k keymanagement.KeySummary) bool {
		return deref(k.DisplayName) != name || k.LifecycleState != keymanagement.KeySummaryLifecycleStateEnabled && k.LifecycleState != keymanagement.KeySummaryLifecycleStateCreating
	})
	if len(live) > 1 {
		return keymanagement.Key{}, fmt.Errorf("%d live keys are named %s", len(live), name)
	}
	verb, id := "unchanged", ""
	if len(live) == 1 {
		id = deref(live[0].Id)
	} else {
		created, err := keys.CreateKey(b.ctx, keymanagement.CreateKeyRequest{CreateKeyDetails: keymanagement.CreateKeyDetails{
			CompartmentId: &compartment, DisplayName: &name, ProtectionMode: protection, KeyShape: &shape}})
		if err != nil {
			return keymanagement.Key{}, fmt.Errorf("create key %s: %w", name, err)
		}
		verb, id = "created", deref(created.Id)
	}
	got, err := keys.GetKey(b.ctx, keymanagement.GetKeyRequest{KeyId: &id,
		RequestMetadata: until(func(r keymanagement.GetKeyResponse) bool {
			return r.LifecycleState == keymanagement.KeyLifecycleStateEnabled
		})})
	if err != nil || got.LifecycleState != keymanagement.KeyLifecycleStateEnabled {
		return keymanagement.Key{}, errors.Join(fmt.Errorf("key %s is %s, not ENABLED", name, got.LifecycleState), err)
	}
	return got.Key, b.report(verb, "key", name, id)
}

func signerPublicKey(ctx context.Context, keys keymanagement.KmsManagementClient, signer keymanagement.Key) (string, error) {
	version, err := keys.GetKeyVersion(ctx, keymanagement.GetKeyVersionRequest{KeyId: signer.Id, KeyVersionId: signer.CurrentKeyVersion})
	if err != nil {
		return "", fmt.Errorf("read key version of %s: %w", deref(signer.DisplayName), err)
	}
	block, _ := pem.Decode([]byte(deref(version.PublicKey)))
	if block == nil {
		return "", fmt.Errorf("key %s has no PEM public key", deref(signer.DisplayName))
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

func (b *bootstrap) bucket(compartment string) (string, error) {
	storage, err := b.factory.ObjectStorage()
	if err != nil {
		return "", err
	}
	namespace, err := storage.GetNamespace(b.ctx, objectstorage.GetNamespaceRequest{})
	if err != nil {
		return "", fmt.Errorf("read object storage namespace: %w", err)
	}
	name := b.staging.GateBucket()
	got, err := storage.GetBucket(b.ctx, objectstorage.GetBucketRequest{NamespaceName: namespace.Value, BucketName: &name})
	if failure, ok := common.IsServiceError(err); ok && failure.GetHTTPStatusCode() == 404 {
		created, err := storage.CreateBucket(b.ctx, objectstorage.CreateBucketRequest{NamespaceName: namespace.Value, CreateBucketDetails: objectstorage.CreateBucketDetails{
			Name: &name, CompartmentId: &compartment, PublicAccessType: objectstorage.CreateBucketDetailsPublicAccessTypeObjectreadwithoutlist}})
		if err != nil {
			return "", fmt.Errorf("create bucket %s: %w", name, err)
		}
		return deref(namespace.Value), b.report("created", "bucket", name, deref(created.Id))
	}
	if err != nil {
		return "", fmt.Errorf("read bucket %s: %w", name, err)
	}
	if deref(got.CompartmentId) != compartment || got.PublicAccessType != objectstorage.BucketPublicAccessTypeObjectreadwithoutlist {
		return "", fmt.Errorf("bucket %s is in %s with public access %s, not in %s with %s", name, deref(got.CompartmentId), got.PublicAccessType, compartment, objectstorage.BucketPublicAccessTypeObjectreadwithoutlist)
	}
	return deref(namespace.Value), b.report("unchanged", "bucket", name, deref(got.Id))
}

func (b *bootstrap) dynamicGroup(name, compartment string) error {
	rule := "ALL {instance.compartment.id = '" + compartment + "'}"
	listed, err := b.iam.ListDynamicGroups(b.ctx, identity.ListDynamicGroupsRequest{CompartmentId: &b.tenancy, Name: &name})
	if err != nil {
		return fmt.Errorf("list dynamic groups: %w", err)
	}
	if len(listed.Items) == 1 {
		got, err := b.iam.GetDynamicGroup(b.ctx, identity.GetDynamicGroupRequest{DynamicGroupId: listed.Items[0].Id})
		if err != nil {
			return fmt.Errorf("read dynamic group %s: %w", name, err)
		}
		group := got.DynamicGroup
		if deref(group.MatchingRule) == rule {
			return b.report("unchanged", "dynamic-group", name, deref(group.Id))
		}
		return fmt.Errorf("dynamic group %s matches %q, not %q; it is not this staging region's group", name, deref(group.MatchingRule), rule)
	}
	created, err := b.iam.CreateDynamicGroup(b.ctx, identity.CreateDynamicGroupRequest{CreateDynamicGroupDetails: identity.CreateDynamicGroupDetails{
		CompartmentId: &b.tenancy, Name: &name, MatchingRule: &rule, Description: common.String("ts-orch nodes of staging region " + b.staging.Label)}})
	if err != nil {
		return fmt.Errorf("create dynamic group %s: %w", name, err)
	}
	return b.report("created", "dynamic-group", name, deref(created.Id))
}

func (b *bootstrap) policy(group, compartment string, replacer *strings.Replacer) error {
	statements := make([]string, len(reconcilerStatements))
	for i, statement := range reconcilerStatements {
		statements[i] = replacer.Replace(statement)
	}
	listed, err := b.iam.ListPolicies(b.ctx, identity.ListPoliciesRequest{CompartmentId: &compartment, Name: &group})
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	if len(listed.Items) == 1 {
		policy := listed.Items[0]
		if slices.Equal(policy.Statements, statements) {
			return b.report("unchanged", "policy", group, deref(policy.Id))
		}
		if _, err := b.iam.UpdatePolicy(b.ctx, identity.UpdatePolicyRequest{PolicyId: policy.Id, UpdatePolicyDetails: identity.UpdatePolicyDetails{Statements: statements}}); err != nil {
			return fmt.Errorf("update policy %s: %w", group, err)
		}
		return b.report("updated", "policy", group, deref(policy.Id))
	}
	created, err := b.iam.CreatePolicy(b.ctx, identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{
		CompartmentId: &compartment, Name: &group, Statements: statements, Description: common.String("ts-orch nodes of staging region " + b.staging.Label + ": reconcile, Vault and OCIR read")}})
	if err != nil {
		return fmt.Errorf("create policy %s: %w", group, err)
	}
	return b.report("created", "policy", group, deref(created.Id))
}

func resolvable(ctx context.Context, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("vault management endpoint %q is not a URL", endpoint)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		_, err := net.DefaultResolver.LookupHost(ctx, parsed.Hostname())
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vault management endpoint %s does not resolve: %w", parsed.Hostname(), err)
		case <-tick.C:
		}
	}
}

func until[R any](done func(R) bool) common.RequestMetadata {
	policy := common.NewRetryPolicyWithOptions(common.ReplaceWithValuesFromRetryPolicy(common.NoRetryPolicy()), common.WithMaximumNumberAttempts(90), common.WithFixedBackoff(5*time.Second),
		common.WithShouldRetryOperation(func(r common.OCIOperationResponse) bool {
			if failure, ok := common.IsServiceError(r.Error); ok {
				return failure.GetHTTPStatusCode() == 404
			}
			response, ok := r.Response.(R)
			return r.Error == nil && ok && !done(response)
		}))
	return common.RequestMetadata{RetryPolicy: &policy}
}
