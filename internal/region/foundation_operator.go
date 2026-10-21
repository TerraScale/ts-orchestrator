package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The existing operator identity creates the first protected records before
// any instance principal is allowed to become their writer.
type foundationOperator struct {
	factory  *ociclient.Factory
	objects  *objectstorage.ObjectStorageClient
	genesis  trust.Keyring
	bundle   RetainedFoundation
	domain   bootstrap.StorageDomain
	id       string
	deadline time.Time
	buckets  map[string]string
}

func (authority *HomeIAMAuthority) reserveFoundationWorkloadOrigin(ctx context.Context) error {
	if authority == nil || authority.operator == nil {
		return errors.New("founding workload origin requires the authenticated initial operator")
	}
	ctx, releaseLease, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer releaseLease()
	// shortcut: this advisory lease cannot fence paused SDK dispatch; native genesis admission stays closed until consumer fencing exists.
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	if _, ok := authority.resolver.Footprint.(*SignedFootprint); !ok {
		return errors.New("founding workload origin lacks its verified foundation reader")
	}
	envelope, err := trust.DecodeEnvelope(authority.operator.bundle.GrantWire)
	if err != nil {
		return err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if grant.SchemaVersion != 3 {
		return nil
	}
	wire, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil {
		return err
	}
	for _, origin := range grant.WorkloadGenesis {
		name, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			return err
		}
		if err := publishFoundationObject(ctx, authority.objects, authority.domain.Namespace, name, wire); err != nil {
			return err
		}
		published, err := readDiscoveryObject(ctx, authority.objects, authority.domain.Namespace, name, int64(len(wire)))
		if err != nil || !bytes.Equal(published, wire) {
			return errors.Join(errors.New("founding workload origin lacks exact immutable readback"), err)
		}
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return err
	}
	return nil
}

func (authority *HomeIAMAuthority) verifyFoundationWorkloadStartup(ctx context.Context) error {
	grant, err := authority.originalMaterialGrant()
	if err != nil || grant.SchemaVersion != 3 {
		return err
	}
	reader := authority.resolver.Footprint.(*SignedFootprint)
	// Existing consumers must understand the signed lineage before paid work.
	_, err = bootstrap.VerifyBoundRegionalStartupTemplate(ctx, authority.factory, authority.operator.bundle.GrantWire, reader.roots, reader.bootstrapAnchor, oci.RegionGRU, time.Now())
	return err
}

func (operator *foundationOperator) guardWorkloadOrigin(ctx context.Context, reader *SignedFootprint) error {
	expected, err := json.Marshal(operator.bundle, json.Deterministic(true))
	if err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(operator.bundle.GrantWire)
	if err != nil {
		return err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
			name, err := release.WorkloadGenesisObject(operator.bundle.TenancyID, cell, reader.scope.Environment, role)
			if err != nil {
				return err
			}
			wire, err := readDiscoveryObject(ctx, operator.objects, operator.domain.Namespace, name, int64(len(expected)))
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
				continue
			}
			if err != nil {
				return err
			}
			if grant.SchemaVersion != 3 || !bytes.Equal(wire, expected) {
				return errors.New("permanent founding workload origin refuses a different or historical lineage")
			}
		}
	}
	return nil
}

func (authority *HomeIAMAuthority) publishFoundationPrerequisites(ctx context.Context) error {
	if authority == nil || authority.operator == nil {
		return errors.New("foundation prerequisites require the verified initial operator")
	}
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	for _, object := range []struct {
		name string
		wire []byte
	}{
		{foundationRootChainObject, authority.operator.bundle.RootChainWire},
		{strings.TrimSuffix(authority.domain.Prefix, "/") + "/" + foundationGrantObject, authority.operator.bundle.GrantWire},
	} {
		if err := publishFoundationObject(ctx, authority.objects, authority.domain.Namespace, object.name, object.wire); err != nil {
			return err
		}
	}
	return authority.Guard(ctx, 0)
}

func (operator *foundationOperator) guard(ctx context.Context) error {
	if operator == nil || ctx == nil || operator.factory == nil || operator.objects == nil {
		return errors.New("initial foundation operator is unavailable")
	}
	if err := operator.checkDeadline(ctx); err != nil {
		return err
	}
	principal, err := operator.factory.Provider().UserOCID()
	if err != nil || principal != operator.id {
		return errors.New("initial foundation operator identity changed")
	}
	tenancy, err := operator.factory.Provider().TenancyOCID()
	if err != nil || tenancy != operator.bundle.TenancyID {
		return errors.New("initial foundation operator tenancy changed")
	}
	resolver, err := verifyRetainedFoundation(ctx, operator.bundle, operator.genesis)
	if err != nil {
		return err
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return errors.New("initial foundation operator lacks its independent signed scope")
	}
	if err := operator.guardWorkloadOrigin(ctx, reader); err != nil {
		return err
	}
	// Missing discovery permits the initial provisioning sequence. An existing
	// different publication cannot be replaced by replaying an older bundle.
	for _, expected := range []struct {
		name string
		wire []byte
	}{
		{foundationRootChainObject, operator.bundle.RootChainWire},
		{strings.TrimSuffix(operator.domain.Prefix, "/") + "/" + foundationGrantObject, operator.bundle.GrantWire},
		{foundationDiscoveryObject, operator.bundle.AnchorWire},
	} {
		wire, err := readDiscoveryObject(ctx, operator.objects, operator.domain.Namespace, expected.name, int64(len(expected.wire)))
		if failure, ok := common.IsServiceError(err); ok && failure.GetHTTPStatusCode() == 404 {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(wire, expected.wire) {
			return errors.New("initial foundation operator bundle differs from published authority")
		}
	}
	return operator.checkDeadline(ctx)
}

func (operator *foundationOperator) checkDeadline(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if operator.deadline.IsZero() || !time.Now().Before(operator.deadline) {
		return errors.New("initial foundation signed authority expired")
	}
	return nil
}

func newOperatorHomeIAMAuthority(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, bundle RetainedFoundation) (*HomeIAMAuthority, FoundationResolver, error) {
	if ctx == nil || factory == nil || len(genesis) == 0 {
		return nil, FoundationResolver{}, errors.New("initial provisioning requires authenticated operator and independent roots")
	}
	resolver, err := verifyRetainedFoundation(ctx, bundle, genesis)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	principal, err := factory.Provider().UserOCID()
	if err != nil || !strings.HasPrefix(principal, "ocid1.user.oc1..") || len(principal) > 512 || strings.ContainsAny(principal, "\x00\r\n'\" ") {
		return nil, FoundationResolver{}, errors.New("initial provisioning requires the existing operator user principal")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != bundle.TenancyID {
		return nil, FoundationResolver{}, errors.New("initial provisioning differs from authenticated operator tenancy")
	}
	grant, err := decodeOriginalMaterialGrant(bundle)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	if grant.SchemaVersion == 3 {
		for _, intent := range grant.Regions {
			if intent.NetBirdManager != nil && (intent.NetBirdManager.Material == nil || intent.NetBirdManager.Material.Context.ProducerUserID != principal) {
				return nil, FoundationResolver{}, errors.New("initial user differs from original signed material producer")
			}
		}
	}
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return nil, FoundationResolver{}, errors.New("initial provisioning requires its verified signed foundation")
	}
	footprint, deadline, err := reader.verifyOriginalGrant(bundle.GrantWire)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	if reader.expires.Before(deadline) {
		deadline = reader.expires
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var target bootstrapmaterial.VaultTarget
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] == "GRU" && intent.BootstrapMaterial != nil {
			target = intent.BootstrapMaterial.SourceVaultTarget
		}
	}
	compartment := target.CompartmentOCID
	if target.Validate(foundationHomeRegion) != nil || !sourceCompartmentPattern.MatchString(compartment) {
		return nil, FoundationResolver{}, errors.New("initial provisioning lacks the signed existing home escrow compartment")
	}
	home, err := factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	kms := sdkcli.NewClient(home, "")
	vaults, err := kms.KMSVaults()
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	vault, err := vaults.GetVault(ociclient.RequestContext(ctx), keymanagement.GetVaultRequest{VaultId: new(target.VaultOCID)})
	if err != nil || deref(vault.Id) != target.VaultOCID || deref(vault.CompartmentId) != compartment || vault.LifecycleState != keymanagement.VaultLifecycleStateActive {
		return nil, FoundationResolver{}, errors.Join(errors.New("initial home storage Vault differs from signed escrow"), err)
	}
	management, err := kms.KMSManagement(deref(vault.ManagementEndpoint))
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	ledger, err := management.GetKey(ociclient.RequestContext(ctx), keymanagement.GetKeyRequest{KeyId: new(reader.storage.LedgerKMSKeyOCID)})
	if err != nil || deref(ledger.Id) != reader.storage.LedgerKMSKeyOCID || deref(ledger.CompartmentId) != compartment || deref(ledger.VaultId) != target.VaultOCID ||
		ledger.LifecycleState != keymanagement.KeyLifecycleStateEnabled || ledger.ProtectionMode != keymanagement.KeyProtectionModeHsm || ledger.KeyShape == nil ||
		ledger.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmAes || ledger.KeyShape.Length == nil || *ledger.KeyShape.Length != 32 {
		return nil, FoundationResolver{}, errors.Join(errors.New("initial ledger key is not enabled HSM AES-256 in the signed home escrow Vault and compartment"), err)
	}
	if grant.SchemaVersion == 3 {
		source, err := management.GetKey(ociclient.RequestContext(ctx), keymanagement.GetKeyRequest{KeyId: new(target.KMSKeyOCID)})
		if err != nil || deref(source.Id) != target.KMSKeyOCID || deref(source.CompartmentId) != compartment || deref(source.VaultId) != target.VaultOCID ||
			source.LifecycleState != keymanagement.KeyLifecycleStateEnabled || source.KeyShape == nil ||
			source.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmAes || source.KeyShape.Length == nil || *source.KeyShape.Length != 32 {
			return nil, FoundationResolver{}, errors.Join(errors.New("initial source key is not enabled AES-256 in the signed home escrow Vault and compartment"), err)
		}
	}
	objects, err := home.ObjectStorage()
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	store, err := NewObjectFoundationStore(&objects, reader.storage.Namespace, reader.storage.HeadBucket)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	resolver.Store, reader.factory, reader.client = store, home, &objects
	operator := &foundationOperator{factory: home, objects: &objects, genesis: genesis, bundle: bundle.clone(), domain: reader.storage, id: principal, deadline: deadline}
	authority := &HomeIAMAuthority{operator: operator, resolver: resolver, currentGenesis: genesis,
		tenancyID: tenancy, installationID: reader.home.InstallationID, grantDigest: reader.home.GrantSHA256, grantGeneration: reader.home.GrantGeneration}
	authority, err = authority.initialize(ctx, home, ctx, &objects, nil)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	if authority.bucketCompartment != compartment {
		return nil, FoundationResolver{}, errors.New("actual protected bucket is outside the signed home escrow compartment")
	}
	operator.buckets = make(map[string]string, 2)
	for _, bucket := range []struct{ role, name, key string }{
		{"head_bucket", reader.storage.HeadBucket, reader.storage.HeadKMSKeyOCID},
		{"ledger_bucket", reader.storage.LedgerBucket, reader.storage.LedgerKMSKeyOCID},
	} {
		response, err := objects.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(reader.storage.Namespace), BucketName: new(bucket.name)})
		if err != nil || deref(response.Name) != bucket.name || deref(response.Namespace) != reader.storage.Namespace ||
			deref(response.CompartmentId) != compartment || deref(response.KmsKeyId) != bucket.key || !validAuxiliaryID(bucket.role, deref(response.Id), foundationHomeRegion) {
			return nil, FoundationResolver{}, errors.Join(errors.New("initial home bucket prerequisite differs from signed storage"), err)
		}
		operator.buckets[bucket.role] = deref(response.Id)
	}
	if grant.SchemaVersion == 3 {
		birth, err := operator.originalSourceProducerBirth(grant)
		if err != nil {
			return nil, FoundationResolver{}, err
		}
		store.originalSourceBirth = &birth
	}
	if err := operator.guard(ctx); err != nil {
		return nil, FoundationResolver{}, err
	}
	return authority, resolver, nil
}
