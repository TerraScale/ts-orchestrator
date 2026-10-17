package region

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
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
	if _, err := verifyRetainedFoundation(ctx, operator.bundle, operator.genesis); err != nil {
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
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok {
		return nil, FoundationResolver{}, errors.New("initial provisioning requires its verified signed foundation")
	}
	footprint, deadline, err := reader.authorizedRegions(ctx)
	if err != nil {
		return nil, FoundationResolver{}, err
	}
	if reader.expires.Before(deadline) {
		deadline = reader.expires
	}
	var compartment string
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] == "GRU" && intent.BootstrapMaterial != nil {
			compartment = intent.BootstrapMaterial.SourceVaultTarget.CompartmentOCID
		}
	}
	if !sourceCompartmentPattern.MatchString(compartment) {
		return nil, FoundationResolver{}, errors.New("initial provisioning lacks the signed existing home escrow compartment")
	}
	home, err := factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return nil, FoundationResolver{}, err
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
	if err := operator.guard(ctx); err != nil {
		return nil, FoundationResolver{}, err
	}
	return authority, resolver, nil
}
