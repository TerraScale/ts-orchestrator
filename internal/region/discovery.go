package region

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const foundationHomeRegion = "sa-saopaulo-1"
const foundationDiscoveryBucket = "gru-1-head"
const foundationDiscoveryObject = "orchestrator/foundation/v1/anchor.json"

var ErrFoundationDiscoveryPending = errors.New("authenticated foundation discovery is pending")

type foundationDiscoveryObjects interface {
	FoundationObjects
	GetNamespace(context.Context, objectstorage.GetNamespaceRequest) (objectstorage.GetNamespaceResponse, error)
}

// DiscoverFoundation locates the production home anchor without a local anchor
// or host installation. The fixed OCI location is only an untrusted locator;
// independent roots and the authenticated tenancy remain mandatory.
func DiscoverFoundation(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring) (FoundationResolver, error) {
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil {
		return FoundationResolver{}, err
	}
	return discoverFoundation(ctx, client, tenancy, roots)
}

func foundationHomeClient(factory *ociclient.Factory) (*objectstorage.ObjectStorageClient, string, error) {
	if factory == nil {
		return nil, "", fmt.Errorf("%w: authenticated OCI caller is absent", ErrFoundationDiscoveryPending)
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy == "" {
		return nil, "", fmt.Errorf("%w: authenticated tenancy is absent", ErrFoundationDiscoveryPending)
	}
	home, err := factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return nil, "", err
	}
	client, err := home.ObjectStorage()
	return &client, tenancy, err
}

func discoveryNamespace(ctx context.Context, client foundationDiscoveryObjects, tenancy string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{CompartmentId: new(tenancy)})
	if err != nil || response.Value == nil || *response.Value == "" || strings.ContainsAny(*response.Value, "/\\\r\n") {
		return "", fmt.Errorf("%w: caller's home storage namespace is unavailable", ErrFoundationDiscoveryPending)
	}
	return *response.Value, nil
}

func discoverFoundation(ctx context.Context, client foundationDiscoveryObjects, tenancy string, roots trust.Keyring) (FoundationResolver, error) {
	if len(roots) == 0 {
		return FoundationResolver{}, fmt.Errorf("%w: independent trusted roots are absent", ErrFoundationDiscoveryPending)
	}
	namespace, err := discoveryNamespace(ctx, client, tenancy)
	if err != nil {
		return FoundationResolver{}, err
	}
	wire, err := readDiscoveryObject(ctx, client, namespace, foundationDiscoveryObject, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return FoundationResolver{}, fmt.Errorf("%w: current signed home anchor is unavailable", ErrFoundationDiscoveryPending)
	}
	anchor, err := verifyDiscoveryAnchor(wire, roots, tenancy, namespace)
	if err != nil {
		return FoundationResolver{}, err
	}
	reader, err := NewSignedFootprint(client, anchor, roots, tenancy)
	if err != nil {
		return FoundationResolver{}, err
	}
	if _, err := reader.AuthorizedRegions(ctx); err != nil {
		return FoundationResolver{}, err
	}
	store, err := NewObjectFoundationStore(client, namespace, foundationDiscoveryBucket)
	if err != nil {
		return FoundationResolver{}, err
	}
	return FoundationResolver{Footprint: reader, Store: store}, nil
}

func verifyDiscoveryAnchor(wire []byte, roots trust.Keyring, tenancy, namespace string) (bootstrap.VerifiedBootstrapAnchor, error) {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, err
	}
	// DeploymentID selects only the root-signature scope; no fact in this
	// envelope is trusted until verification and caller-tenancy checks finish.
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: envelope.Scope.DeploymentID, Cell: oci.RegionGRU, Environment: "production"}, time.Now(), bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, err
	}
	home, err := anchor.FoundationScope()
	if err != nil {
		return bootstrap.VerifiedBootstrapAnchor{}, err
	}
	if home.TenancyID != tenancy || home.OCIRegion != foundationHomeRegion || home.StorageDomain.Namespace != namespace || home.StorageDomain.HeadBucket != foundationDiscoveryBucket {
		return bootstrap.VerifiedBootstrapAnchor{}, errors.New("signed home discovery differs from authenticated tenancy or fixed storage location")
	}
	return anchor, nil
}

func readDiscoveryObject(ctx context.Context, client FoundationObjects, namespace, name string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(namespace), BucketName: new(foundationDiscoveryBucket), ObjectName: new(name)})
	if err != nil {
		return nil, err
	}
	if response.Content == nil {
		return nil, errors.New("signed discovery object has no content")
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, limit+1))
	if err != nil || len(wire) > int(limit) {
		return nil, errors.New("signed discovery object is unreadable or oversized")
	}
	return wire, nil
}

// PublishFoundationDiscovery conditionally publishes already root-signed public
// grant bytes, then their anchor. It creates no bucket, IAM, root, or secret.
// Existing different objects are immutable; uncertain outcomes recover only
// through an exact read of the same bytes.
func PublishFoundationDiscovery(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, anchorWire, grantWire []byte) error {
	client, tenancy, err := foundationHomeClient(factory)
	if err != nil {
		return err
	}
	return publishFoundationDiscovery(ctx, client, tenancy, roots, anchorWire, grantWire)
}

func publishFoundationDiscovery(ctx context.Context, client foundationDiscoveryObjects, tenancy string, roots trust.Keyring, anchorWire, grantWire []byte) error {
	if len(roots) == 0 {
		return errors.New("initial publication requires independent trusted roots")
	}
	namespace, err := discoveryNamespace(ctx, client, tenancy)
	if err != nil {
		return err
	}
	anchor, err := verifyDiscoveryAnchor(anchorWire, roots, tenancy, namespace)
	if err != nil {
		return err
	}
	reader, err := NewSignedFootprint(client, anchor, roots, tenancy)
	if err != nil {
		return err
	}
	if _, _, err := reader.verifyGrant(grantWire); err != nil {
		return err
	}
	grantName := strings.TrimSuffix(reader.storage.Prefix, "/") + "/" + foundationGrantObject
	for _, object := range []struct {
		name string
		wire []byte
	}{{grantName, grantWire}, {foundationDiscoveryObject, anchorWire}} {
		policy := common.NoRetryPolicy()
		request := objectstorage.PutObjectRequest{NamespaceName: new(namespace), BucketName: new(foundationDiscoveryBucket), ObjectName: new(object.name), IfNoneMatch: new("*"), ContentType: new("application/json"), ContentLength: new(int64(len(object.wire))), PutObjectBody: io.NopCloser(bytes.NewReader(object.wire)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, writeErr := client.PutObject(ociclient.RequestContext(writeCtx), request)
		cancel()
		if writeErr == nil {
			continue
		}
		observed, readErr := readDiscoveryObject(ctx, client, namespace, object.name, foundationRecordLimit)
		if readErr != nil || !bytes.Equal(observed, object.wire) {
			return fmt.Errorf("initial foundation publication did not establish the exact immutable object: %w", writeErr)
		}
	}
	return nil
}
