package region

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const foundationHomeRegion = "sa-saopaulo-1"
const foundationDiscoveryBucket = "gru-1-head"
const foundationDiscoveryObject = "orchestrator/foundation/v1/anchor.json"
const foundationRootChainObject = "orchestrator/foundation/v1/root-chain.json"

var ErrFoundationDiscoveryPending = errors.New("authenticated foundation discovery is pending")

type foundationDiscoveryObjects interface {
	FoundationObjects
	GetNamespace(context.Context, objectstorage.GetNamespaceRequest) (objectstorage.GetNamespaceResponse, error)
}

func discoveryNamespace(ctx context.Context, client foundationDiscoveryObjects, tenancy string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{CompartmentId: new(tenancy)})
	if err != nil || response.Value == nil || *response.Value == "" || strings.ContainsAny(*response.Value, "/\\\r\n") {
		return "", errors.Join(fmt.Errorf("%w: caller's home storage namespace is unavailable", ErrFoundationDiscoveryPending), err, ctx.Err())
	}
	return *response.Value, nil
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
