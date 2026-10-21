package region

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var (
	ErrOriginalFoundationDelivery         = errors.New("original public foundation bundle delivery refused")
	ErrOriginalFoundationAdmissionPending = errors.New("original startup binding, local custody, source archive and runtime admission are pending")
)

// OriginalFoundationAdmissionPendingError reports public delivery, never source
// custody or permission to start a controller.
type OriginalFoundationAdmissionPendingError struct {
	BundleSHA256 string
}

func (hold *OriginalFoundationAdmissionPendingError) Error() string {
	return ErrOriginalFoundationAdmissionPending.Error()
}

func (hold *OriginalFoundationAdmissionPendingError) Unwrap() error {
	return ErrOriginalFoundationAdmissionPending
}

// DeliverOriginalFoundationPublic is the automatic original actor entry point.
// Only a descriptor without original bundle data may continue ordinary startup.
func DeliverOriginalFoundationPublic(ctx context.Context) error {
	imds := bootstrapstart.NewIMDSClient()
	digest, err := imds.FetchOriginalBundleSHA256(ctx)
	if err != nil || digest == "" {
		return err
	}
	instance, err := imds.FetchInstanceID(ctx)
	if err != nil {
		return errors.Join(ErrOriginalFoundationDelivery, err)
	}
	parts := strings.Split(instance, ".")
	if len(parts) != 5 {
		return ErrOriginalFoundationDelivery
	}
	entry, ok := catalog.CellForOCIRegion(parts[3])
	if !ok {
		return ErrOriginalFoundationDelivery
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, entry.OCIRegion)
	if err != nil {
		return errors.Join(ErrOriginalFoundationDelivery, err)
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	wire, err := readOriginalFoundationPublic(ctx, factory, instance, entry.Cell, digest, genesis)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := bootstrapstart.InstallOriginalFoundationPublic(wire); err != nil {
		return errors.Join(ErrOriginalFoundationDelivery, err)
	}
	return &OriginalFoundationAdmissionPendingError{BundleSHA256: digest}
}

func readOriginalFoundationPublic(ctx context.Context, factory *ociclient.Factory, instance, cell, digest string, genesis trust.Keyring) ([]byte, error) {
	if factory == nil {
		return nil, ErrOriginalFoundationDelivery
	}
	parts := strings.Split(instance, ".")
	if len(parts) != 5 || parts[3] != factory.Region() {
		return nil, ErrOriginalFoundationDelivery
	}
	entry, ok := catalog.CellForOCIRegion(parts[3])
	if !ok || entry.Cell != cell {
		return nil, ErrOriginalFoundationDelivery
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	if err := bootstrapstart.VerifyInstancePrincipal(factory, instance, tenancy); err != nil {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	client, authenticatedTenancy, err := foundationHomeClient(factory)
	if err != nil || authenticatedTenancy != tenancy {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	// These actual SDK reads authenticate the provider whose local token claims
	// were checked above; parsing those claims alone supplies no authority.
	// CompartmentId would require namespace-read IAM absent from the immutable
	// exact-object birth policy. The caller's own namespace needs no such grant.
	namespaceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	response, err := client.GetNamespace(ociclient.RequestContext(namespaceCtx), objectstorage.GetNamespaceRequest{})
	namespaceErr := namespaceCtx.Err()
	cancel()
	if err != nil || namespaceErr != nil || response.Value == nil || *response.Value == "" ||
		len(*response.Value) > 255 || strings.ContainsAny(*response.Value, "/\\ \t\r\n") {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err, namespaceErr)
	}
	namespace := *response.Value
	key, err := release.WorkloadGenesisObject(tenancy, cell, "production", "ts-auth")
	if err != nil {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	wire, err := readDiscoveryObject(ctx, client, namespace, key, bootstrapstart.MaxOriginalFoundationPublicBytes)
	if err != nil {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	bundle, err := originalFoundationPublicScope(wire, tenancy, namespace, cell, digest)
	if err != nil {
		return nil, err
	}
	// The full verifier can adopt durable lineage floors. Hash and exact scope
	// checks must finish first; successful verification still grants no startup.
	if err := VerifyFoundationProvisionBundle(ctx, genesis, bundle); err != nil {
		return nil, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	return wire, nil
}

func originalFoundationPublicScope(wire []byte, tenancy, namespace, cell, digest string) (RetainedFoundation, error) {
	var bundle RetainedFoundation
	if len(wire) == 0 || len(wire) > bootstrapstart.MaxOriginalFoundationPublicBytes || digestSource(wire) != digest ||
		protocol.DecodeStrict(wire, &bundle, bootstrapstart.MaxOriginalFoundationPublicBytes) != nil {
		return bundle, fmt.Errorf("%w: bundle bytes or digest differ", ErrOriginalFoundationDelivery)
	}
	canonical, err := protocol.EncodeJSON(bundle)
	if err != nil || !bytes.Equal(wire, canonical) || bundle.TenancyID != tenancy || bundle.Namespace != namespace {
		return bundle, fmt.Errorf("%w: bundle differs from canonical authenticated scope", ErrOriginalFoundationDelivery)
	}
	for _, signed := range [][]byte{bundle.AnchorWire, bundle.GrantWire} {
		envelope, err := trust.DecodeEnvelope(signed)
		if err != nil || envelope.Scope.Cell != "GRU" || envelope.Scope.Environment != "production" {
			return bundle, fmt.Errorf("%w: signed home production scope differs", ErrOriginalFoundationDelivery)
		}
	}
	grant, err := decodeOriginalMaterialGrant(bundle)
	if err != nil || grant.TenancyID != tenancy {
		return bundle, errors.Join(ErrOriginalFoundationDelivery, err)
	}
	var regional *BootstrapMaterialIntent
	for _, intent := range grant.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		if regional != nil || intent.BootstrapMaterial == nil {
			return bundle, ErrOriginalFoundationDelivery
		}
		regional = intent.BootstrapMaterial
	}
	if regional == nil {
		return bundle, ErrOriginalFoundationDelivery
	}
	entry, ok := catalog.CellForOCIRegion(regional.Config.Region)
	if !ok || entry.Cell != cell || regional.Config.Cell != strings.ToLower(cell) ||
		regional.Config.Environment != "production" || regional.Startup == nil || regional.Startup.SeedSlot != "controller-a" {
		return bundle, fmt.Errorf("%w: regional production startup scope differs", ErrOriginalFoundationDelivery)
	}
	var origin release.WorkloadGenesis
	origins := 0
	for _, candidate := range grant.WorkloadGenesis {
		if candidate.Cell == cell && candidate.Environment == "production" && candidate.Role == "ts-auth" {
			origins++
			if origins > 1 {
				return bundle, ErrOriginalFoundationDelivery
			}
			origin = candidate
		}
	}
	if origin.Validate() != nil || origin.TenancyID != tenancy || origin.Namespace != namespace || origin.Bucket != foundationDiscoveryBucket ||
		origin.InstallationID != grant.InstallationID || origin.InstallationID != regional.InstallationID ||
		origin.DeploymentID != regional.Config.DeploymentID || origin.ClusterID != regional.Config.ClusterID {
		return bundle, fmt.Errorf("%w: exact original ts-auth scope differs", ErrOriginalFoundationDelivery)
	}
	return bundle, nil
}
