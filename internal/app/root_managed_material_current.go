//go:build linux

package app

import (
	"context"
	"os"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func (service *rootWorkloadCredentials) ManagedMaterialCurrent(ctx context.Context, call rootoci.Call,
	request rootoci.ManagedMaterialCurrentRequest,
) (rootoci.ManagedMaterialCurrentReceipt, error) {
	fail := func() (rootoci.ManagedMaterialCurrentReceipt, error) {
		return rootoci.ManagedMaterialCurrentReceipt{}, rootoci.ErrUnauthorized
	}
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || service == nil || service.admission == nil ||
		call.Operation() != rootoci.OperationManagedMaterialCurrent || !entityid.Valid(request.DatabaseID) ||
		!entityid.Valid(request.PartitionID) || !time.Now().Before(call.Deadline()) {
		return fail()
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, set := os.LookupEnv(name); set {
			return fail()
		}
	}
	original := ctx
	ctx, cancel := context.WithDeadline(ctx, call.Deadline())
	defer cancel()
	if call.Guard(ctx) != nil {
		return fail()
	}
	controller, _, err := service.admission.readers(ctx, call)
	if err != nil {
		return fail()
	}
	config := controller.config
	ctx = config.credentialContext
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return fail()
	}
	managed, err := loadManagedControllerConfig(cfg)
	if err != nil || managed == nil || config.Specs.ociRegion == nil || !reflect.DeepEqual(managed.region, *config.Specs.ociRegion) {
		return fail()
	}
	material, err := acceptedMaterialConfigFromMarker(config.Accepted, cfg.NATS.Cell, managed.region)
	if err != nil {
		return fail()
	}
	lease, err := config.Mutations.AdmitRuntimeLease(ctx, config.Specs.identity.DeploymentID, call.RuntimeID())
	if err != nil {
		return fail()
	}
	rootKV, err := config.JS.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return fail()
	}
	root, err := rootKV.Get(ctx, rootChainKey)
	if err != nil || root == nil || root.Operation() != jetstream.KeyValuePut {
		return fail()
	}
	chain, err := trust.DecodeRootChain(root.Value())
	if err != nil {
		return fail()
	}
	roots, err := trust.VerifyRootChain(config.Specs.roots.genesis, config.Specs.roots.identity, chain)
	if err != nil || roots.Head != config.Specs.roots.reply("").Head {
		return fail()
	}
	spec, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil || spec == nil || spec.Operation() != jetstream.KeyValuePut || spec.Revision() != config.Specs.revision {
		return fail()
	}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Done() == nil || ctx.Err() != nil || config.credentialSource == nil {
		return fail()
	}
	deadline = earlier(deadline, earlier(call.Deadline(), lease.Deadline()))
	if !config.releaseDeadline.IsZero() {
		deadline = earlier(deadline, config.releaseDeadline)
	}
	credentialContext := ctx
	ctx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	guard := func(ctx context.Context) error {
		if ctx == nil || ctx.Err() != nil || original.Err() != nil || credentialContext.Err() != nil || !time.Now().Before(deadline) ||
			call.Guard(ctx) != nil || config.credentialSource.Guard(ctx) != nil || lease.Guard(ctx) != nil ||
			rootTrustChainCurrent(ctx, config.JS, root) != nil || controllerHostSpecCurrent(ctx, config.JS, config.Specs, spec, roots.Head) != nil {
			return rootoci.ErrUnauthorized
		}
		accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
		if err != nil || !reflect.DeepEqual(accepted, config.Accepted) {
			return rootoci.ErrUnauthorized
		}
		current, err := loadManagedControllerConfig(cfg)
		if err != nil || !reflect.DeepEqual(current, managed) || call.Guard(ctx) != nil || config.credentialSource.Guard(ctx) != nil ||
			lease.Guard(ctx) != nil || ctx.Err() != nil || original.Err() != nil || credentialContext.Err() != nil || !time.Now().Before(deadline) {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if guard(ctx) != nil {
		return fail()
	}
	region, err := material.repository.Region.OCIRegion()
	if err != nil {
		return fail()
	}
	factory, err := service.admission.factory.ForRegion(region)
	if err != nil {
		return fail()
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		return fail()
	}
	reader, err := managedmaterial.NewPreparationReader(material.repository, managedCurrentObjects{ObjectClient: &client}, config.Mutations, config.ResponsePublic, material.subnetCIDR)
	if err != nil {
		return fail()
	}
	ctx = ociclient.WithRequestGuard(ctx, guard)
	originalReceipt, err := config.Mutations.ReadMaterialReceipt(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return fail()
	}
	preparation, err := reader.Current(ctx, request.DatabaseID, request.PartitionID)
	if err != nil || guard(ctx) != nil {
		return fail()
	}
	result := rootoci.ManagedMaterialCurrentReceipt{Preparation: preparation, ExpiresAt: deadline}
	wire, err := protocol.EncodeJSON(result)
	if err != nil || len(wire) > rootoci.MaxManagedMaterialCurrentBytes || guard(ctx) != nil {
		return fail()
	}
	currentReceipt, err := config.Mutations.ReadMaterialReceipt(ctx, request.DatabaseID, request.PartitionID)
	if err != nil || !reflect.DeepEqual(originalReceipt, currentReceipt) || guard(ctx) != nil || call.Guard(ctx) != nil ||
		config.credentialSource.Guard(ctx) != nil || lease.Guard(ctx) != nil || ctx.Err() != nil || original.Err() != nil ||
		credentialContext.Err() != nil || !time.Now().Before(deadline) {
		return fail()
	}
	return result, nil
}

// Only the SDK retry loop receives RequestContext; R3 and final lifetime checks
// keep the original cancellable context and deadline.
type managedCurrentObjects struct {
	managedmaterial.ObjectClient
}

func (client managedCurrentObjects) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	return client.ObjectClient.GetObject(ociclient.RequestContext(ctx), request)
}
