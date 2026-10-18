package app

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func currentContainerAllocations(ctx context.Context, factory *ociclient.Factory, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
	if ctx == nil || factory == nil {
		return release.SequenceLocation{}, errors.New("container allocation requires context and OCI credentials")
	}
	if err := ctx.Err(); err != nil {
		return release.SequenceLocation{}, err
	}
	var namespace, bucket, home string
	var genesis release.VerifiedWorkloadGenesis
	if len(bundle.Migration) == 0 {
		if !target.Genesis.IsVerified() {
			var err error
			target.Genesis, err = currentContainerWorkloadGenesis(ctx, factory, roots, target)
			if err != nil {
				return release.SequenceLocation{}, err
			}
		}
		if !target.Genesis.Allows(target) {
			return release.SequenceLocation{}, errors.New("container allocation requires independently verified workload genesis")
		}
		origin := target.Genesis.Origin()
		namespace, bucket, home, genesis = origin.Namespace, origin.Bucket, "GRU", target.Genesis
	} else {
		envelope, err := trust.DecodeEnvelope(bundle.Migration)
		if err != nil {
			return release.SequenceLocation{}, err
		}
		// Established migrations retain authority after their submission envelope expires.
		migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, target.Role, target.Environment)
		if err != nil {
			return release.SequenceLocation{}, err
		}
		namespace, bucket, home = migration.Namespace, migration.Bucket, migration.Region
	}
	entry, ok := catalog.Lookup(home)
	if !ok {
		return release.SequenceLocation{}, errors.New("container allocation origin has no OCI region")
	}
	regional, err := factory.ForRegion(entry.OCIRegion)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	client, err := regional.ObjectStorage()
	if err != nil {
		return release.SequenceLocation{}, err
	}
	return release.SequenceLocation{Client: containerAllocationReader{client: client}, Namespace: namespace, Bucket: bucket, Genesis: genesis}, nil
}

func currentContainerWorkloadGenesis(ctx context.Context, factory *ociclient.Factory, roots trust.Keyring, target release.ContainerTarget) (release.VerifiedWorkloadGenesis, error) {
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	founders, err := currentControllerHostReader(ctx)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	current, err := founders.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	foundation, err := region.NewFoundationDiscovery(factory, current.Anchor(), roots)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	_, original, err := foundation.WorkloadGenesis(ctx, target.Cell, target.Role, target.Environment)
	if err != nil {
		return release.VerifiedWorkloadGenesis{}, err
	}
	return region.VerifyWorkloadGenesisEvidence(original, inputs.Genesis, current.Anchor(), target.Cell, target.Role, target.Environment)
}

type containerAllocationReader struct {
	client objectstorage.ObjectStorageClient
}

func (reader containerAllocationReader) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	return reader.client.GetObject(ctx, request)
}

func (containerAllocationReader) PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return objectstorage.PutObjectResponse{}, errors.New("runtime container allocation verification cannot write release sequences")
}
