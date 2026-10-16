package app

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
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
	envelope, err := trust.DecodeEnvelope(bundle.Migration)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	// Established migrations retain authority after their submission envelope expires.
	migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, target.Role, target.Environment)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	entry, ok := catalog.Lookup(migration.Region)
	if !ok {
		return release.SequenceLocation{}, errors.New("container allocation migration has no OCI region")
	}
	regional, err := factory.ForRegion(entry.OCIRegion)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	client, err := regional.ObjectStorage()
	if err != nil {
		return release.SequenceLocation{}, err
	}
	return release.SequenceLocation{Client: containerAllocationReader{client: client}, Namespace: migration.Namespace, Bucket: migration.Bucket}, nil
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
