package ociclient

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type objectReader interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

// ReadObject joins SDK retry work while retaining cancellation at the HTTP boundary.
// Other implementations receive the original context and own their cancellation.
func ReadObject(ctx context.Context, client objectReader, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	switch sdk := client.(type) {
	case objectstorage.ObjectStorageClient:
		ConfigureReadCancellation(&sdk.BaseClient)
		return sdk.GetObject(ReadContext(ctx), request)
	case *objectstorage.ObjectStorageClient:
		copy := *sdk
		ConfigureReadCancellation(&copy.BaseClient)
		return copy.GetObject(ReadContext(ctx), request)
	default:
		return client.GetObject(ctx, request)
	}
}
