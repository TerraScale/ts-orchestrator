package managedmaterial

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type floorReadObjectClient struct {
	ObjectClient
	duringRead func()
}

func (client *floorReadObjectClient) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if hook := client.duringRead; hook != nil {
		client.duringRead = nil
		hook()
	}
	return client.ObjectClient.GetObject(ctx, request)
}
