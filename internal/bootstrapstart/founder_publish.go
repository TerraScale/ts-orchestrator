package bootstrapstart

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type FounderSelectionObjectWriter interface {
	FounderSelectionObjectReader
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}
