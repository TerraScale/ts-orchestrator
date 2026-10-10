package bootstrapstart

import (
	"context"
	"errors"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type ambiguousFounderPublisher struct {
	store *founderLedgerObjects
}

func (publisher ambiguousFounderPublisher) GetObject(ctx context.Context,
	request objectstorage.GetObjectRequest,
) (objectstorage.GetObjectResponse, error) {
	return publisher.store.GetObject(ctx, request)
}

func (publisher ambiguousFounderPublisher) PutObject(ctx context.Context,
	request objectstorage.PutObjectRequest,
) (objectstorage.PutObjectResponse, error) {
	response, err := publisher.store.PutObject(ctx, request)
	if err == nil && strings.HasSuffix(*request.ObjectName, "/current.json") {
		return response, errors.New("response lost after selector CAS")
	}
	return response, err
}
