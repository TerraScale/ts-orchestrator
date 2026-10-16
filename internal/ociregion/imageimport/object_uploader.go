package imageimport

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/workrequests"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// ObjectUploader retains the streaming byte/digest and multipart cleanup checks
// while accepting a concrete SDK client with a caller's request interceptor.
type ObjectUploader interface {
	HeadObject(ctx context.Context, namespace, bucket, object string) (bool, map[string]string, error)
	UploadObject(ctx context.Context, request UploadRequest) error
}

func NewObjectUploader(objects objectstorage.ObjectStorageClient) ObjectUploader {
	return &sdkClient{objects: objects, uploadRetry: ociclient.IdempotentPutRetryPolicy(ociclient.RetryOptions{})}
}

// NewClientFromSDK preserves the importer contract with already configured SDK
// clients, including request interceptors that revalidate disposable confinement.
func NewClientFromSDK(compute core.ComputeClient, objects objectstorage.ObjectStorageClient, work workrequests.WorkRequestClient) API {
	return &sdkClient{compute: compute, objects: objects, workRequest: work, uploadRetry: ociclient.IdempotentPutRetryPolicy(ociclient.RetryOptions{})}
}
