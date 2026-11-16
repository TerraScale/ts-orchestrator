package imageimport

import (
	"context"
)

// ObjectUploader retains the streaming byte/digest and multipart cleanup checks
// while accepting a concrete SDK client with a caller's request interceptor.
type ObjectUploader interface {
	HeadObject(ctx context.Context, namespace, bucket, object string) (bool, map[string]string, error)
	UploadObject(ctx context.Context, request UploadRequest) error
}
