package kvsnapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// ErrConflict means the snapshot object changed between its read and the
// conditional write; the next pass reads it again.
var ErrConflict = errors.New("kv snapshot object changed concurrently")

type serviceError interface {
	error
	common.ServiceError
}

// ObjectClient is the Object Storage subset the snapshots use.
type ObjectClient interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

// Objects reads and conditionally writes one cell's snapshot objects.
type Objects struct {
	Client ObjectClient
	Config Config
	Cell   string
}

// NewInstancePrincipalObjects builds the controller's Object Storage access
// from its instance principal.
func NewInstancePrincipalObjects(config Config, cell string) (*Objects, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	factory, err := ociclient.InstancePrincipal(config.Region)
	if err != nil {
		return nil, err
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	return &Objects{Client: client, Config: config, Cell: cell}, nil
}

// Get returns the bucket's snapshot and its ETag. Only OCI's ObjectNotFound
// reports an absent snapshot; a missing bucket or a refused grant, which OCI
// also answers with 404, is an error, so a restore never mistakes an
// unreadable snapshot for an empty one.
func (objects *Objects) Get(ctx context.Context, bucket string) (Document, string, bool, error) {
	response, err := objects.Client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: new(objects.Config.Namespace), BucketName: new(objects.Config.Bucket),
		ObjectName: new(objects.Config.objectName(objects.Cell, bucket)),
	})
	if err != nil {
		if serviceErr, ok := errors.AsType[serviceError](err); ok &&
			serviceErr.GetHTTPStatusCode() == http.StatusNotFound && serviceErr.GetCode() == "ObjectNotFound" {
			return Document{}, "", false, nil
		}
		return Document{}, "", false, fmt.Errorf("read kv snapshot of %s: %w", bucket, err)
	}
	if response.Content == nil {
		return Document{}, "", false, fmt.Errorf("kv snapshot of %s has no body", bucket)
	}
	data, err := io.ReadAll(io.LimitReader(response.Content, maxDocumentBytes+1))
	if err = errors.Join(err, response.Content.Close()); err != nil {
		return Document{}, "", false, fmt.Errorf("read kv snapshot of %s: %w", bucket, err)
	}
	if response.ETag == nil || *response.ETag == "" ||
		response.ContentLength == nil || *response.ContentLength != int64(len(data)) {
		return Document{}, "", false, fmt.Errorf("kv snapshot of %s lacks its ETag or was truncated", bucket)
	}
	document, err := decodeDocument(data, objects.Cell, bucket)
	if err != nil {
		return Document{}, "", false, err
	}
	return document, *response.ETag, true, nil
}

// Put writes document only while the object still has etag, or only while
// it is absent when etag is empty, and returns the new ETag. OCI checks the
// body against its SHA-256.
func (objects *Objects) Put(ctx context.Context, document Document, etag string) (string, error) {
	data, err := encodeDocument(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	request := objectstorage.PutObjectRequest{
		NamespaceName: new(objects.Config.Namespace), BucketName: new(objects.Config.Bucket),
		ObjectName:    new(objects.Config.objectName(objects.Cell, document.Bucket)),
		PutObjectBody: io.NopCloser(bytes.NewReader(data)), ContentLength: new(int64(len(data))),
		ContentType:          new("application/json"),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
	}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(etag)
	}
	if objects.Config.KMSKeyID != "" {
		request.OpcSseKmsKeyId = new(objects.Config.KMSKeyID)
	}
	response, err := objects.Client.PutObject(ctx, request)
	if err != nil {
		if serviceErr, ok := errors.AsType[serviceError](err); ok &&
			serviceErr.GetHTTPStatusCode() == http.StatusPreconditionFailed {
			return "", ErrConflict
		}
		return "", fmt.Errorf("write kv snapshot of %s: %w", document.Bucket, err)
	}
	if response.ETag == nil || *response.ETag == "" {
		return "", fmt.Errorf("kv snapshot write of %s returned no ETag", document.Bucket)
	}
	return *response.ETag, nil
}
