package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

type OCIObjectStorageAdapter struct {
	ObjectStorage *OCIHTTPTransport
	Journal       ProviderMutationJournal
}

func NewOCIObjectStorageAdapter(transport *OCIHTTPTransport, journal ProviderMutationJournal) (*OCIObjectStorageAdapter, error) {
	if err := validateOCIAdapter(transport, OCIServiceObjectStorage, journal); err != nil {
		return nil, err
	}
	return &OCIObjectStorageAdapter{ObjectStorage: transport, Journal: journal}, nil
}

func validateObjectRef(object ObjectRef) error {
	if len(object.Namespace) < 1 || len(object.Namespace) > 128 || len(object.Bucket) < 1 || len(object.Bucket) > 256 ||
		len(object.Name) < 1 || len(object.Name) > 1024 || strings.ContainsAny(object.Namespace+object.Bucket+object.Name, "\r\n") ||
		strings.Contains(object.Namespace, "/") || strings.Contains(object.Bucket, "/") {
		return &errs.Argument{Message: "object storage identity is invalid"}
	}
	return nil
}

func objectStoragePath(object ObjectRef) string {
	return "/n/" + url.PathEscape(object.Namespace) + "/b/" + url.PathEscape(object.Bucket) + "/o/" + url.PathEscape(object.Name)
}

func objectPutBinding(request ObjectPutRequest) any {
	return struct {
		Object ObjectRef
		SHA256 string
		Size   int
	}{request.Object, request.SHA256, len(request.Content)}
}

func ObjectPutMutationFingerprint(request ObjectPutRequest) string {
	return fingerprintJSON("object.put", objectPutBinding(request))
}

func ObjectPutMutationScope(request ObjectPutRequest) string {
	return ProviderMutationScope("object", request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func (a *OCIObjectStorageAdapter) PutObject(ctx context.Context, request ObjectPutRequest) (ObjectMetadata, error) {
	if a == nil || validateOCIAdapter(a.ObjectStorage, OCIServiceObjectStorage, a.Journal) != nil {
		return ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(request.Object); err != nil {
		return ObjectMetadata{}, err
	}
	if len(request.Content) == 0 || int64(len(request.Content)) > a.ObjectStorage.Config.MaxBodyBytes || !validSHA256Hex(request.SHA256) || objectSHA256(request.Content) != request.SHA256 {
		return ObjectMetadata{}, &errs.Argument{Message: "object storage content binding is invalid"}
	}
	if err := expectJSONMutation(request.Mutation, "object.put", ObjectPutMutationScope(request), objectPutBinding(request)); err != nil {
		return ObjectMetadata{}, err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return ObjectMetadata{}, err
	}
	if result, done, err := completedMutation(record); done {
		if err != nil {
			return ObjectMetadata{}, err
		}
		return ObjectMetadata{ETag: result.ETag, SHA256: request.SHA256, Size: int64(len(request.Content))}, nil
	}
	if record.State == MutationSubmitted || record.State == MutationUnknown {
		metadata, found, err := a.HeadObject(ctx, request.Object)
		if err != nil {
			return ObjectMetadata{}, err
		}
		if !found || metadata.SHA256 != request.SHA256 || metadata.Size != int64(len(request.Content)) {
			return ObjectMetadata{}, &ProviderOutcomeUnknownError{}
		}
		if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
			return ObjectMetadata{}, err
		}
		return metadata, nil
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return ObjectMetadata{}, err
	}
	resp, err := a.ObjectStorage.DoWithHeaders(ctx, http.MethodPut, objectStoragePath(request.Object), bytes.NewReader(request.Content), map[string]string{
		"Content-Type":               "application/octet-stream",
		"If-None-Match":              "*",
		"opc-meta-terrascale-sha256": request.SHA256,
	})
	if err != nil {
		if IsOutcomeIndeterminate(err) {
			metadata, found, readErr := a.HeadObject(ctx, request.Object)
			if readErr == nil && found && metadata.SHA256 == request.SHA256 && metadata.Size == int64(len(request.Content)) {
				if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
					return ObjectMetadata{}, err
				}
				return metadata, nil
			}
			return ObjectMetadata{}, finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return ObjectMetadata{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusPreconditionFailed {
			drainClose(resp.Body)
			metadata, found, readErr := a.HeadObject(ctx, request.Object)
			if readErr == nil && found && metadata.SHA256 == request.SHA256 && metadata.Size == int64(len(request.Content)) {
				if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
					return ObjectMetadata{}, err
				}
				return metadata, nil
			}
			return ObjectMetadata{}, knownFailure(ctx, a.Journal, request.Mutation, "object-conflict")
		}
		return ObjectMetadata{}, ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
	}
	drainClose(resp.Body)
	metadata := ObjectMetadata{ETag: safeHeader(resp, "etag"), SHA256: request.SHA256, Size: int64(len(request.Content))}
	if metadata.ETag == "" {
		return ObjectMetadata{}, finishUnknown(ctx, a.Journal, request.Mutation)
	}
	if err := markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: metadata.ETag}); err != nil {
		return ObjectMetadata{}, err
	}
	return metadata, nil
}

func objectMetadataFromResponse(resp *http.Response) (ObjectMetadata, error) {
	if resp == nil {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage response is missing"}
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage content length is invalid"}
	}
	metadata := ObjectMetadata{ETag: safeHeader(resp, "etag"), SHA256: safeHeader(resp, "opc-meta-terrascale-sha256"), Size: size}
	if metadata.ETag == "" || !validSHA256Hex(metadata.SHA256) {
		return ObjectMetadata{}, &InvalidDataError{Message: "OCI Object Storage metadata is incomplete"}
	}
	return metadata, nil
}

func (a *OCIObjectStorageAdapter) HeadObject(ctx context.Context, object ObjectRef) (ObjectMetadata, bool, error) {
	if a == nil || a.ObjectStorage == nil {
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(object); err != nil {
		return ObjectMetadata{}, false, err
	}
	resp, err := a.ObjectStorage.Do(ctx, http.MethodHead, objectStoragePath(object), nil)
	if err != nil {
		return ObjectMetadata{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		return ObjectMetadata{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return ObjectMetadata{}, false, &InvalidOperationError{Message: "OCI Object Storage metadata read failed"}
	}
	metadata, err := objectMetadataFromResponse(resp)
	drainClose(resp.Body)
	return metadata, err == nil, err
}

func (a *OCIObjectStorageAdapter) GetObject(ctx context.Context, object ObjectRef) (io.ReadCloser, ObjectMetadata, error) {
	if a == nil || a.ObjectStorage == nil {
		return nil, ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(object); err != nil {
		return nil, ObjectMetadata{}, err
	}
	resp, err := a.ObjectStorage.Do(ctx, http.MethodGet, objectStoragePath(object), nil)
	if err != nil {
		return nil, ObjectMetadata{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return nil, ObjectMetadata{}, &InvalidOperationError{Message: "OCI Object Storage object read failed"}
	}
	metadata, err := objectMetadataFromResponse(resp)
	if err != nil {
		drainClose(resp.Body)
		return nil, ObjectMetadata{}, err
	}
	return newDigestVerifyingReadCloser(resp.Body, metadata.SHA256), metadata, nil
}

func objectDeleteBinding(request ObjectDeleteRequest) any {
	return struct {
		Object  ObjectRef
		IfMatch string
	}{request.Object, request.IfMatch}
}

func ObjectDeleteMutationFingerprint(request ObjectDeleteRequest) string {
	return fingerprintJSON("object.delete", objectDeleteBinding(request))
}

func ObjectDeleteMutationScope(request ObjectDeleteRequest) string {
	return ProviderMutationScope("object", request.Object.Namespace, request.Object.Bucket, request.Object.Name)
}

func (a *OCIObjectStorageAdapter) DeleteObject(ctx context.Context, request ObjectDeleteRequest) error {
	if a == nil || validateOCIAdapter(a.ObjectStorage, OCIServiceObjectStorage, a.Journal) != nil {
		return &InvalidOperationError{Message: "OCI Object Storage adapter is unavailable"}
	}
	if err := validateObjectRef(request.Object); err != nil {
		return err
	}
	if !isSafeETag(request.IfMatch) {
		return &errs.Argument{Message: "object delete ETag fence is invalid"}
	}
	if err := expectJSONMutation(request.Mutation, "object.delete", ObjectDeleteMutationScope(request), objectDeleteBinding(request)); err != nil {
		return err
	}
	record, err := prepareMutation(ctx, a.Journal, request.Mutation)
	if err != nil {
		return err
	}
	if _, done, err := completedMutation(record); done {
		return err
	}
	_, found, err := a.HeadObject(ctx, request.Object)
	if err != nil {
		return err
	}
	if !found {
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
	}
	if record.State == MutationUnknown {
		return &ProviderOutcomeUnknownError{}
	}
	if _, err := a.Journal.MarkSubmitted(ctx, request.Mutation); err != nil {
		return err
	}
	resp, err := a.ObjectStorage.DoWithHeaders(ctx, http.MethodDelete, objectStoragePath(request.Object), nil, map[string]string{"If-Match": request.IfMatch})
	if err != nil {
		if IsOutcomeIndeterminate(err) {
			if _, found, readErr := a.HeadObject(ctx, request.Object); readErr == nil && !found {
				return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
			}
			return finishUnknown(ctx, a.Journal, request.Mutation)
		}
		return err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		drainClose(resp.Body)
		return markSucceeded(ctx, a.Journal, request.Mutation, ProviderMutationResult{ResourceID: objectStoragePath(request.Object), ETag: request.IfMatch})
	}
	return ociMutationFailure(ctx, a.Journal, request.Mutation, resp)
}

// digestVerifyingReadCloser verifies the streamed bytes against the object's
// SHA-256 digest as they are read, so a truncated or tampered transfer fails
// at the read boundary instead of after the fact.
type digestVerifyingReadCloser struct {
	source   io.ReadCloser
	digest   hash.Hash
	expected string
	done     bool
}

func newDigestVerifyingReadCloser(source io.ReadCloser, expected string) io.ReadCloser {
	return &digestVerifyingReadCloser{source: source, digest: sha256.New(), expected: expected}
}

func (r *digestVerifyingReadCloser) Read(buffer []byte) (int, error) {
	n, err := r.source.Read(buffer)
	if n > 0 {
		_, _ = r.digest.Write(buffer[:n])
	}
	if err == io.EOF && !r.done {
		r.done = true
		if hex.EncodeToString(r.digest.Sum(nil)) != r.expected {
			return n, &InvalidDataError{Message: "provider content digest does not match"}
		}
	}
	return n, err
}

func (r *digestVerifyingReadCloser) Close() error { return r.source.Close() }

var (
	_ ObjectStorageProvider = (*OCIObjectStorageAdapter)(nil)
)
