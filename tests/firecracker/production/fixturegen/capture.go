package fixturegen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// CapturedObject is one exact private Object Storage key and the final bytes
// written by the public bootstrap.Ledger lifecycle. Object names are captured
// from SDK requests; fixturegen never reconstructs the ledger's private names.
type CapturedObject struct {
	Namespace    string
	Bucket       string
	ObjectName   string
	Body         []byte
	ETag         string
	LastModified time.Time
}

type capturedKey struct{ namespace, bucket, object string }

// CapturingObjectStorage is a bounded in-memory ObjectStorageClient for
// offline generation. It implements the same create-only and ETag CAS headers
// that the ledger relies on, then exposes its exact final read inventory.
type CapturingObjectStorage struct {
	mu      sync.Mutex
	now     time.Time
	objects map[capturedKey]CapturedObject
	misses  map[capturedKey]struct{}
	version uint64
	puts    uint64
}

func NewCapturingObjectStorage(now time.Time) (*CapturingObjectStorage, error) {
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errors.New("capture clock must be a fixed UTC instant")
	}
	return &CapturingObjectStorage{now: now.Truncate(time.Second), objects: make(map[capturedKey]CapturedObject),
		misses: make(map[capturedKey]struct{})}, nil
}

func (store *CapturingObjectStorage) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	if request.NamespaceName == nil || request.BucketName == nil || request.ObjectName == nil ||
		request.PutObjectBody == nil || request.ContentLength == nil || *request.ContentLength < 0 ||
		*request.ContentLength > 64<<10 || request.OpcSseKmsKeyId == nil ||
		request.OpcChecksumAlgorithm != objectstorage.PutObjectOpcChecksumAlgorithmSha256 ||
		request.OpcContentSha256 == nil || request.IfNoneMatch == nil && request.IfMatch == nil ||
		request.IfNoneMatch != nil && request.IfMatch != nil {
		return objectstorage.PutObjectResponse{}, errors.New("capture rejected noncanonical ledger PUT")
	}
	defer request.PutObjectBody.Close()
	body, err := io.ReadAll(io.LimitReader(request.PutObjectBody, 64<<10+1))
	if err != nil || int64(len(body)) != *request.ContentLength {
		return objectstorage.PutObjectResponse{}, errors.New("capture rejected ledger PUT content length")
	}
	digest := sha256.Sum256(body)
	if *request.OpcContentSha256 != base64.StdEncoding.EncodeToString(digest[:]) {
		return objectstorage.PutObjectResponse{}, errors.New("capture rejected ledger PUT SHA-256")
	}
	key := capturedKey{*request.NamespaceName, *request.BucketName, *request.ObjectName}
	store.mu.Lock()
	defer store.mu.Unlock()
	previous, exists := store.objects[key]
	if request.IfNoneMatch != nil && (*request.IfNoneMatch != "*" || exists) ||
		request.IfMatch != nil && (!exists || *request.IfMatch != previous.ETag) {
		return objectstorage.PutObjectResponse{}, captureServiceError{http.StatusPreconditionFailed}
	}
	if len(store.objects) >= 512 && !exists {
		return objectstorage.PutObjectResponse{}, errors.New("capture object bound exceeded")
	}
	store.version++
	store.puts++
	etag := fmt.Sprintf("\"%s-%d\"", hex.EncodeToString(digest[:8]), store.version)
	store.objects[key] = CapturedObject{Namespace: key.namespace, Bucket: key.bucket, ObjectName: key.object,
		Body: bytes.Clone(body), ETag: etag, LastModified: store.now}
	return objectstorage.PutObjectResponse{ETag: new(etag), OpcRequestId: new("fixture-capture-put")}, nil
}

func (store *CapturingObjectStorage) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if request.NamespaceName == nil || request.BucketName == nil || request.ObjectName == nil {
		return objectstorage.GetObjectResponse{}, errors.New("capture rejected incomplete exact-key GET")
	}
	key := capturedKey{*request.NamespaceName, *request.BucketName, *request.ObjectName}
	store.mu.Lock()
	object, exists := store.objects[key]
	if !exists {
		if _, seen := store.misses[key]; !seen && len(store.misses) >= 512 {
			store.mu.Unlock()
			return objectstorage.GetObjectResponse{}, errors.New("capture expected-missing route bound exceeded")
		}
		store.misses[key] = struct{}{}
	}
	now := store.now
	store.mu.Unlock()
	if !exists {
		return objectstorage.GetObjectResponse{}, captureServiceError{http.StatusNotFound}
	}
	responseHeaders := make(http.Header)
	responseHeaders.Set("Date", now.Format(http.TimeFormat))
	length := int64(len(object.Body))
	return objectstorage.GetObjectResponse{RawResponse: &http.Response{Header: responseHeaders},
		Content: io.NopCloser(bytes.NewReader(object.Body)), ContentLength: &length, ETag: new(object.ETag),
		LastModified: &common.SDKTime{Time: object.LastModified}, OpcRequestId: new("fixture-capture-get")}, nil
}

// MissingSnapshot returns exact keys that were read as absent during the
// production Ledger workflow and remain absent after fixture construction.
func (store *CapturingObjectStorage) MissingSnapshot() []CapturedMissing {
	store.mu.Lock()
	defer store.mu.Unlock()
	missing := make([]CapturedMissing, 0, len(store.misses))
	for key := range store.misses {
		if _, exists := store.objects[key]; !exists {
			missing = append(missing, CapturedMissing{Namespace: key.namespace, Bucket: key.bucket, ObjectName: key.object})
		}
	}
	slices.SortFunc(missing, func(a, b CapturedMissing) int {
		return bytes.Compare([]byte(a.Namespace+"\x00"+a.Bucket+"\x00"+a.ObjectName),
			[]byte(b.Namespace+"\x00"+b.Bucket+"\x00"+b.ObjectName))
	})
	return missing
}

type CapturedMissing struct {
	Namespace  string
	Bucket     string
	ObjectName string
}

func (store *CapturingObjectStorage) Snapshot() []CapturedObject {
	store.mu.Lock()
	defer store.mu.Unlock()
	objects := make([]CapturedObject, 0, len(store.objects))
	for _, object := range store.objects {
		object.Body = bytes.Clone(object.Body)
		objects = append(objects, object)
	}
	slices.SortFunc(objects, func(a, b CapturedObject) int {
		return bytes.Compare([]byte(a.Namespace+"\x00"+a.Bucket+"\x00"+a.ObjectName),
			[]byte(b.Namespace+"\x00"+b.Bucket+"\x00"+b.ObjectName))
	})
	return objects
}

func (store *CapturingObjectStorage) PutCount() uint64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.puts
}

type captureServiceError struct{ status int }

func (err captureServiceError) Error() string {
	return fmt.Sprintf("captured Object Storage status %d", err.status)
}
func (err captureServiceError) GetHTTPStatusCode() int  { return err.status }
func (err captureServiceError) GetMessage() string      { return err.Error() }
func (err captureServiceError) GetCode() string         { return "FixtureCapture" }
func (err captureServiceError) GetOpcRequestID() string { return "fixture-capture" }
