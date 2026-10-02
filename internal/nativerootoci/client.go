package nativerootoci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	MaxRootBytes  = 64 << 10 // tb-object MAX_MANIFEST_BYTES
	MaxETagBytes  = 1024
	requestLimit  = 25 * time.Second // below TerraBase's 30-second object request limit
	probeBodySize = 8                // tb-object's conditional-update probe size
)

type ObjectClient interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

type serviceError interface {
	error
	GetHTTPStatusCode() int
}

// Service has no method for caller-selected OCI bucket or object names.
// Its permit bounds SDK work separately from the host's management loop.
type Service struct {
	target  Target
	client  ObjectClient
	permits chan struct{}
}

type clientConstruction struct {
	done   chan struct{}
	client ObjectClient
	err    error
}

var instancePrincipalClients struct {
	sync.Mutex
	byRegion map[string]*clientConstruction
}

func NewService(target Target, client ObjectClient) (*Service, error) {
	if !target.valid() || target.digest() != target.Digest || client == nil {
		return nil, errors.New("native OCI root service target or client is invalid")
	}
	return &Service{target: target, client: client, permits: make(chan struct{}, 2)}, nil
}

// NewInstancePrincipalClient uses the host identity and OCI's native Object
// Storage API. The service HTTP transport is bounded, has no proxy or redirect,
// and never passes credentials to the member process.
func NewInstancePrincipalClient(ctx context.Context, region string) (ObjectClient, error) {
	if ctx == nil {
		return nil, errors.New("native OCI root client context is missing")
	}
	if !catalog.IsOCIRegion(region) {
		return nil, errors.New("native OCI root region is invalid")
	}
	// The SDK's metadata region discovery sleeps between eight retries and has
	// no context parameter. Share one construction attempt per region so those
	// retries cannot hold the management loop or accumulate goroutines.
	instancePrincipalClients.Lock()
	if instancePrincipalClients.byRegion == nil {
		instancePrincipalClients.byRegion = make(map[string]*clientConstruction)
	}
	attempt := instancePrincipalClients.byRegion[region]
	if attempt == nil {
		attempt = &clientConstruction{done: make(chan struct{})}
		instancePrincipalClients.byRegion[region] = attempt
		go func() {
			attempt.client, attempt.err = constructInstancePrincipalClient(region)
			close(attempt.done)
			if attempt.err != nil {
				instancePrincipalClients.Lock()
				if instancePrincipalClients.byRegion[region] == attempt {
					delete(instancePrincipalClients.byRegion, region)
				}
				instancePrincipalClients.Unlock()
			}
		}()
	}
	instancePrincipalClients.Unlock()
	wait, cancel := context.WithTimeout(ctx, requestLimit)
	defer cancel()
	select {
	case <-attempt.done:
		return attempt.client, attempt.err
	case <-wait.Done():
		return nil, errors.New("native OCI root client construction deadline expired")
	}
}

func constructInstancePrincipalClient(region string) (ObjectClient, error) {
	for _, name := range []string{"OCI_METADATA_BASE_URL", "OCI_SDK_AUTH_CLIENT_REGION_URL",
		"OCI_DEFAULT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"} {
		if _, overridden := os.LookupEnv(name); overridden {
			return nil, errors.New("native OCI root SDK override is unavailable")
		}
	}
	provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(common.Region(region),
		func(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
			if client, ok := dispatcher.(*http.Client); !ok || client == nil {
				return nil, errors.New("native OCI root metadata transport is invalid")
			}
			return bootstrap.NewInstancePrincipalSDKHTTPClient()
		})
	if err != nil {
		return nil, errors.New("native OCI root instance principal is unavailable")
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, errors.New("native OCI Object Storage client is unavailable")
	}
	client.SetRegion(region)
	client.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, errors.New("native OCI Object Storage transport is unavailable")
	}
	policy := common.NoRetryPolicy()
	client.Configuration.RetryPolicy = &policy
	return &client, nil
}

type requestOperationKey struct{}

// Execute is one bounded request. authorize must recheck the exact active
// member, process and host lease immediately before each OCI SDK operation.
func (service *Service) Execute(ctx context.Context, request Request, authorize func(context.Context) error) (response Response) {
	response = Response{Version: 1, Status: "uncertain"}
	if service == nil || ctx == nil || authorize == nil ||
		request.Version != 1 || request.PublicationDigest != service.target.PublicationDigest ||
		request.TargetDigest != service.target.Digest || !request.valid() {
		return response
	}
	ctx, cancel := context.WithTimeout(ctx, requestLimit)
	defer cancel()
	ctx = context.WithValue(ctx, requestOperationKey{}, request.Operation)
	started := time.Now()
	rejected := false
	defer func() {
		// Stage logs identify an individual GET/PUT failure. This request
		// summary supplies total elapsed time, including permit wait and
		// multiple SDK operations for probe_update.
		if response.Status == "uncertain" && !rejected {
			slog.Warn("native OCI root request uncertain", "operation", request.Operation,
				"elapsed", time.Since(started))
		}
	}()
	select {
	case service.permits <- struct{}{}:
		defer func() { <-service.permits }()
	case <-ctx.Done():
		logNativeRootFailure(ctx, request.Operation, "permit", ctx.Err())
		return response
	}
	if err := authorize(ctx); err != nil {
		logNativeRootFailure(ctx, request.Operation, "authorize", err)
		return response
	}
	switch request.Operation {
	case "get":
		body, etag, status := service.get(ctx, service.target.rootKey(), MaxRootBytes, authorize)
		response.Status = status
		if status == "found" {
			response.ETag = etag
			response.RootBase64 = base64.StdEncoding.EncodeToString(body)
		}
	case "create", "update":
		body, err := base64.StdEncoding.Strict().DecodeString(request.RootBase64)
		if err != nil || len(body) == 0 || len(body) > MaxRootBytes ||
			base64.StdEncoding.EncodeToString(body) != request.RootBase64 {
			rejected = true
			slog.Warn("native OCI root request rejected", "operation", request.Operation,
				"cause", "invalid_root_payload")
			return response
		}
		ifMatch := request.IfMatch
		if request.Operation == "create" {
			ifMatch = ""
		}
		response.ETag, response.Status = service.put(ctx, service.target.rootKey(), body, ifMatch, authorize)
	case "probe_update":
		response.Status = service.probeUpdate(ctx, authorize)
	}
	return response
}

func (service *Service) get(ctx context.Context, key string, maximum int,
	authorize func(context.Context) error,
) ([]byte, string, string) {
	if err := authorize(ctx); err != nil {
		logNativeRootFailure(ctx, "get", "authorize", err)
		return nil, "", "uncertain"
	}
	response, err := service.client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: new(service.target.Namespace), BucketName: new(service.target.Bucket),
		ObjectName: new(key), RequestMetadata: noRetryMetadata(),
	})
	if ctx.Err() != nil {
		if response.Content != nil {
			_ = response.Content.Close()
		}
		logNativeRootFailure(ctx, "get", "sdk", errors.Join(ctx.Err(), err))
		return nil, "", "uncertain"
	}
	if err != nil {
		if failure, ok := errors.AsType[serviceError](err); ok && failure.GetHTTPStatusCode() == http.StatusNotFound {
			return nil, "", "absent"
		}
		logNativeRootFailure(ctx, "get", "sdk", err)
		return nil, "", "uncertain"
	}
	if response.Content == nil {
		logNativeRootFailure(ctx, "get", "response_metadata", nil)
		return nil, "", "uncertain"
	}
	if response.ContentLength == nil || *response.ContentLength < 1 ||
		*response.ContentLength > int64(maximum) || response.ETag == nil || !validETag(*response.ETag) {
		_ = response.Content.Close()
		logNativeRootFailure(ctx, "get", "response_metadata", nil)
		return nil, "", "uncertain"
	}
	body, err := io.ReadAll(io.LimitReader(response.Content, int64(maximum)+1))
	closeErr := response.Content.Close()
	if err != nil || closeErr != nil || len(body) != int(*response.ContentLength) || len(body) > maximum {
		logNativeRootFailure(ctx, "get", "response_body", errors.Join(err, closeErr))
		return nil, "", "uncertain"
	}
	return body, *response.ETag, "found"
}

func (service *Service) put(ctx context.Context, key string, body []byte, ifMatch string,
	authorize func(context.Context) error,
) (string, string) {
	if err := authorize(ctx); err != nil {
		logNativeRootFailure(ctx, "put", "authorize", err)
		return "", "uncertain"
	}
	length := int64(len(body))
	checksum := sha256.Sum256(body)
	request := objectstorage.PutObjectRequest{
		NamespaceName: new(service.target.Namespace), BucketName: new(service.target.Bucket),
		ObjectName: new(key), PutObjectBody: io.NopCloser(bytes.NewReader(body)),
		ContentLength: new(length), ContentType: new("application/octet-stream"),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     new(base64.StdEncoding.EncodeToString(checksum[:])),
		RequestMetadata:      noRetryMetadata(),
	}
	if ifMatch == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(ifMatch)
	}
	// A failed write acknowledgement may have committed. Never retry the Put.
	response, err := service.client.PutObject(ctx, request)
	if ctx.Err() != nil {
		logNativeRootFailure(ctx, "put", "sdk", errors.Join(ctx.Err(), err))
		return "", "uncertain"
	}
	if err != nil {
		if failure, ok := errors.AsType[serviceError](err); ok &&
			failure.GetHTTPStatusCode() == http.StatusPreconditionFailed {
			return "", "precondition"
		}
		logNativeRootFailure(ctx, "put", "sdk", err)
		return "", "uncertain"
	}
	if response.ETag == nil || !validETag(*response.ETag) {
		logNativeRootFailure(ctx, "put", "response_metadata", nil)
		return "", "uncertain"
	}
	return *response.ETag, "written"
}

// Provider errors can contain signed URLs and credential details. Keep journal
// diagnostics bounded to operation, stage, status and the remaining lease.
func logNativeRootFailure(ctx context.Context, operation, stage string, err error) {
	cause := "invalid_response"
	status := 0
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		cause = "deadline"
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		cause = "canceled"
	case err != nil:
		cause = "operation_failed"
		if failure, ok := errors.AsType[AuthorizationError](err); ok {
			cause = failure.Cause
		}
	}
	if failure, ok := errors.AsType[serviceError](err); ok {
		status = failure.GetHTTPStatusCode()
	}
	remaining := time.Duration(0)
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	requestOperation, _ := ctx.Value(requestOperationKey{}).(string)
	slog.Warn("native OCI root operation uncertain", "operation", operation,
		"request_operation", requestOperation, "stage", stage,
		"cause", cause, "http_status", status, "deadline_remaining", remaining)
}

func noRetryMetadata() common.RequestMetadata {
	policy := common.NoRetryPolicy()
	return common.RequestMetadata{RetryPolicy: &policy}
}

func (service *Service) probeUpdate(ctx context.Context, authorize func(context.Context) error) string {
	key := service.target.probeKey()
	current, oldETag, status := service.get(ctx, key, probeBodySize, authorize)
	if status == "absent" {
		oldETag, status = service.put(ctx, key, []byte("OCIprobe"), "", authorize)
		current = []byte("OCIprobe")
	}
	if status != "found" && status != "written" {
		return "uncertain"
	}
	first := []byte("OCItest1")
	second := []byte("OCItest2")
	if bytes.Equal(current, first) {
		first, second = second, first
	}
	newETag, status := service.put(ctx, key, first, oldETag, authorize)
	if status != "written" || newETag == oldETag {
		return "uncertain"
	}
	_, status = service.put(ctx, key, second, oldETag, authorize)
	if status == "written" {
		return "unsupported"
	}
	if status != "precondition" {
		return "uncertain"
	}
	// Every admission also proves native create-if-absent on this same private
	// probe key. A mistaken success must never be treated as a CAS-capable store.
	_, status = service.put(ctx, key, []byte("OCItest3"), "", authorize)
	if status == "written" {
		return "unsupported"
	}
	if status != "precondition" {
		return "uncertain"
	}
	readback, observedETag, status := service.get(ctx, key, probeBodySize, authorize)
	if status != "found" || observedETag != newETag || !bytes.Equal(readback, first) {
		return "uncertain"
	}
	return "written"
}

func validETag(value string) bool {
	if value == "" || value == "*" || len(value) > MaxETagBytes || strings.Contains(value, ",") {
		return false
	}
	for _, char := range []byte(value) {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}
