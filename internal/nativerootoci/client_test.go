package nativerootoci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const nativeTestDigest = "678dcc5f87692c0885126111c6828c7181bedd6cdb268f655ac442e1846a20cb"

type objectClientStub struct {
	get func(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	put func(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

func (client objectClientStub) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	return client.get(ctx, request)
}

func (client objectClientStub) PutObject(ctx context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return client.put(ctx, request)
}

type objectFailure int

func (failure objectFailure) Error() string          { return "object request failed" }
func (failure objectFailure) GetHTTPStatusCode() int { return int(failure) }

func testTarget(t *testing.T) Target {
	t.Helper()
	publication := bytes.Repeat([]byte{0x47}, 32)
	target, err := NewTarget("sa-saopaulo-1", "grxnmoqvrcdv",
		"ts-preview-gru-20260926-terrabase-live",
		"https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
		hex.EncodeToString(publication), nativeTestDigest)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}
	return target
}

func testRequest(target Target, operation string, body []byte, etag string) Request {
	return Request{Version: 1, Operation: operation, PublicationDigest: target.PublicationDigest,
		TargetDigest: target.Digest, RootBase64: base64.StdEncoding.EncodeToString(body), IfMatch: etag}
}

func TestNativeRootConditionalPutAndUncertainFailure(t *testing.T) {
	target := testTarget(t)
	const oldETag = `"old"`
	const nextETag = `"new"`
	putCalls := 0
	service, err := NewService(target, objectClientStub{put: func(_ context.Context,
		request objectstorage.PutObjectRequest,
	) (objectstorage.PutObjectResponse, error) {
		putCalls++
		body, readErr := io.ReadAll(request.PutObjectBody)
		if readErr != nil || string(body) != "root" || *request.NamespaceName != target.Namespace ||
			*request.BucketName != target.Bucket || *request.ObjectName != target.rootKey() ||
			request.RequestMetadata.RetryPolicy == nil ||
			request.RequestMetadata.RetryPolicy.MaximumNumberAttempts != 1 {
			t.Fatal("PutObject escaped the exact target, body, or retry bound")
		}
		if putCalls == 1 {
			if request.IfMatch != nil || request.IfNoneMatch == nil || *request.IfNoneMatch != "*" {
				t.Fatal("Create lacked If-None-Match: *")
			}
			return objectstorage.PutObjectResponse{ETag: new(nextETag)}, nil
		}
		if request.IfNoneMatch != nil || request.IfMatch == nil || *request.IfMatch != oldETag {
			t.Fatal("Update lacked the exact old ETag")
		}
		switch putCalls {
		case 2:
			return objectstorage.PutObjectResponse{}, objectFailure(http.StatusPreconditionFailed)
		default:
			return objectstorage.PutObjectResponse{}, context.DeadlineExceeded
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(context.Context) error { return nil }
	if response := service.Execute(t.Context(), testRequest(target, "create", []byte("root"), ""), authorize); response.Status != "written" || response.ETag != nextETag {
		t.Fatalf("create response = %+v", response)
	}
	if response := service.Execute(t.Context(), testRequest(target, "update", []byte("root"), oldETag), authorize); response.Status != "precondition" {
		t.Fatalf("412 response = %+v", response)
	}
	if response := service.Execute(t.Context(), testRequest(target, "update", []byte("root"), oldETag), authorize); response.Status != "uncertain" {
		t.Fatalf("ambiguous failure response = %+v", response)
	}
	if putCalls != 3 {
		t.Fatalf("Put calls = %d, want 3", putCalls)
	}
	wrong := testRequest(target, "update", []byte("root"), oldETag)
	wrong.TargetDigest = hex.EncodeToString(bytes.Repeat([]byte{0}, 32))
	if response := service.Execute(t.Context(), wrong, authorize); response.Status != "uncertain" || putCalls != 3 {
		t.Fatal("wrong target digest reached OCI client")
	}
}
