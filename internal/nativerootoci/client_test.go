package nativerootoci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const nativeTestDigest = "678dcc5f87692c0885126111c6828c7181bedd6cdb268f655ac442e1846a20cb"

type objectClientStub struct {
	get func(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	put func(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

func TestNativeRootUncertaintyLogsStageAndStatusWithoutProviderSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	target := testTarget(t)
	service, err := NewService(target, objectClientStub{
		get: func(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
			return objectstorage.GetObjectResponse{}, objectFailure(http.StatusServiceUnavailable)
		},
		put: func(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
			return objectstorage.PutObjectResponse{}, errors.New("secret-signed-provider-url")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(context.Context) error { return nil }
	for _, request := range []Request{
		testRequest(target, "get", nil, ""),
		testRequest(target, "update", []byte("secret-root-body"), "secret-etag"),
	} {
		if response := service.Execute(t.Context(), request, authorize); response.Status != "uncertain" {
			t.Fatalf("failure did not stay uncertain: %+v", response)
		}
	}
	for _, field := range []string{`"operation":"get"`, `"operation":"put"`, `"stage":"sdk"`,
		`"http_status":503`, `"deadline_remaining"`, `"elapsed"`} {
		if !strings.Contains(logs.String(), field) {
			t.Fatalf("missing diagnostic %s: %s", field, logs.String())
		}
	}
	if strings.Contains(logs.String(), "secret-") || strings.Contains(logs.String(), target.Bucket) {
		t.Fatalf("sensitive provider or request detail leaked: %s", logs.String())
	}
	for _, operation := range []string{"get", "update"} {
		logs.Reset()
		ctx, cancel := context.WithCancel(t.Context())
		service, err := NewService(target, objectClientStub{
			get: func(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
				cancel()
				return objectstorage.GetObjectResponse{}, objectFailure(http.StatusServiceUnavailable)
			},
			put: func(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
				cancel()
				return objectstorage.PutObjectResponse{}, objectFailure(http.StatusServiceUnavailable)
			},
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		request := testRequest(target, operation, nil, "")
		if operation == "update" {
			request = testRequest(target, operation, []byte("root"), "etag")
		}
		response := service.Execute(ctx, request, authorize)
		cancel()
		if response.Status != "uncertain" || !strings.Contains(logs.String(), `"cause":"canceled"`) ||
			!strings.Contains(logs.String(), `"http_status":503`) {
			t.Fatalf("cancellation lost provider evidence for %s: %+v %s", operation, response, logs.String())
		}
	}
	logs.Reset()
	malformed := testRequest(target, "update", []byte("root"), "etag")
	malformed.RootBase64 = "!!!!"
	if response := service.Execute(t.Context(), malformed, authorize); response.Status != "uncertain" {
		t.Fatalf("malformed request response changed: %+v", response)
	}
	if !strings.Contains(logs.String(), "native OCI root request rejected") ||
		strings.Contains(logs.String(), "native OCI root request uncertain") {
		t.Fatalf("malformed request was mislabeled: %s", logs.String())
	}
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

func TestNativeRootTargetRejectsWrongSignedLocator(t *testing.T) {
	target := testTarget(t)
	if target.Digest != nativeTestDigest {
		t.Fatal("native target digest differs from producer vector")
	}
	target.Endpoint = "https://other.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com"
	if _, err := NewTarget(target.Region, target.Namespace, target.Bucket, target.Endpoint,
		target.PublicationDigest, target.Digest); err == nil {
		t.Fatal("wrong endpoint accepted")
	}
	target = testTarget(t)
	target.Bucket = "other-bucket"
	if _, err := NewTarget(target.Region, target.Namespace, target.Bucket, target.Endpoint,
		target.PublicationDigest, target.Digest); err == nil {
		t.Fatal("wrong bucket accepted")
	}
}

func TestNativeRootSignedConfigSelectsOnlyExactTarget(t *testing.T) {
	target := testTarget(t)
	native := []byte(`{"version":1,"ack_profile":"object_durable","bucket":"ts-preview-gru-20260926-terrabase-live","region":"sa-saopaulo-1","endpoint":"https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com","native_oci_root":{"namespace":"grxnmoqvrcdv"}}`)
	selected, enabled, err := TargetFromSignedConfig(native, target.Digest, target.PublicationDigest)
	if err != nil || !enabled || selected != target {
		t.Fatalf("signed native target = %+v, enabled = %t, error = %v", selected, enabled, err)
	}
	generic := []byte(`{"version":1,"ack_profile":"object_durable","bucket":"generic","region":"sa-saopaulo-1"}`)
	if _, enabled, err := TargetFromSignedConfig(generic, target.Digest, target.PublicationDigest); err != nil || enabled {
		t.Fatalf("generic config selected native root: enabled = %t, error = %v", enabled, err)
	}
	for _, changed := range [][]byte{
		bytes.Replace(native, []byte(`"namespace":"grxnmoqvrcdv"`), []byte(`"namespace":"other"`), 1),
		bytes.Replace(native, []byte(`"ack_profile":"object_durable"`), []byte(`"ack_profile":"weak"`), 1),
		append(bytes.TrimSuffix(native, []byte("}")), []byte(`,"unexpected":true}`)...),
	} {
		if _, enabled, err := TargetFromSignedConfig(changed, target.Digest, target.PublicationDigest); err == nil || enabled {
			t.Fatalf("invalid signed config selected native root: %s", changed)
		}
	}
	if _, enabled, err := TargetFromSignedConfig(native,
		hex.EncodeToString(bytes.Repeat([]byte{0}, 32)), target.PublicationDigest); err == nil || enabled {
		t.Fatal("mismatched signed target digest selected native root")
	}
}

func TestNativeRootGetReturnsOneResponseBytesAndETag(t *testing.T) {
	target := testTarget(t)
	const etag = `"etag-from-get"`
	getCalls := 0
	service, err := NewService(target, objectClientStub{get: func(_ context.Context,
		request objectstorage.GetObjectRequest,
	) (objectstorage.GetObjectResponse, error) {
		getCalls++
		if *request.NamespaceName != target.Namespace || *request.BucketName != target.Bucket ||
			*request.ObjectName != target.rootKey() || request.RequestMetadata.RetryPolicy == nil ||
			request.RequestMetadata.RetryPolicy.MaximumNumberAttempts != 1 {
			t.Fatal("GetObject escaped the exact target or retry bound")
		}
		return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader([]byte("root"))),
			ContentLength: new(int64(4)), ETag: new(etag)}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	response := service.Execute(t.Context(), testRequest(target, "get", nil, ""), func(context.Context) error { return nil })
	if response.Status != "found" || response.ETag != etag || response.RootBase64 != base64.StdEncoding.EncodeToString([]byte("root")) || getCalls != 1 {
		t.Fatalf("Get response = %+v, calls = %d", response, getCalls)
	}
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

func TestNativeRootProbeRequiresStaleETagRejectionAndReadback(t *testing.T) {
	target := testTarget(t)
	const initialETag = `"probe-created"`
	const updatedETag = `"probe-updated"`
	getCalls, putCalls := 0, 0
	service, err := NewService(target, objectClientStub{
		get: func(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
			getCalls++
			if *request.ObjectName != target.probeKey() {
				t.Fatal("probe Get used an unexpected key")
			}
			if getCalls == 1 {
				return objectstorage.GetObjectResponse{}, objectFailure(http.StatusNotFound)
			}
			return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader([]byte("OCItest1"))),
				ContentLength: new(int64(8)), ETag: new(updatedETag)}, nil
		},
		put: func(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
			putCalls++
			body, readErr := io.ReadAll(request.PutObjectBody)
			if readErr != nil || *request.ObjectName != target.probeKey() || len(body) != 8 {
				t.Fatal("probe Put used an unexpected key or body")
			}
			switch putCalls {
			case 1:
				if string(body) != "OCIprobe" || request.IfNoneMatch == nil || *request.IfNoneMatch != "*" {
					t.Fatal("probe creation lacked If-None-Match")
				}
				return objectstorage.PutObjectResponse{ETag: new(initialETag)}, nil
			case 2:
				if string(body) != "OCItest1" || request.IfMatch == nil || *request.IfMatch != initialETag {
					t.Fatal("probe update lacked its current ETag")
				}
				return objectstorage.PutObjectResponse{ETag: new(updatedETag)}, nil
			case 3:
				if string(body) != "OCItest2" || request.IfMatch == nil || *request.IfMatch != initialETag {
					t.Fatal("probe stale write did not reuse the old ETag")
				}
				return objectstorage.PutObjectResponse{}, objectFailure(http.StatusPreconditionFailed)
			case 4:
				if string(body) != "OCItest3" || request.IfMatch != nil ||
					request.IfNoneMatch == nil || *request.IfNoneMatch != "*" {
					t.Fatal("probe repeated create lacked If-None-Match")
				}
				return objectstorage.PutObjectResponse{}, objectFailure(http.StatusPreconditionFailed)
			default:
				t.Fatal("probe made an extra Put")
				return objectstorage.PutObjectResponse{}, nil
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := service.Execute(t.Context(), testRequest(target, "probe_update", nil, ""),
		func(context.Context) error { return nil })
	if response.Status != "written" || response.ETag != "" || response.RootBase64 != "" ||
		getCalls != 2 || putCalls != 4 {
		t.Fatalf("probe response = %+v, Gets = %d, Puts = %d", response, getCalls, putCalls)
	}
}

func TestNativeRootProbeRepeatsConditionalCreateOnExistingKey(t *testing.T) {
	for _, test := range []struct {
		name         string
		createStatus int
		wantStatus   string
		wantGetCalls int
	}{
		{name: "stale create rejected", createStatus: http.StatusPreconditionFailed,
			wantStatus: "written", wantGetCalls: 2},
		{name: "stale create accepted", createStatus: http.StatusOK,
			wantStatus: "unsupported", wantGetCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := testTarget(t)
			const oldETag = `"existing"`
			const newETag = `"updated"`
			getCalls, putCalls := 0, 0
			service, err := NewService(target, objectClientStub{
				get: func(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
					getCalls++
					if *request.ObjectName != target.probeKey() {
						t.Fatal("existing probe read escaped fixed key")
					}
					if getCalls == 1 {
						return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader([]byte("OCIprobe"))),
							ContentLength: new(int64(8)), ETag: new(oldETag)}, nil
					}
					return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader([]byte("OCItest1"))),
						ContentLength: new(int64(8)), ETag: new(newETag)}, nil
				},
				put: func(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
					putCalls++
					body, readErr := io.ReadAll(request.PutObjectBody)
					if readErr != nil || *request.ObjectName != target.probeKey() || len(body) != 8 {
						t.Fatal("existing probe write escaped fixed key or size")
					}
					switch putCalls {
					case 1:
						if string(body) != "OCItest1" || request.IfMatch == nil || *request.IfMatch != oldETag {
							t.Fatal("existing probe update lacked its old ETag")
						}
						return objectstorage.PutObjectResponse{ETag: new(newETag)}, nil
					case 2:
						if string(body) != "OCItest2" || request.IfMatch == nil || *request.IfMatch != oldETag {
							t.Fatal("existing probe stale update lacked its old ETag")
						}
						return objectstorage.PutObjectResponse{}, objectFailure(http.StatusPreconditionFailed)
					case 3:
						if string(body) != "OCItest3" || request.IfMatch != nil ||
							request.IfNoneMatch == nil || *request.IfNoneMatch != "*" {
							t.Fatal("existing probe repeated create lacked If-None-Match")
						}
						if test.createStatus == http.StatusOK {
							return objectstorage.PutObjectResponse{ETag: new(`"unexpected"`)}, nil
						}
						return objectstorage.PutObjectResponse{}, objectFailure(test.createStatus)
					default:
						t.Fatal("existing probe made an extra Put")
						return objectstorage.PutObjectResponse{}, nil
					}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			response := service.Execute(t.Context(), testRequest(target, "probe_update", nil, ""),
				func(context.Context) error { return nil })
			if response.Status != test.wantStatus || response.ETag != "" ||
				getCalls != test.wantGetCalls || putCalls != 3 {
				t.Fatalf("repeated probe response = %+v, Gets = %d, Puts = %d", response, getCalls, putCalls)
			}
		})
	}
}
