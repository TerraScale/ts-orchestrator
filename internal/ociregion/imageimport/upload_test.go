package imageimport_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
)

func uploadFixture(t *testing.T, size int) (string, []byte, string) {
	t.Helper()
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(index*7 + index/251)
	}
	path := filepath.Join(t.TempDir(), "image.qcow2")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return path, data, hex.EncodeToString(sum[:])
}

func uploadRequest(path, digest string, partSize int64) imageimport.UploadRequest {
	return imageimport.UploadRequest{Namespace: "ns", Bucket: "images", Object: "images/" + digest + ".qcow2", Path: path,
		SHA256: digest, Metadata: map[string]string{"sha256": digest}, PartSize: partSize, Parallelism: 3}
}

func TestStreamingUploadCommitsExactlyTheVerifiedBytes(t *testing.T) {
	for name, size := range map[string]int{"multipart": 10*1024 + 17, "exact parts": 8 * 1024, "single part": 900, "empty": 0} {
		t.Run(name, func(t *testing.T) {
			region := imageimporttest.Start(t, "ocid1.image.oc1..x")
			client, err := imageimporttest.Client(region.URL, "sa-saopaulo-1")
			if err != nil {
				t.Fatal(err)
			}
			path, data, digest := uploadFixture(t, size)
			if err := client.UploadObject(t.Context(), uploadRequest(path, digest, 1024)); err != nil {
				t.Fatalf("%v\n%q", err, region.Requests())
			}
			stored, metadata, ok := region.Object("ns", "images", "images/"+digest+".qcow2")
			if !ok || !bytes.Equal(stored, data) || metadata["sha256"] != digest {
				t.Fatalf("stored %d bytes ok=%v metadata=%v", len(stored), ok, metadata)
			}
			if open, aborted := region.Multipart(); open != 0 || aborted != 0 {
				t.Fatalf("open=%d aborted=%d", open, aborted)
			}
			// The object is content addressed and never overwritten.
			if err := client.UploadObject(t.Context(), uploadRequest(path, digest, 1024)); err == nil {
				t.Fatal("an existing object was overwritten")
			}
		})
	}
}

// The QCOW2 is rewritten while its parts are being uploaded, after the
// digest check passed: the upload is aborted and nothing is committed.
func TestStreamingUploadAbortsWhenTheFileChangesMidUpload(t *testing.T) {
	region := imageimporttest.Start(t, "ocid1.image.oc1..x")
	client, err := imageimporttest.Client(region.URL, "sa-saopaulo-1")
	if err != nil {
		t.Fatal(err)
	}
	path, data, digest := uploadFixture(t, 16*1024)
	tampered := bytes.Clone(data)
	tampered[len(tampered)-1] ^= 0xff
	region.SetPartHook(func(part int) {
		if part == 1 {
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Error(err)
			}
		}
	})
	request := uploadRequest(path, digest, 1024)
	request.Parallelism = 1
	err = client.UploadObject(t.Context(), request)
	if !errors.Is(err, imageimport.ErrUploadDigestMismatch) {
		t.Fatalf("err=%v", err)
	}
	if _, _, ok := region.Object("ns", "images", "images/"+digest+".qcow2"); ok {
		t.Fatal("tampered bytes were committed")
	}
	if open, aborted := region.Multipart(); open != 0 || aborted != 1 {
		t.Fatalf("open=%d aborted=%d", open, aborted)
	}
}

// A part failure is reported as itself, not as the cancellation it caused,
// and the upload is aborted.
func TestStreamingUploadReportsThePartFailure(t *testing.T) {
	region := imageimporttest.Start(t, "ocid1.image.oc1..x")
	client, err := imageimporttest.Client(region.URL, "sa-saopaulo-1")
	if err != nil {
		t.Fatal(err)
	}
	region.SetPartFailure(http.StatusForbidden)
	path, _, digest := uploadFixture(t, 64*1024)
	err = client.UploadObject(t.Context(), uploadRequest(path, digest, 1024))
	if err == nil || !strings.Contains(err.Error(), "upload OCI part") || errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if open, aborted := region.Multipart(); open != 0 || aborted != 1 {
		t.Fatalf("open=%d aborted=%d", open, aborted)
	}
}

func TestStreamingUploadCancelsWhileWaitingForPartHeaders(t *testing.T) {
	for _, scenario := range []struct{ stage, cause string }{
		{"part", "caller"}, {"part", "deadline"}, {"part", "sibling failure"},
		{"single put", "caller"}, {"multipart create", "caller"}, {"multipart commit", "caller"},
	} {
		t.Run(scenario.stage+"/"+scenario.cause, func(t *testing.T) {
			cause := scenario.cause
			region := imageimporttest.Start(t, "ocid1.image.oc1..x")
			target, err := url.Parse(region.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			consumed, disconnected, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				blocked := scenario.stage == "part" && r.Method == http.MethodPut && r.URL.Query().Get("uploadPartNum") == "1" ||
					scenario.stage == "single put" && r.Method == http.MethodPut ||
					scenario.stage == "multipart create" && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/u") ||
					scenario.stage == "multipart commit" && r.Method == http.MethodPost && r.URL.Query().Get("uploadId") != ""
				if blocked {
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil || n == 0 || scenario.stage == "part" && n != 1024 {
						t.Errorf("request body: bytes=%d err=%v", n, err)
						return
					}
					close(consumed)
					// Withhold all response headers after consuming the entire body.
					select {
					case <-r.Context().Done():
						close(disconnected)
					case <-release:
					}
					return
				}
				if cause == "sibling failure" && r.Method == http.MethodPut && r.URL.Query().Get("uploadPartNum") == "2" {
					select {
					case <-consumed:
					case <-release:
					}
					http.Error(w, "primary part failure", http.StatusForbidden)
					return
				}
				proxy.ServeHTTP(w, r)
			}))
			defer server.Close()
			defer close(release)
			client, err := imageimporttest.Client(server.URL, "sa-saopaulo-1")
			if err != nil {
				t.Fatal(err)
			}
			path, _, digest := uploadFixture(t, 2048)
			partSize := int64(1024)
			if scenario.stage == "single put" {
				partSize = 4096
			}
			ctx, cancel := context.WithCancel(t.Context())
			if cause == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), time.Second)
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- client.UploadObject(ctx, uploadRequest(path, digest, partSize)) }()
			select {
			case <-consumed:
			case <-time.After(5 * time.Second):
				t.Fatal("server never consumed the full request body")
			}
			if cause == "caller" {
				cancel()
			}
			select {
			case err := <-done:
				if cause == "sibling failure" {
					if err == nil || !strings.Contains(err.Error(), "upload OCI part 2:") || errors.Is(err, context.Canceled) {
						t.Fatalf("primary part failure lost: %v", err)
					}
					var failure interface{ GetHTTPStatusCode() int }
					if !errors.As(err, &failure) || failure.GetHTTPStatusCode() != http.StatusForbidden {
						t.Fatalf("primary HTTP 403 lost: %v", err)
					}
				} else if !errors.Is(err, ctx.Err()) {
					t.Fatalf("err=%v; want %v", err, ctx.Err())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("upload hung waiting for response headers after cancellation")
			}
			select {
			case <-disconnected:
			case <-time.After(2 * time.Second):
				t.Fatal("HTTP request was not canceled")
			}
			wantAborts := 1
			if scenario.stage == "single put" || scenario.stage == "multipart create" {
				wantAborts = 0
			}
			if open, aborted := region.Multipart(); open != 0 || aborted != wantAborts {
				t.Fatalf("open=%d aborted=%d", open, aborted)
			}
			if region.Count("POST /n/ns/b/images/u/") != 0 {
				t.Fatal("canceled upload was committed")
			}
		})
	}
}

func TestStreamingUploadRetriesSeekableParts(t *testing.T) {
	for _, cancelRetry := range []bool{false, true} {
		name := "successful retry"
		if cancelRetry {
			name = "canceled retry"
		}
		t.Run(name, func(t *testing.T) {
			region := imageimporttest.Start(t, "ocid1.image.oc1..x")
			target, err := url.Parse(region.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			path, data, digest := uploadFixture(t, 1024)
			var attempts atomic.Int32
			failed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					body, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(body, data) {
						t.Errorf("retried part differs: bytes=%d err=%v", len(body), err)
					}
					if attempts.Add(1) == 1 {
						if cancelRetry {
							w.Header().Set("Retry-After", "30")
						}
						http.Error(w, "retry this part", http.StatusServiceUnavailable)
						close(failed)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
				}
				proxy.ServeHTTP(w, r)
			}))
			defer server.Close()
			client, err := imageimporttest.Client(server.URL, "sa-saopaulo-1")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- client.UploadObject(ctx, uploadRequest(path, digest, 1024)) }()
			if cancelRetry {
				select {
				case <-failed:
				case <-time.After(5 * time.Second):
					t.Fatal("server never refused the first attempt")
				}
				// Let the SDK enter the 30-second Retry-After wait before canceling.
				time.AfterFunc(100*time.Millisecond, cancel)
			}
			select {
			case err := <-done:
				if cancelRetry {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("err=%v; want cancellation", err)
					}
					if attempts.Load() != 1 {
						t.Fatalf("canceled part retried: attempts=%d", attempts.Load())
					}
					if open, aborted := region.Multipart(); open != 0 || aborted != 1 {
						t.Fatalf("open=%d aborted=%d", open, aborted)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("upload did not finish or cancel during retry backoff")
			}
			if attempts.Load() != 2 {
				t.Fatalf("part attempts=%d; want 2", attempts.Load())
			}
			if stored, _, ok := region.Object("ns", "images", "images/"+digest+".qcow2"); !ok || !bytes.Equal(stored, data) {
				t.Fatal("retried bytes were not committed intact")
			}
		})
	}
}

// A huge configured part size does not allocate the part size for a small
// file: buffers follow the file's size.
func TestStreamingUploadSizesBuffersByTheFile(t *testing.T) {
	region := imageimporttest.Start(t, "ocid1.image.oc1..x")
	client, err := imageimporttest.Client(region.URL, "sa-saopaulo-1")
	if err != nil {
		t.Fatal(err)
	}
	path, data, digest := uploadFixture(t, 4096)
	if err := client.UploadObject(t.Context(), uploadRequest(path, digest, 64<<30)); err != nil {
		t.Fatal(err)
	}
	if stored, _, ok := region.Object("ns", "images", "images/"+digest+".qcow2"); !ok || !bytes.Equal(stored, data) {
		t.Fatal("object not stored")
	}
}

func TestStreamingUploadRefusesAMismatchedSinglePartBeforeAnyRequest(t *testing.T) {
	region := imageimporttest.Start(t, "ocid1.image.oc1..x")
	client, err := imageimporttest.Client(region.URL, "sa-saopaulo-1")
	if err != nil {
		t.Fatal(err)
	}
	path, _, _ := uploadFixture(t, 100)
	other := sha256.Sum256([]byte("other"))
	request := uploadRequest(path, hex.EncodeToString(other[:]), 1024)
	if err := client.UploadObject(t.Context(), request); !errors.Is(err, imageimport.ErrUploadDigestMismatch) {
		t.Fatalf("err=%v", err)
	}
	if requests := region.Requests(); len(requests) != 0 {
		t.Fatalf("requests=%q", requests)
	}
	request.SHA256 = ""
	if err := client.UploadObject(t.Context(), request); err == nil {
		t.Fatal("an upload without an expected digest was accepted")
	}
}
