package imageimport_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
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
