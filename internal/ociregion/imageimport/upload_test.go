package imageimport_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

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
