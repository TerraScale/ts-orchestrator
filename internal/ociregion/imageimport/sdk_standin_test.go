package imageimport_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
)

// The real SDK client imports into a stand-in region: it signs every request,
// uploads through the upload manager, creates the image, polls the work
// request until it succeeds, applies the launch contract, and a rerun finds
// the live image instead of importing twice.
func TestSDKClientImportsIntoStandIn(t *testing.T) {
	const imageID = "ocid1.image.oc1.sa-saopaulo-1.standin"
	region := imageimporttest.Start(t, imageID)
	dir := t.TempDir()
	qcow2 := filepath.Join(dir, "image.qcow2")
	data := []byte("qualified qcow2 bytes")
	if err := os.WriteFile(qcow2, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	run := func(out string) map[string]any {
		t.Helper()
		err := imageimport.RunImporters(t.Context(), []string{"--qcow2", qcow2, "--sha256", digest,
			"--compartment-id", "ocid1.compartment.oc1..c", "--namespace", "ns", "--bucket", "images",
			"--display-name", "terrascale-test", "--out", out}, io.Discard, imageimporttest.Importer(region.URL))
		if err != nil {
			t.Fatalf("%v\nrequests: %q", err, region.Requests())
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal(b, &record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	first := run(filepath.Join(dir, "first.json"))
	if first["image_id"] != imageID || first["object"] != "ns/images/images/"+digest+".qcow2" ||
		first["billable_size_gb"] != float64(imageimporttest.BillableSizeGB) || !slices.Equal(anyStrings(first["shapes"]), []string{imageimport.A1Shape}) {
		t.Fatalf("record=%v", first)
	}
	stored, metadata, ok := region.Object("ns", "images", "images/"+digest+".qcow2")
	if !ok || string(stored) != string(data) || metadata["sha256"] != digest {
		t.Fatalf("uploaded object=%q metadata=%v ok=%v", stored, metadata, ok)
	}
	if state, _ := region.Image(imageID); state != "AVAILABLE" {
		t.Fatalf("image state %s", state)
	}
	polls := region.Count("GET /20160918/workRequests/")
	if region.Count("POST /20160918/images") != 1 || region.Count("PUT /n/ns/b/images/o/") != 1 || polls != imageimporttest.WorkRequestPolls+1 {
		t.Fatalf("requests: %q", region.Requests())
	}

	second := run(filepath.Join(dir, "second.json"))
	if second["image_id"] != imageID || second["capability_schema_id"] != first["capability_schema_id"] {
		t.Fatalf("rerun record=%v first=%v", second, first)
	}
	for _, prefix := range []string{"POST /20160918/images", "PUT /n/", "HEAD /n/", "POST /20160918/computeImageCapabilitySchemas", "PUT /20160918/images/"} {
		if region.Count(prefix) != 1 {
			t.Fatalf("rerun repeated %s: %q", prefix, region.Requests())
		}
	}
	if region.Count("GET /20160918/workRequests/") != polls {
		t.Fatalf("rerun polled a finished work request: %q", region.Requests())
	}
	for _, request := range region.Requests() {
		if strings.HasPrefix(request, "DELETE ") {
			t.Fatalf("removed a shape of a compliant image: %q", region.Requests())
		}
	}
}

func anyStrings(value any) []string {
	var out []string
	for _, item := range value.([]any) {
		out = append(out, item.(string))
	}
	return out
}
