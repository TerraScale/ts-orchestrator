package imageimport_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport/imageimporttest"
)

func TestSDKRegionalImportsCheckpointPartialSuccessAndResume(t *testing.T) {
	regions := []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}
	servers := map[string]*imageimporttest.Server{}
	for _, region := range regions {
		servers[region] = imageimporttest.Start(t, "ocid1.image."+region)
	}
	dir := t.TempDir()
	data := []byte("qualified regional image")
	qcow2 := filepath.Join(dir, "image.qcow2")
	if err := os.WriteFile(qcow2, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	o := imageimport.Options{QCOW2: qcow2, SHA256: hex.EncodeToString(sum[:]), Compartment: "ocid1.compartment.oc1..c",
		Namespace: "ns", Bucket: "images", DisplayName: "regional", Out: filepath.Join(dir, "imports.json"), Regions: regions}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	releaseFailure := make(chan struct{})
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-releaseFailure:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"regional scope unavailable"}`)
	}))
	defer func() {
		close(releaseFailure)
		unavailable.Close()
	}()
	finished := make(chan error, 1)
	go func() {
		_, err := imageimport.ImportRegions(ctx, o, io.Discard, func(region string) (imageimport.Importer, error) {
			if region == regions[2] {
				return imageimporttest.Importer(unavailable.URL)(region)
			}
			return imageimporttest.Importer(servers[region].URL)(region)
		})
		finished <- err
	}()
	read := func() map[string]any {
		t.Helper()
		b, err := os.ReadFile(o.Out)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal(b, &record); err != nil {
			t.Fatalf("checkpoint is truncated: %v", err)
		}
		return record
	}
	for {
		record := read()
		if done, ok := record["regions"].(map[string]any); ok && len(done) == 2 {
			pending, ok := record["pending"].([]any)
			if !ok || len(pending) != 1 || pending[0] != regions[2] {
				t.Fatalf("in-flight checkpoint=%v", record)
			}
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("healthy imports did not checkpoint independently: %v", record)
		}
	}
	releaseFailure <- struct{}{}
	if err := <-finished; err == nil || !strings.Contains(err.Error(), regions[2]+":") || !strings.Contains(err.Error(), "regional scope unavailable") {
		t.Fatalf("partial import error=%v", err)
	}
	partial := read()
	if len(partial["regions"].(map[string]any)) != 2 || partial["pending"] != nil ||
		partial["errors"].(map[string]any)[regions[2]] == nil {
		t.Fatalf("partial checkpoint=%v", partial)
	}
	result, err := imageimport.ImportRegions(ctx, o, io.Discard, func(region string) (imageimport.Importer, error) {
		return imageimporttest.Importer(servers[region].URL)(region)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result["regions"].(map[string]any)) != 3 || result["pending"] != nil || result["errors"] != nil {
		t.Fatalf("resumed result=%v", result)
	}
	for region, server := range servers {
		if server.Count("POST /20160918/images") != 1 || server.Count("PUT /n/ns/b/images/o/") != 1 {
			t.Errorf("%s repeated completed work: %q", region, server.Requests())
		}
	}
}

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
			"--display-name", "0000000000EKYENDPQ5JG1M4A1", "--out", out}, io.Discard, imageimporttest.Importer(region.URL))
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
