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
