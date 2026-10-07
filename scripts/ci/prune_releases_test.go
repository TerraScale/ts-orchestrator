package ci

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPruneReleasesKeepsNewestRecentAndPinned runs prune-releases.sh against
// a fake Forgejo with 25 daily CI pre-releases and a stable release.
func TestPruneReleasesKeepsNewestRecentAndPinned(t *testing.T) {
	const token = "prune-token-do-not-log"
	digest := strings.Repeat("d", 64)
	revision := func(i int) string { return fmt.Sprintf("%040x", i+1) }
	var releases []map[string]any
	for i := range 25 {
		tag := fmt.Sprintf("ci-%s-run-%d", revision(i), 100+i)
		releases = append(releases, map[string]any{
			"id": i, "tag_name": tag, "prerelease": true,
			"created_at": time.Now().UTC().Add(-time.Duration(i) * 24 * time.Hour).Format(time.RFC3339),
			"assets": []map[string]any{{"name": "qualification.json", "size": 10,
				"browser_download_url": "/download/" + strconv.Itoa(i)}, {"name": "binary", "size": 1000}},
		})
	}
	releases = append(releases, map[string]any{"id": 99, "tag_name": "v1.0.0", "prerelease": false,
		"created_at": "2020-01-01T00:00:00Z", "assets": []map[string]any{}})

	var mu sync.Mutex
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, filepath.Base(r.URL.Path))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/repos/TerraScale/demo/releases":
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			start, end := min((page-1)*20, len(releases)), min(page*20, len(releases))
			if err := json.MarshalWrite(w, releases[start:end]); err != nil {
				t.Error(err)
			}
		case r.URL.Path == "/download/22":
			fmt.Fprintf(w, `{"artifacts":[{"sha256":%q}]}`, digest)
		case r.URL.Path == "/download/23":
			http.Error(w, "broken", http.StatusInternalServerError)
		case strings.HasPrefix(r.URL.Path, "/download/"):
			fmt.Fprintf(w, `{"artifacts":[{"sha256":%q}]}`, strings.Repeat("0", 64))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for i := range releases[:25] {
		releases[i]["assets"].([]map[string]any)[0]["browser_download_url"] = server.URL + "/download/" + strconv.Itoa(i)
	}

	run := func(pins string) (string, error) {
		path := filepath.Join(t.TempDir(), "pins")
		if err := os.WriteFile(path, []byte(pins), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), "bash", "prune-releases.sh", "TerraScale/demo", path)
		cmd.Env = append(os.Environ(), "FORGEJO_SERVER_URL="+server.URL, "FORGEJO_TOKEN="+token)
		output, err := cmd.CombinedOutput()
		if strings.Contains(string(output), token) {
			t.Fatalf("the token leaked into the output:\n%s", output)
		}
		return string(output), err
	}

	if output, err := run("no pins here\n"); err == nil || len(deleted) > 0 {
		t.Fatalf("pruned without pins: %v %v\n%s", err, deleted, output)
	}
	// Release 21 is pinned by its revision inside fleet-status JSON, 22 by
	// a digest its manifest names, 23 by a manifest that cannot be read.
	output, err := run(fmt.Sprintf(`{"cell":"GRU","channel":{"source_revision":%q}}`+"\n%s\n", revision(21), digest))
	if err != nil {
		t.Fatalf("prune: %v\n%s", err, output)
	}
	slices.Sort(deleted)
	if !slices.Equal(deleted, []string{"20", "24"}) ||
		!strings.Contains(output, "TS_RELEASE_PRUNE_V1 repository=TerraScale/demo releases=26 deleted=2 kept_pinned=3 bytes=2020 dry_run=false") {
		t.Fatalf("deleted %v\n%s", deleted, output)
	}
}
