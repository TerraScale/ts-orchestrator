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
// a fake GitHub with 25 daily CI pre-releases and a stable release.
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
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodDelete:
			mu.Lock()
			deleted = append(deleted, filepath.Base(r.URL.Path))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/repos/TerraScale/demo/releases":
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			start, end := min((page-1)*20, len(releases)), min(page*20, len(releases))
			if err := json.MarshalWrite(w, releases[start:end]); err != nil {
				t.Error(err)
			}
		case r.URL.Path == "/download/22":
			fmt.Fprintf(w, `{"artifacts":[{"sha256":%q}]}`, digest)
		case r.URL.Path == "/download/23":
			http.Error(w, "broken", http.StatusInternalServerError)
		case r.URL.Path == "/download/24":
			fmt.Fprintf(w, `{"artifacts":[{"sha256":%q}]}`, strings.Repeat("e", 64))
		case strings.HasPrefix(r.URL.Path, "/download/"):
			fmt.Fprintf(w, `{"artifacts":[{"sha256":%q}]}`, strings.Repeat("0", 64))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	bin := t.TempDir()
	gh := `#!/usr/bin/env bash
set -euo pipefail
[[ $GH_HOST == github.com ]] || exit 2
if [[ $1 == api ]]; then
	shift
	if [[ $1 == --method ]]; then
		[[ $2 == DELETE ]] || exit 2
		curl --fail --silent --show-error -X DELETE -H "Authorization: Bearer $GH_TOKEN" "$MOCK_GITHUB_API/$3"
	else
		[[ $1 == 'repos/TerraScale/demo/releases?per_page=50&page='* ]] || exit 2
		curl --fail --silent --show-error -H "Authorization: Bearer $GH_TOKEN" "$MOCK_GITHUB_API/$1"
	fi
elif [[ $1 == release && $2 == download ]]; then
	[[ $4 == --repo && $5 == TerraScale/demo && $6 == --pattern && $7 == qualification.json && $8 == --output ]] || exit 2
	id=${3##*-run-}
	curl --fail --silent --show-error -H "Authorization: Bearer $GH_TOKEN" "$MOCK_GITHUB_API/download/$((id - 100))" -o "$9"
else
	exit 2
fi
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(gh), 0o700); err != nil {
		t.Fatal(err)
	}

	run := func(pins string) (string, error) {
		path := filepath.Join(t.TempDir(), "pins")
		if err := os.WriteFile(path, []byte(pins), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), "bash", "prune-releases.sh", "TerraScale/demo", path)
		cmd.Env = append(os.Environ(), "MOCK_GITHUB_API="+server.URL, "GH_TOKEN="+token, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
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
	// the rollback digest, 23 by a manifest that cannot be read, and 24
	// by the known-bad digest. All pins come from fleet-status JSON.
	output, err := run(fmt.Sprintf(`{"cell":"GRU","channel":{"source_revision":%q},"status":{"pins":{"rollback":[%q],"known_bad":[%q]}}}`+"\n", revision(21), digest, strings.Repeat("e", 64)))
	if err != nil {
		t.Fatalf("prune: %v\n%s", err, output)
	}
	slices.Sort(deleted)
	if !slices.Equal(deleted, []string{"20"}) ||
		!strings.Contains(output, "TS_RELEASE_PRUNE repository=TerraScale/demo releases=26 deleted=1 kept_pinned=4 bytes=1010 dry_run=false") {
		t.Fatalf("deleted %v\n%s", deleted, output)
	}
	mu.Lock()
	deleted = nil
	mu.Unlock()
	output, err = run(revision(21))
	if err != nil {
		t.Fatalf("prune without digest pins: %v\n%s", err, output)
	}
	slices.Sort(deleted)
	if !slices.Equal(deleted, []string{"20", "22", "24"}) {
		t.Fatalf("unreadable qualification was not retained without digest pins: %v\n%s", deleted, output)
	}

}
