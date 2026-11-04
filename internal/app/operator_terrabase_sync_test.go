package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

type cdTestFeed struct {
	t         *testing.T
	releases  map[string]terrabaseReleaseFiles
	commits   []string
	listing   []string
	badRun    bool
	badLog    bool
	calls     int
	downloads []string
}

func newCDTestFeed(t *testing.T) *cdTestFeed {
	t.Helper()
	return &cdTestFeed{t: t, releases: make(map[string]terrabaseReleaseFiles)}
}

func (feed *cdTestFeed) add(root, version string, runID uint64) string {
	feed.t.Helper()
	files := writeDeployTestRelease(feed.t, root, version)
	wire, err := os.ReadFile(files.Qualification)
	if err != nil {
		feed.t.Fatal(err)
	}
	var qualification map[string]any
	if err := json.Unmarshal(wire, &qualification); err != nil {
		feed.t.Fatal(err)
	}
	qualification["repository"] = "TerraScale/TerraBase"
	verification := qualification["verification"].(map[string]any)
	verification["run_id"], verification["run_number"], verification["job"] = runID, runID+1000, "fast"
	wire, err = json.Marshal(qualification)
	if err != nil {
		feed.t.Fatal(err)
	}
	if err := os.WriteFile(files.Qualification, wire, 0o600); err != nil {
		feed.t.Fatal(err)
	}
	var source terrabaseSourceDigest
	sourceWire, err := os.ReadFile(files.SourceDigest)
	if err != nil {
		feed.t.Fatal(err)
	}
	if err := json.Unmarshal(sourceWire, &source); err != nil {
		feed.t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	source.QualificationSHA256 = hex.EncodeToString(sum[:])
	sourceWire, err = json.Marshal(source)
	if err != nil {
		feed.t.Fatal(err)
	}
	if err := os.WriteFile(files.SourceDigest, sourceWire, 0o600); err != nil {
		feed.t.Fatal(err)
	}
	tag := fmt.Sprintf("ci-%s-run-%d", source.SourceRevision, runID)
	feed.releases[tag] = files
	feed.commits = append(feed.commits, source.SourceRevision)
	feed.listing = append(feed.listing, tag)
	return tag
}

func (feed *cdTestFeed) run(_ context.Context, name string, args ...string) ([]byte, error) {
	feed.calls++
	if name == "git" {
		switch args[2] {
		case "remote":
			return []byte(terrabaseSourceRepo + ".git\n"), nil
		case "fetch":
			return nil, nil
		case "merge-base":
			left, right := slices.Index(feed.commits, args[4]), slices.Index(feed.commits, args[5])
			if args[5] == "refs/remotes/origin/main" {
				right = len(feed.commits) - 1
			}
			if left < 0 || right < 0 || left > right {
				return nil, errCDNotAncestor
			}
			return nil, nil
		}
	}
	if name != "gh" {
		feed.t.Fatalf("unexpected command: %s %v", name, args)
	}
	if args[0] == "release" && args[1] == "list" {
		var releases []map[string]any
		for _, tag := range feed.listing {
			releases = append(releases, map[string]any{"tagName": tag, "isDraft": false, "isPrerelease": true})
		}
		return json.Marshal(releases)
	}
	if args[0] == "release" && args[1] == "download" {
		feed.downloads = append(feed.downloads, args[6])
		files := feed.releases[args[2]]
		source := map[string]string{"qualification.json": files.Qualification, terrabaseServerArtifact: files.Binary, "source-digest.json": files.SourceDigest}[args[6]]
		wire, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(args[8], wire, 0o600)
	}
	if args[0] == "api" {
		if len(args) < 4 || args[1] != "--hostname" || args[2] != "github.com" {
			feed.t.Fatalf("GitHub API hostname is not pinned: %v", args)
		}
		endpoint := args[len(args)-1]
		parts := strings.Split(endpoint, "/")
		id, err := strconv.ParseUint(parts[5], 10, 64)
		if err != nil {
			return nil, err
		}
		for tag, files := range feed.releases {
			match := cdTagPattern.FindStringSubmatch(tag)
			runID, _ := strconv.ParseUint(match[2], 10, 64)
			if runID != id {
				continue
			}
			if parts[4] == "runs" && len(parts) == 6 {
				status, conclusion := "completed", "success"
				if feed.badRun {
					status, conclusion = "in_progress", ""
				}
				return json.Marshal(map[string]any{"id": id, "run_number": id + 1000, "head_sha": match[1], "head_branch": "main", "event": "push",
					"path": ".github/workflows/fast.yml", "status": status, "conclusion": conclusion, "run_attempt": 1,
					"repository":      map[string]string{"full_name": terrabaseGitHubRepo},
					"head_repository": map[string]string{"full_name": terrabaseGitHubRepo}})
			}
			if parts[4] == "runs" && strings.Contains(endpoint, "/attempts/1/jobs") {
				return json.Marshal([]map[string]any{{"jobs": []map[string]any{
					{"id": 1, "run_id": id, "name": "fast", "status": "completed", "conclusion": "success", "run_attempt": 1},
					{"id": id, "run_id": id, "name": "publish", "status": "completed", "conclusion": "success", "run_attempt": 1}}}})
			}
			if parts[4] == "jobs" {
				if feed.badLog {
					return []byte("unrelated qualification"), nil
				}
				wire, err := os.ReadFile(files.Qualification)
				if err != nil {
					return nil, err
				}
				sum := sha256.Sum256(wire)
				return fmt.Appendf(nil, "2026-09-30T00:00:00Z TS_TERRABASE_QUALIFICATION_V2 source_sha=%s run_id=%d run_number=%d manifest_sha256=%x\n", match[1], id, id+1000, sum), nil
			}
		}
	}
	feed.t.Fatalf("unexpected command: %s %v", name, args)
	return nil, errors.New("unexpected command")
}

func cdTestState(t *testing.T, root string, files terrabaseReleaseFiles) string {
	t.Helper()
	statePath := filepath.Join(root, "state")
	state, err := openDeployState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	release, err := loadTerraBaseRelease(files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.ensureJSON(deployArtifactFile, delivery.ArtifactRecord{Digest: release.Digest, Source: release.Source}); err != nil {
		t.Fatal(err)
	}
	return statePath
}

func TestTerraBaseSyncRejectsUnqualifiedOrChangedInputsBeforeUpdating(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 20)
	feed.badRun = true
	if err := syncTerraBase(t.Context(), state, root, feed.run, func(terrabaseReleaseFiles) error {
		t.Fatal("non-green main reached the updater")
		return nil
	}, io.Discard); err == nil {
		t.Fatal("non-green main was admitted")
	}
	if _, err := os.Stat(filepath.Join(state, cdActiveFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unverified release pinned: %v", err)
	}
	if slices.Contains(feed.downloads, terrabaseServerArtifact) {
		t.Fatal("large server downloaded before publication readiness was checked")
	}
}

func TestTerraBaseSyncCompletesRealSignedRollingUpdateAndLatchesRollback(t *testing.T) {
	cell := startDeployTestCell(t, true, true)
	plan, state := writeDeployTestPlan(t, cell.root, 9465)
	runDeployTestOperator(t, t.Context(), cell, "terrabase-deploy", "--plan", plan, "--state", state)
	var intent placement.Intent
	readDeployTestState(t, state, deployIntentFile, &intent)
	controller := startFakeRolloutController(t, cell, intent)
	feed := newCDTestFeed(t)
	feed.add(cell.root, "1", 10)
	feed.add(cell.root, "2", 20)
	update := func(files terrabaseReleaseFiles) error {
		_, err := runDeployTestOperatorErr(t.Context(), cell, "terrabase-update", "--state", state,
			"--qualification", files.Qualification, "--binary", files.Binary, "--source-digest", files.SourceDigest,
			"--compatibility-actor", "compatibility", "--compatibility-key", cell.root+"/compatibility.key", "--wait", "30s", "--soak", "1s")
		return err
	}
	if err := syncTerraBase(t.Context(), state, cell.root, feed.run, update, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(controller.prepares) != 2 || controller.prepares[0].CanarySeatID != "000000000082AXF7GZQT1D126Y" || controller.prepares[1].CanarySeatID != "0000000000XG8SBD7XGE97V28G" {
		t.Fatalf("automatic release did not update both seats sequentially: %+v", controller.prepares)
	}
	third := feed.add(cell.root, "3", 30)
	controller.failing, _, _ = digestReleaseBinary(feed.releases[third].Binary)
	if err := syncTerraBase(t.Context(), state, cell.root, feed.run, update, io.Discard); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("held candidate not rolled back: %v", err)
	}
	if len(controller.prepares) != 4 || controller.seats[0].pins.ArtifactDigest != controller.seats[1].pins.ArtifactDigest || !controller.seats[1].serving {
		t.Fatalf("rollback changed peer or did not restore canary: %+v", controller.prepares)
	}
	if err := syncTerraBase(t.Context(), state, cell.root, feed.run, update, io.Discard); err == nil || !strings.Contains(err.Error(), "automatic rollout stopped") {
		t.Fatal(err)
	}
}
