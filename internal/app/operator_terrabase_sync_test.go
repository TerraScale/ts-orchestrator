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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
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
	verification["run_id"], verification["run_number"], verification["job"] = runID, runID, "fast"
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
	feed.listing = append(feed.listing, "\u2068"+tag+"\u2069 (prerelease)")
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
	if name != "fj" {
		feed.t.Fatalf("unexpected command: %s %v", name, args)
	}
	if args[0] == "release" && args[1] == "list" {
		return []byte(strings.Join(feed.listing, "\n")), nil
	}
	if args[0] == "release" && args[1] == "asset" {
		feed.downloads = append(feed.downloads, args[8])
		files := feed.releases[args[7]]
		source := map[string]string{"qualification.json": files.Qualification, terrabaseServerArtifact: files.Binary, "source-digest.json": files.SourceDigest}[args[8]]
		wire, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(args[10], wire, 0o600)
	}
	if args[0] == "actions" {
		id, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			return nil, err
		}
		for tag, files := range feed.releases {
			match := cdTagPattern.FindStringSubmatch(tag)
			runID, _ := strconv.ParseUint(match[2], 10, 64)
			if runID != id {
				continue
			}
			if args[1] == "run-detail" {
				status := "success"
				if feed.badRun {
					status = "running"
				}
				return json.Marshal(map[string]any{"run_id": id, "run_number": id, "head_sha": match[1],
					"workflow": "fast.yml", "status": status, "jobs": []map[string]any{
						{"id": 1, "run_id": id, "name": "fast", "status": "success"},
						{"id": id, "run_id": id, "name": "publish", "status": "success"}}})
			}
			if args[1] == "job-logs" {
				if feed.badLog {
					return []byte("unrelated qualification"), nil
				}
				wire, err := os.ReadFile(files.Qualification)
				if err != nil {
					return nil, err
				}
				sum := sha256.Sum256(wire)
				return fmt.Appendf(nil, "2026-09-30T00:00:00Z TS_TERRABASE_QUALIFICATION_V2 source_sha=%s run_id=%d run_number=%d manifest_sha256=%x\n", match[1], id, id, sum), nil
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

func TestTerraBaseSyncSelectsNewestSourceAndDoesNotRepeatCompletedRollout(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 100) // Older source was rerun after version 3.
	latest := feed.add(root, "3", 30)
	feed.listing = append(feed.listing, "ci-"+strings.Repeat("f", 40)+"-run-200", "irrelevant ci-tag")
	updates := 0
	update := func(files terrabaseReleaseFiles) error {
		updates++
		release, err := loadTerraBaseRelease(files)
		if err != nil || release.CIRunID != 30 {
			t.Fatalf("selected release: %+v %v", release, err)
		}
		return nil
	}
	for range 2 {
		if err := syncTerraBase(t.Context(), state, root, feed.run, update, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	var completed terrabaseCDCandidate
	readDeployTestState(t, state, cdReceiptName(1), &completed)
	if updates != 1 || completed.Tag != latest {
		t.Fatalf("updates=%d completion=%+v", updates, completed)
	}
	// Crash recovery after the completion receipt is synced must remove the
	// stale active pin without contacting Forgejo or running another update.
	journal, err := openDeployState(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ensureJSON(cdActiveFile, completed); err != nil {
		t.Fatal(err)
	}
	if err := syncTerraBase(t.Context(), state, root, nil, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, cdActiveFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale active pin retained: %v", err)
	}
}

func TestTerraBaseSyncRejectsUnqualifiedOrChangedInputsBeforeUpdating(t *testing.T) {
	for _, failure := range []string{"binary", "source digest", "run", "publish log", "origin", "git error"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			feed := newCDTestFeed(t)
			initial := feed.add(root, "1", 10)
			state := cdTestState(t, root, feed.releases[initial])
			latest := feed.add(root, "2", 20)
			run := feed.run
			switch failure {
			case "binary":
				if err := os.WriteFile(feed.releases[latest].Binary, []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "source digest":
				if err := os.Remove(feed.releases[latest].SourceDigest); err != nil {
					t.Fatal(err)
				}
			case "run":
				feed.badRun = true
			case "publish log":
				feed.badLog = true
			case "origin", "git error":
				run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
					if name == "git" && args[2] == "remote" && failure == "origin" {
						return []byte("https://example.com/unreviewed.git"), nil
					}
					if name == "git" && args[2] == "merge-base" && failure == "git error" {
						return nil, errors.New("git repository corrupt")
					}
					return feed.run(ctx, name, args...)
				}
			}
			if err := syncTerraBase(t.Context(), state, root, run, func(terrabaseReleaseFiles) error {
				t.Fatal("unqualified input reached the updater")
				return nil
			}, io.Discard); err == nil {
				t.Fatal("unqualified release accepted")
			}
			if _, err := os.Stat(filepath.Join(state, cdActiveFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unverified release pinned: %v", err)
			}
			if failure != "binary" && slices.Contains(feed.downloads, terrabaseServerArtifact) {
				t.Fatal("large server downloaded before publication readiness was checked")
			}
		})
	}
}

func TestTerraBaseSyncResumesPinnedReleaseBeforeConsideringNewerPublication(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	second := feed.add(root, "2", 20)
	ctx, cancel := context.WithCancel(t.Context())
	err := syncTerraBase(ctx, state, root, feed.run, func(terrabaseReleaseFiles) error {
		cancel()
		return context.Canceled
	}, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	feed.add(root, "3", 30)
	if err := syncTerraBase(t.Context(), state, root, feed.run, func(files terrabaseReleaseFiles) error {
		release, err := loadTerraBaseRelease(files)
		if err != nil || release.CIRunID != 20 {
			t.Fatalf("interrupted pin was replaced: %+v %v", release, err)
		}
		return nil
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	var completed terrabaseCDCandidate
	readDeployTestState(t, state, cdReceiptName(1), &completed)
	if completed.Tag != second {
		t.Fatalf("completed = %+v", completed)
	}
}

func TestTerraBaseSyncStopsAfterFailureAndLocksOverlappingInvocations(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	feed.add(root, "2", 20)
	err := syncTerraBase(t.Context(), state, root, feed.run, func(terrabaseReleaseFiles) error {
		if err := syncTerraBase(t.Context(), state, root, feed.run, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "holds this deployment") {
			t.Fatalf("overlapping sync accepted: %v", err)
		}
		return errors.New("candidate held and rolled back")
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "held") {
		t.Fatal(err)
	}
	feed.add(root, "3", 30)
	calls := feed.calls
	if err := syncTerraBase(t.Context(), state, root, feed.run, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "automatic rollout stopped") {
		t.Fatalf("failed candidate not blocked: %v", err)
	}
	if feed.calls != calls {
		t.Fatal("blocked sync contacted the release producer")
	}
}

func TestTerraBaseSyncRejectsAssetMutationDuringResume(t *testing.T) {
	root := t.TempDir()
	feed := newCDTestFeed(t)
	initial := feed.add(root, "1", 10)
	state := cdTestState(t, root, feed.releases[initial])
	second := feed.add(root, "2", 20)
	ctx, cancel := context.WithCancel(t.Context())
	_ = syncTerraBase(ctx, state, root, feed.run, func(terrabaseReleaseFiles) error { cancel(); return context.Canceled }, io.Discard)
	var source terrabaseSourceDigest
	wire, err := os.ReadFile(feed.releases[second].SourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &source); err != nil {
		t.Fatal(err)
	}
	source.SourceDigestSHA256 = strings.Repeat("a", 64)
	wire, err = json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feed.releases[second].SourceDigest, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncTerraBase(t.Context(), state, root, feed.run, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "assets changed") {
		t.Fatalf("changed source accepted on resume: %v", err)
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
			"--compatibility-actor", "compatibility", "--compatibility-key", cell.root+"/compatibility.key", "--wait", "30s")
		return err
	}
	if err := syncTerraBase(t.Context(), state, cell.root, feed.run, update, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(controller.prepares) != 2 || controller.prepares[0].CanarySeatID != "permanent-a" || controller.prepares[1].CanarySeatID != "elastic-gru" {
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

func TestTerraBaseSyncCLIRejectsIncompleteOptionsWithoutContactingCell(t *testing.T) {
	if err := runOperator(t.Context(), []string{"terrabase-sync"}, io.Discard); err == nil || !strings.Contains(err.Error(), "requires --config") {
		t.Fatal(err)
	}
	if _, err := cdCommand(t.Context(), "git", "-C", t.TempDir(), "merge-base", "--is-ancestor", "bad", "bad"); errors.Is(err, errCDNotAncestor) || err == nil {
		t.Fatalf("git failure confused with a source lineage rejection: %v", err)
	}
	var output cdCommandOutput
	if _, err := output.Write(make([]byte, (8<<20)+1)); err == nil {
		t.Fatal("unbounded command output")
	}
}
