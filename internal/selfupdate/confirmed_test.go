package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestConfirmedHistorySurvivesPruningAndReopen(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	var confirmed []string
	for index := range ConfirmedReleaseHistory + 2 {
		digest := f.stage([]byte(fmt.Sprintf("confirmed build %d", index)))
		at := f.now.Add(time.Duration(index) * 3 * time.Second)
		activation, err := Activate(f.layout, digest, testUnit, at, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if outcome, _, err := Watch(f.layout, testUnit, f.proof(activation, at.Add(time.Second)), at.Add(time.Second)); err != nil || outcome != OutcomeConfirmed {
			t.Fatalf("confirm %d: %s %v", index, outcome, err)
		}
		confirmed = append(confirmed, digest)
	}
	unproven := f.stage([]byte("staged but never confirmed"))
	// A new Layout reads durable history after a process restart.
	reopened := Layout{Root: f.layout.Root, Owner: f.layout.Owner}
	want := slices.Clone(confirmed[2:])
	slices.Reverse(want)
	if got, err := reopened.ConfirmedReleases(); err != nil || !slices.Equal(got, want) {
		t.Fatalf("retained confirmations: %v %v; want %v", got, err, want)
	}
	removed, err := reopened.PruneReleases(f.now.Add(2 * StagedReleaseRetention))
	if err != nil {
		t.Fatal(err)
	}
	wantRemoved := slices.Sorted(slices.Values(append(slices.Clone(confirmed[:2]), unproven)))
	if !slices.Equal(slices.Sorted(slices.Values(removed)), wantRemoved) {
		t.Fatalf("pruned %v; want %v", removed, wantRemoved)
	}
	for _, digest := range append(want, baked) {
		if err := reopened.VerifyRelease(digest); err != nil {
			t.Fatalf("retained bytes %s: %v", digest, err)
		}
	}
}

func TestRejectedReleaseNeverEntersConfirmedHistory(t *testing.T) {
	f := newFixture(t)
	if _, err := Seed(f.layout, f.baked); err != nil {
		t.Fatal(err)
	}
	good := f.stage([]byte("confirmed predecessor"))
	activation, err := Activate(f.layout, good, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(f.layout, testUnit, f.proof(activation, f.now.Add(time.Second)), f.now.Add(time.Second)); err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("confirm: %s %v", outcome, err)
	}
	bad := f.stage([]byte("candidate without a proof"))
	activation, err = Activate(f.layout, bad, testUnit, f.now.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(f.layout, testUnit, ProofCheck{}, activation.Deadline); err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("reject: %s %v", outcome, err)
	}
	if got, err := f.layout.ConfirmedReleases(); err != nil || !slices.Equal(got, []string{good}) {
		t.Fatalf("rejected candidate entered history: %v %v", got, err)
	}
	if err := f.layout.markKnownBad(good); err != nil {
		t.Fatal(err)
	}
	if got, err := f.layout.ConfirmedReleases(); err != nil || len(got) != 0 {
		t.Fatalf("subsequently rejected release remains eligible: %v %v", got, err)
	}
}

func TestInterruptedConfirmationReplaysOneHistoryEntry(t *testing.T) {
	f := newFixture(t)
	if _, err := Seed(f.layout, f.baked); err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("confirmed before link failure"))
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// The durable history write succeeds; the following link commit fails.
	path := filepath.Join(f.layout.Root, knownGoodLink)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	proof := f.proof(activation, f.now.Add(time.Second))
	if outcome, _, err := Watch(f.layout, testUnit, proof, f.now.Add(time.Second)); err == nil || outcome != OutcomePending {
		t.Fatalf("failed link commit: %s %v", outcome, err)
	}
	if _, pending, err := f.layout.Pending(); err != nil || !pending {
		t.Fatalf("interruption lost activation: %t %v", pending, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := Watch(f.layout, testUnit, proof, f.now.Add(2*time.Second)); err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("confirmation replay: %s %v", outcome, err)
	}
	if got, err := f.layout.ConfirmedReleases(); err != nil || !slices.Equal(got, []string{target}) {
		t.Fatalf("confirmation replay duplicated history: %v %v", got, err)
	}
	if known, err := f.layout.KnownGood(); err != nil || known != target {
		t.Fatalf("confirmation replay did not commit the delegate: %q %v", known, err)
	}
}

func TestUnsafeConfirmedHistoryStopsConfirmationAndPruning(t *testing.T) {
	for _, attack := range []string{"corrupt", "duplicate", "symlink", "writable"} {
		t.Run(attack, func(t *testing.T) {
			f := newFixture(t)
			if _, err := Seed(f.layout, f.baked); err != nil {
				t.Fatal(err)
			}
			old := f.stage([]byte("old settled directory"))
			target := f.stage([]byte("target with a valid proof"))
			activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.layout.Root, confirmedReleasesFile)
			wire := []byte(`{"schema":"` + confirmedReleasesSchema + `","releases":[]}`)
			switch attack {
			case "corrupt":
				wire = []byte(`{"schema":"` + confirmedReleasesSchema + `","releases":["invalid"]}`)
			case "duplicate":
				wire = []byte(`{"schema":"` + confirmedReleasesSchema + `","releases":["` + old + `","` + old + `"]}`)
			case "symlink":
				if err := os.Symlink(f.layout.BinaryPath(old), path); err != nil {
					t.Fatal(err)
				}
			}
			if attack != "symlink" {
				if err := os.WriteFile(path, wire, 0o644); err != nil {
					t.Fatal(err)
				}
				if attack == "writable" {
					if err := os.Chmod(path, 0o666); err != nil {
						t.Fatal(err)
					}
				}
			}
			if outcome, _, err := Watch(f.layout, testUnit, f.proof(activation, f.now.Add(time.Second)), f.now.Add(time.Second)); err == nil || outcome != OutcomePending {
				t.Fatalf("unsafe history confirmed: %s %v", outcome, err)
			}
			if _, pending, err := f.layout.Pending(); err != nil || !pending {
				t.Fatalf("confirmation failure lost recovery record: %t %v", pending, err)
			}
			if known, err := f.layout.KnownGood(); err != nil || known != "" {
				t.Fatalf("confirmation failure moved known-good: %q %v", known, err)
			}
			if removed, err := f.layout.PruneReleases(f.now.Add(2 * StagedReleaseRetention)); err == nil || len(removed) != 0 {
				t.Fatalf("unsafe history allowed pruning: %v %v", removed, err)
			}
			if err := f.layout.VerifyRelease(old); err != nil {
				t.Fatalf("unsafe history deleted retained bytes: %v", err)
			}
		})
	}
}
