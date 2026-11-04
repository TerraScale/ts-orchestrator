package selfupdate

import (
	"fmt"

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
