package swarmruntime

import (
	"errors"
	"strings"
	"testing"
)

// Merges that land close together release in run order; an older run that
// releases after a newer one is superseded, not failed, while a rerun that
// rebuilt a different image under an approved run stays refused.
func TestDeploymentAcceptsSupersededAndRefusesChangedRuns(t *testing.T) {
	image := func(digit string) string { return "ghcr.io/terrascale/ts-auth@sha256:" + strings.Repeat(digit, 64) }
	floor := &Deployment{Repository: "TerraScale/terrascale", RunID: "200", Revision: strings.Repeat("b", 40), Image: image("b")}

	older := &Deployment{Repository: floor.Repository, RunID: "100", Revision: strings.Repeat("a", 40), Image: image("a")}
	if err := floor.Accepts(older); !errors.Is(err, ErrSupersededDeployment) {
		t.Fatalf("older run: %v, want ErrSupersededDeployment", err)
	}

	rebuilt := *floor
	rebuilt.Image = image("c")
	if err := floor.Accepts(&rebuilt); err == nil || errors.Is(err, ErrSupersededDeployment) {
		t.Fatalf("rebuilt image under the approved run: %v, want a refusal that is not superseded", err)
	}

	other := *floor
	other.Repository, other.RunID = "TerraScale/ts-dashboard", "300"
	if err := floor.Accepts(&other); err == nil || errors.Is(err, ErrSupersededDeployment) {
		t.Fatalf("another repository: %v, want a refusal that is not superseded", err)
	}

	same, newer := *floor, *floor
	newer.RunID = "300"
	for _, next := range []*Deployment{&same, &newer} {
		if err := floor.Accepts(next); err != nil {
			t.Fatalf("run %s: %v, want accepted", next.RunID, err)
		}
	}
}

func TestDeploymentAttemptOrdering(t *testing.T) {
	floor := Deployment{Repository: "TerraScale/terrascale", RunID: "200", RunAttempt: 2, Revision: strings.Repeat("b", 40), Image: "ghcr.io/terrascale/ts-auth@sha256:" + strings.Repeat("b", 64)}
	for _, tc := range []struct {
		name    string
		change  func(*Deployment)
		refused bool
	}{
		{"identical", func(*Deployment) {}, false},
		{"lower attempt", func(d *Deployment) { d.RunAttempt-- }, true},
		{"legacy attempt", func(d *Deployment) { d.RunAttempt = 0 }, true},
		{"same attempt rebuilt", func(d *Deployment) { d.Image = strings.ReplaceAll(d.Image, "b", "c") }, true},
		{"higher attempt", func(d *Deployment) { d.RunAttempt++ }, false},
		// A re-run rebuilds its image; it retries the run's failed release.
		{"higher attempt rebuilt", func(d *Deployment) { d.RunAttempt++; d.Image = strings.ReplaceAll(d.Image, "b", "c") }, false},
		{"higher attempt changed commit", func(d *Deployment) { d.RunAttempt++; d.Revision = strings.Repeat("c", 40) }, true},
		{"newer run first attempt", func(d *Deployment) { d.RunID, d.RunAttempt = "201", 1 }, false},
	} {
		next := floor
		tc.change(&next)
		err := floor.Accepts(&next)
		if (err != nil) != tc.refused || err != nil && err.Error() != "deployment changes an already approved run; release from a newer signed run" {
			t.Errorf("%s: %v, refused=%v", tc.name, err, tc.refused)
		}
	}
}

func TestDashboardPackageHandoff(t *testing.T) {
	old := &Deployment{Repository: "TerraScale/ts-dashboard", RunID: "200", Revision: strings.Repeat("a", 40), Image: "ghcr.io/terrascale/ts-dashboard@sha256:" + strings.Repeat("a", 64)}
	next := &Deployment{Repository: "TerraScale/terrascale", RunID: "201", Revision: strings.Repeat("b", 40), Image: "ghcr.io/terrascale/terrascale-dashboard@sha256:" + strings.Repeat("b", 64)}
	if err := old.Accepts(next); err != nil {
		t.Fatalf("new package handoff: %v", err)
	}
	for _, d := range []*Deployment{old, next} {
		if err := validateServiceDeployment("ts-dashboard", d, d); err != nil {
			t.Fatal(err)
		}
		if err := validateServiceDeployment("ts-auth", d, d); err == nil {
			t.Fatal("dashboard image accepted for auth")
		}
	}
	if err := next.Accepts(old); err == nil {
		t.Fatal("old repository regained authority")
	}
	older := *next
	older.RunID = "199"
	if err := old.Accepts(&older); err == nil {
		t.Fatal("older run crossed repository floor")
	}
	unrelated := *next
	unrelated.Image = "ghcr.io/terrascale/ts-auth@sha256:" + strings.Repeat("b", 64)
	if err := old.Accepts(&unrelated); err == nil {
		t.Fatal("another service crossed repository floor")
	}
}
