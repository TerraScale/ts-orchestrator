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
