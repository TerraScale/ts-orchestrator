package rolloutexec

import (
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

func TestHostUnitsGroupEveryHostThatSharesAPartition(t *testing.T) {
	units := HostUnits(map[string][]string{
		"h1": {"p1"}, "h2": {"p1", "p2"}, "h3": {"p2"}, "h4": {"p3"}, "h5": {"p3"}, "h6": nil,
	})
	group := map[string]string{}
	for _, unit := range units {
		group[unit.ID] = unit.Group
	}
	if group["h1"] != group["h2"] || group["h2"] != group["h3"] {
		t.Fatalf("hosts linked through p1 and p2 are in different groups: %v", group)
	}
	if group["h4"] != group["h5"] || group["h4"] == group["h1"] || group["h6"] == group["h1"] || group["h6"] == group["h4"] {
		t.Fatalf("unrelated hosts share a group: %v", group)
	}
	again := HostUnits(map[string][]string{
		"h6": nil, "h5": {"p3"}, "h4": {"p3"}, "h3": {"p2"}, "h2": {"p2", "p1"}, "h1": {"p1"},
	})
	for _, unit := range again {
		if group[unit.ID] != unit.Group {
			t.Fatalf("grouping depends on input order: %s %s != %s", unit.ID, unit.Group, group[unit.ID])
		}
	}
	policy := testPolicy()
	policy.BatchSize = 3
	waves, err := rollout.PlanWaves(units, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, wave := range waves {
		seen := map[string]bool{}
		for _, id := range wave {
			if seen[group[id]] {
				t.Fatalf("a wave takes two seats of one partition group: %v", waves)
			}
			seen[group[id]] = true
		}
	}
}

func TestControllerUnitsPutTheSeedLast(t *testing.T) {
	if _, err := ControllerUnits([]string{"ctl-a", "ctl-b"}, "ctl-z"); err == nil {
		t.Fatal("a seed outside the controllers was accepted")
	}
	units, err := ControllerUnits([]string{"ctl-a", "ctl-b", "ctl-c"}, "ctl-a")
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy()
	policy.BatchSize = 3
	waves, err := rollout.PlanWaves(units, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(waves) != 3 || waves[2][0] != "ctl-a" {
		t.Fatalf("controller waves = %v, want one controller per wave and the seed last", waves)
	}
}
