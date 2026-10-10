package globalcontrol

import (
	"testing"
	"time"
)

func TestHeartbeatValidation(t *testing.T) {
	t.Parallel()
	valid := Heartbeat{Version: 1, Cell: "sfo", OCIRegion: "us-sanjose-1", SentAt: time.Now()}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Heartbeat){
		"version":    func(h *Heartbeat) { h.Version = 2 },
		"global":     func(h *Heartbeat) { h.Cell = "global" },
		"cell":       func(h *Heartbeat) { h.Cell = "SFO" },
		"oci region": func(h *Heartbeat) { h.OCIRegion = "" },
		"long":       func(h *Heartbeat) { h.OCIRegion = string(make([]byte, 65)) },
		"charset":    func(h *Heartbeat) { h.OCIRegion = "US_SANJOSE 1" },
		"short":      func(h *Heartbeat) { h.OCIRegion = "us" },
		"sent":       func(h *Heartbeat) { h.SentAt = time.Time{} },
	} {
		heartbeat := valid
		mutate(&heartbeat)
		if heartbeat.Validate() == nil {
			t.Errorf("%s accepted: %+v", name, heartbeat)
		}
	}
}

func TestNextRosterFollowsHeartbeats(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	heard := func(cell, ociRegion string, age time.Duration) Heartbeat {
		return Heartbeat{Version: 1, Cell: cell, OCIRegion: ociRegion, SentAt: now.Add(-age)}
	}
	seen := map[string]Heartbeat{
		"gru": heard("gru", "sa-saopaulo-1", 0),
		"sfo": heard("sfo", "us-sanjose-1", time.Second),
		"fra": heard("fra", "eu-frankfurt-1", RegionSilence),
	}

	first, changed := NextRoster(Roster{}, "gru", seen, now)
	if !changed || first.Generation != 1 || first.HomeRegion != "gru" || first.Validate() != nil {
		t.Fatalf("first roster = %+v, changed %v", first, changed)
	}
	if len(first.Regions) != 2 || first.Regions[0].Cell != "gru" || first.Regions[1].Cell != "sfo" ||
		!first.Active("sfo") || first.Active("fra") {
		t.Fatalf("regions = %+v", first.Regions)
	}

	if kept, changed := NextRoster(first, "gru", seen, now.Add(time.Minute)); changed || kept.Generation != 1 {
		t.Fatalf("unchanged roster = %+v, changed %v", kept, changed)
	}

	seen["fra"] = heard("fra", "eu-frankfurt-1", 0)
	added, changed := NextRoster(first, "gru", seen, now)
	if !changed || added.Generation != 2 || len(added.Regions) != 3 || !added.Active("fra") {
		t.Fatalf("added roster = %+v, changed %v", added, changed)
	}

	// Silence drops a region; the home stays even when its own heartbeat is gone.
	delete(seen, "gru")
	dropped, changed := NextRoster(added, "gru", seen, now.Add(RegionSilence))
	if !changed || dropped.Generation != 3 || len(dropped.Regions) != 1 || dropped.Regions[0].Cell != "gru" ||
		dropped.Regions[0].OCIRegion != "sa-saopaulo-1" || dropped.Validate() != nil {
		t.Fatalf("dropped roster = %+v, changed %v", dropped, changed)
	}
}
