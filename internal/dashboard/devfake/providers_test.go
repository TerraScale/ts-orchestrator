package devfake

import (
	"context"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
)

// The providers below stand in for slices that are still being built
// (rollout, storage, trust, netbird, autoscale, regionsuggest, CI, OCI
// inventory), with data shaped like what those slices will report.

type rollouts struct{ region string }

func (source rollouts) Rollouts(context.Context) ([]insights.Rollout, error) {
	now := time.Now().UTC()
	switch source.region {
	case "gru":
		return []insights.Rollout{
			{ID: entityid.Derive("preview-rollout", "v0.43.0", "gru"), Release: "v0.43.0", Phase: "complete", PhaseStarted: now.Add(-245 * time.Minute), Done: true},
			{ID: entityid.Derive("preview-rollout", "terrabase-3.8.2", "gru"), Release: "terrabase 3.8.2", Phase: "canary-soak", PhaseStarted: now.Add(-26 * time.Minute),
				PhaseDeadline: now.Add(4 * time.Minute)},
		}, nil
	case "sfo":
		return []insights.Rollout{{ID: entityid.Derive("preview-rollout", "v0.43.0", "sfo"), Release: "v0.43.0", Phase: "batch",
			PhaseStarted: now.Add(-30 * time.Minute), PhaseDeadline: now.Add(-5 * time.Minute)}}, nil
	case "fra":
		return []insights.Rollout{{ID: entityid.Derive("preview-rollout", "v0.43.0", "fra"), Release: "v0.43.0", Phase: "frozen",
			PhaseStarted: now.Add(-140 * time.Minute)}}, nil
	}
	return nil, nil
}

func (source rollouts) Rollout(ctx context.Context, id string) (insights.Rollout, error) {
	rows, err := source.Rollouts(ctx)
	if err != nil {
		return insights.Rollout{}, err
	}
	for _, record := range rows {
		if record.ID == id {
			return record, nil
		}
	}
	return insights.Rollout{}, dashboard.ErrRolloutNotFound
}

type holds struct{ region string }

func (source holds) Holds(now time.Time) []insights.Hold {
	if source.region != "fra" {
		return nil
	}
	return []insights.Hold{{Reason: "member catalog-3 cordoned: waiting for fra-ctl-3 to rejoin before draining",
		FirstSeen: now.Add(-50 * time.Minute), LastSeen: now}}
}

// Volumes lists GRU's block volumes; one keeps getting stuck attaching.
func (world *World) Volumes(context.Context) ([]insights.Volume, error) {
	now := time.Now().UTC()
	var volumes []insights.Volume
	for index, host := range world.regions[0].hosts {
		for slot := range 3 {
			volumes = append(volumes, insights.Volume{ID: entityid.Derive("preview-volume", host, fmt.Sprint(slot+1)), Host: host,
				State: "attached", StateSince: now.Add(-time.Duration(index*7+slot*3+20) * time.Hour)})
		}
	}
	volumes = append(volumes, insights.Volume{ID: entityid.Derive("preview-volume", "gru-vol-backup-1"), State: "available", StateSince: now.Add(-50 * time.Hour)})
	world.mu.Lock()
	stuck := world.stuck
	world.mu.Unlock()
	if !stuck.IsZero() {
		volumes = append(volumes, insights.Volume{ID: entityid.Derive("preview-volume", "gru-vol-sessions-3"), Host: "gru-host-c", State: "attaching", StateSince: stuck})
	} else {
		volumes = append(volumes, insights.Volume{ID: entityid.Derive("preview-volume", "gru-vol-sessions-3"), Host: "gru-host-c", State: "attached",
			StateSince: now.Add(-time.Minute)})
	}
	return volumes, nil
}

type certificates struct{}

func (certificates) Certificates(context.Context) ([]insights.Certificate, error) {
	now := time.Now().UTC()
	return []insights.Certificate{
		{Name: "release-signer-2026q4", Kind: "delegation", NotAfter: now.Add(5*24*time.Hour + 3*time.Hour)},
		{Name: "nats-cluster-gru", Kind: "tls", NotAfter: now.Add(61 * 24 * time.Hour)},
		{Name: "observability-listener", Kind: "tls", NotAfter: now.Add(83 * 24 * time.Hour)},
	}, nil
}

type peers struct{}

func (peers) Peers(context.Context) ([]insights.NetBirdPeer, error) {
	now := time.Now().UTC()
	out := []insights.NetBirdPeer{}
	for _, name := range []string{"gru-ctl-1", "gru-ctl-2", "gru-ctl-3", "gru-host-a", "gru-host-b", "gru-host-c", "gru-host-d"} {
		out = append(out, insights.NetBirdPeer{Name: name, Connected: true, LastSeen: now})
	}
	out = append(out, insights.NetBirdPeer{Name: "gru-host-e", Connected: true, Relayed: true, LastSeen: now})
	return out, nil
}

type autoscalers struct{}

func (autoscalers) Autoscalers(context.Context) ([]insights.Autoscaler, error) {
	return []insights.Autoscaler{{Name: "terrabase-pool-gru", Current: 12, Max: 12, AtMaxSince: time.Now().Add(-48 * time.Minute)},
		{Name: "edge-cache-gru", Current: 3, Max: 8}}, nil
}

type budgets struct{}

func (budgets) Budgets(context.Context) ([]insights.Budget, error) {
	return []insights.Budget{{Name: "oci-compute-gru", Used: 912, Ceiling: 1000, Unit: "USD/month"},
		{Name: "block-storage-gru", Used: 41, Ceiling: 80, Unit: "TiB"}}, nil
}

// Versions reports controllers, hosts and TerraBase seats in every region,
// mid-rollout: SFO is mixed, FRA still runs the previous release.
func (world *World) Versions(context.Context) ([]dashboard.UnitVersion, error) {
	now := time.Now().UTC()
	var out []dashboard.UnitVersion
	for _, region := range world.regions {
		for _, controller := range append(append([]string{}, region.controllers...), region.missing...) {
			version := region.versions[controller]
			if version == "" {
				version = "v0.42.1"
			}
			out = append(out, dashboard.UnitVersion{Region: region.name, Kind: "controller", Unit: controller, Version: version,
				Since: now.Add(-time.Duration(len(controller)) * time.Hour)})
		}
		for index, host := range region.hosts {
			version := "v0.43.0"
			if region.name == "fra" || region.name == "sfo" && index > 0 {
				version = "v0.42.1"
			}
			out = append(out, dashboard.UnitVersion{Region: region.name, Kind: "host", Unit: host, Version: version,
				Since: now.Add(-time.Duration(index+3) * time.Hour)})
		}
		for dbIndex, db := range region.databases {
			for seat := range db.seats {
				version := "terrabase 3.8.1"
				if db.rollout != nil && seat < db.rollout.Completed || region.name == "gru" && dbIndex < 2 {
					version = "terrabase 3.8.2"
				}
				out = append(out, dashboard.UnitVersion{Region: region.name, Kind: "seat",
					Unit: entityid.Derive("preview-seat", region.name, db.id, fmt.Sprint(seat+1)), Version: version, Since: now.Add(-time.Duration(dbIndex+seat+1) * 5 * time.Hour)})
			}
		}
	}
	return out, nil
}

type qualifications struct{}

func (qualifications) Qualifications(context.Context) ([]dashboard.Qualification, error) {
	now := time.Now().UTC()
	suite := func(name, status string, minutes int, detail string) dashboard.QualificationStep {
		return dashboard.QualificationStep{Name: name, Status: status, Duration: time.Duration(minutes) * time.Minute, Detail: detail}
	}
	return []dashboard.Qualification{
		{Release: "v0.43.1-rc.1", Commit: "b71f8ad1c0ffee", Time: now.Add(-25 * time.Minute), Status: "running",
			Suites: []dashboard.QualificationStep{suite("unit and race", "passed", 6, ""), suite("native cell bootstrap", "passed", 14, ""),
				suite("rolling upgrade 3 controllers", "running", 9, "batch 2 of 3")}},
		{Release: "v0.43.0", Commit: "9f2c7ab3e410aa", Time: now.Add(-7 * time.Hour), Status: "passed",
			Suites: []dashboard.QualificationStep{suite("unit and race", "passed", 6, ""), suite("native cell bootstrap", "passed", 13, ""),
				suite("rolling upgrade 3 controllers", "passed", 22, ""), suite("TerraBase failover", "passed", 18, "")}},
		{Release: "v0.42.9", Commit: "77d0be55aa0912", Time: now.Add(-21 * time.Hour), Status: "passed",
			Suites: []dashboard.QualificationStep{suite("unit and race", "passed", 6, ""),
				suite("TerraBase failover", "flaky", 25, "passed on retry; later rolled back in FRA canary")}},
	}, nil
}

type inventory struct{}

func (inventory) Inventory(context.Context) (dashboard.InventoryObservation, error) {
	items := []dashboard.InventoryItem{}
	for index, name := range []string{"gru-ctl-1", "gru-ctl-2", "gru-ctl-3", "gru-host-a", "gru-host-b", "gru-host-c", "gru-host-d", "gru-host-e"} {
		drift := "in_sync"
		if index == 6 {
			drift = "drifted"
		}
		items = append(items, dashboard.InventoryItem{Kind: "instance", ID: fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.%08x", index*7919+13),
			Name: name, Region: "gru", State: "RUNNING", Drift: drift})
	}
	items = append(items,
		dashboard.InventoryItem{Kind: "volume", ID: "ocid1.volume.oc1.sa-saopaulo-1.0000aa01", Name: "gru-vol-sessions-3", Region: "gru", State: "AVAILABLE", Drift: "in_sync"},
		dashboard.InventoryItem{Kind: "vcn", ID: "ocid1.vcn.oc1.sa-saopaulo-1.0000ab01", Name: "terrascale-gru", Region: "gru", State: "AVAILABLE", Drift: "in_sync"},
		dashboard.InventoryItem{Kind: "bucket", ID: "terrascale-gru-backups", Name: "terrascale-gru-backups", Region: "gru", State: "ACTIVE", Drift: "in_sync"},
		dashboard.InventoryItem{Kind: "instance", ID: "ocid1.instance.oc1.sa-saopaulo-1.0000dead", Name: "gru-host-old", Region: "gru", State: "STOPPED", Drift: "unmanaged"},
	)
	return dashboard.InventoryObservation{Items: items}, nil
}
