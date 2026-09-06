package main

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func deliveryObservationMembership(t *testing.T) (*productionDeliveryMembership, func(healthObservationConfig)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "health.json")
	write := func(config healthObservationConfig) {
		t.Helper()
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(healthObservationConfig{Regions: []healthRegion{{Code: "gru", Latitude: new(0.0), Longitude: new(0.0), Members: []healthMember{{ID: "gru-2", Address: "198.51.100.2", Architecture: new(runtimeplan.HostArchitectureArm64)}, {ID: "gru-1", Address: "198.51.100.1", Architecture: new(runtimeplan.HostArchitectureArm64)}}}}})
	return &productionDeliveryMembership{source: &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path}}, write
}

func TestProductionDeliveryMembershipRereadsEntireAdmission(t *testing.T) {
	membership, write := deliveryObservationMembership(t)
	hosts, err := membership.Hosts(t.Context(), "gru")
	if err != nil || !slices.Equal(hosts, []string{"gru-1", "gru-2"}) {
		t.Fatalf("hosts %v: %v", hosts, err)
	}
	if _, err := membership.Hosts(t.Context(), "GRU"); err == nil {
		t.Fatal("inexact region accepted")
	}
	if _, err := membership.ResolveHost(t.Context(), "gru-1"); err != nil {
		t.Fatal(err)
	}
	write(healthObservationConfig{})
	if _, err := membership.ResolveHost(t.Context(), "gru-1"); err == nil {
		t.Fatal("retired admission cached")
	}
	if _, err := membership.Hosts(t.Context(), "gru"); err == nil {
		t.Fatal("invalid full configuration accepted")
	}
}

type observationCatalog struct{ release hostcontrol.Release }

func (c observationCatalog) ResolveTarget(context.Context, hostcontrol.Host, string) (hostcontrol.Release, error) {
	return c.release, nil
}

func TestProductionDeliveryGatesRequireExactFreshMeasuredFacts(t *testing.T) {
	membership, _ := deliveryObservationMembership(t)
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "terrabase", Version: "v1", ArtifactURL: "https://releases.example/terrabase", SignatureURL: "https://releases.example/terrabase.sig", User: "terrabase", DataVolume: "/var/lib/terrabase", CPUWeight: 100, MemoryMaxBytes: 1 << 30, IOWeight: 100, Sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	sha, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		t.Fatal(err)
	}
	valid := hostagent.NodeStatusReport{NodeId: "gru-1", State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{State: hostagent.NodeStateServing, ClockMeasured: true, Disk: hostagent.DiskFacts{TotalBytes: 100, AvailableBytes: 50}, ManifestSha256: sha, Components: []hostagent.ComponentFact{{Name: "terrabase", Version: "v1", Desired: "v1", Installed: true, UnitActive: true}}, Engine: hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: time.Now().UnixMilli(), LagMeasured: true}}}
	cases := []struct {
		name            string
		mutate          func(*hostagent.NodeStatusReport)
		health, catchup bool
	}{
		{name: "valid", health: true, catchup: false},
		{name: "cordoned after converge", health: true, catchup: false, mutate: func(r *hostagent.NodeStatusReport) { r.State = hostagent.NodeStateDraining; r.Facts.State = r.State }},
		{name: "unknown lag", health: true, mutate: func(r *hostagent.NodeStatusReport) { r.Facts.Engine.LagMeasured = false }},
		{name: "lagging", health: true, mutate: func(r *hostagent.NodeStatusReport) { r.Facts.Engine.LagMS = 1 }},
		{name: "stale", mutate: func(r *hostagent.NodeStatusReport) {
			r.Facts.Engine.ObservedAtUnixMS = time.Now().Add(-time.Minute).UnixMilli()
		}},
		{name: "unknown engine", mutate: func(r *hostagent.NodeStatusReport) { r.Facts.Engine.Measured = false }},
		{name: "wrong manifest", catchup: false, mutate: func(r *hostagent.NodeStatusReport) { r.Facts.ManifestSha256 = "wrong" }},
		{name: "unverified installed", catchup: false, mutate: func(r *hostagent.NodeStatusReport) { r.Facts.Components[0].Installed = false }},
		{name: "wrong version", catchup: false, mutate: func(r *hostagent.NodeStatusReport) { r.Facts.Components[0].Version = "v2" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report := valid
			report.Facts.Components = slices.Clone(valid.Facts.Components)
			if test.mutate != nil {
				test.mutate(&report)
			}
			observations := productionDeliveryObservations{membership: membership, catalog: observationCatalog{hostcontrol.Release{Manifest: manifest}}, status: func(context.Context, string) (hostagent.NodeStatusReport, error) { return report, nil }}
			if err := observations.Healthy(t.Context(), "gru-1", "digest"); (err == nil) != test.health {
				t.Fatalf("health: %v", err)
			}
			if err := observations.CaughtUp(t.Context(), "gru-1"); (err == nil) != test.catchup {
				t.Fatalf("catchup: %v", err)
			}
		})
	}
}
