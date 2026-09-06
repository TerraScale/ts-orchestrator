package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func TestObservedHealthRequiresFreshEngineReports(t *testing.T) {
	region := healthRegion{Code: "gru", Latitude: new(-23.43), Longitude: new(-46.47), Members: []healthMember{{ID: "gru-1", Address: "198.51.100.1", Architecture: new(runtimeplan.HostArchitectureArm64)}}}
	path := filepath.Join(t.TempDir(), "health.json")
	raw, _ := json.Marshal(healthObservationConfig{Regions: []healthRegion{region}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path}
	healthy := func() hostagent.NodeStatusReport {
		return hostagent.NodeStatusReport{NodeId: "gru-1", State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{ClockMeasured: true, Disk: hostagent.DiskFacts{TotalBytes: 100, AvailableBytes: 10}, Engine: hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: time.Now().UnixMilli()}}}
	}
	tests := []struct {
		name       string
		alter      func(*hostagent.NodeStatusReport)
		failed     bool
		want       bool
		draining   bool
		overloaded bool
	}{
		{name: "serving", want: true},
		{name: "transport failure", failed: true},
		{name: "missing engine", alter: func(r *hostagent.NodeStatusReport) { r.Facts.Engine.Measured = false }},
		{name: "stale", alter: func(r *hostagent.NodeStatusReport) {
			r.Facts.Engine.ObservedAtUnixMS = time.Now().Add(-time.Minute).UnixMilli()
		}},
		{name: "future", alter: func(r *hostagent.NodeStatusReport) {
			r.Facts.Engine.ObservedAtUnixMS = time.Now().Add(time.Minute).UnixMilli()
		}},
		{name: "wrong host", alter: func(r *hostagent.NodeStatusReport) { r.NodeId = "gru-foreign" }},
		{name: "engine stopped", alter: func(r *hostagent.NodeStatusReport) { r.Facts.Engine.Serving = false }},
		{name: "draining", draining: true, alter: func(r *hostagent.NodeStatusReport) { r.State = hostagent.NodeStateDraining }},
		{name: "disk exhausted", overloaded: true, alter: func(r *hostagent.NodeStatusReport) { r.Facts.Disk.AvailableBytes = 0 }},
		{name: "unknown clock", alter: func(r *hostagent.NodeStatusReport) { r.Facts.ClockMeasured = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := healthy()
			if test.alter != nil {
				test.alter(&report)
			}
			source.sample = func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error) {
				if test.failed {
					return nil, errors.New("unavailable")
				}
				return []hostagent.NodeStatusReport{report}, nil
			}
			got, err := source.ObserveRegionHealth(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			entry := got["gru"]
			if entry.Healthy != test.want || entry.Draining != test.draining || entry.Overloaded != test.overloaded || entry.Lat != *region.Latitude || entry.Lon != *region.Longitude || entry.LagMeasured {
				t.Fatalf("unexpected observed health: %+v", entry)
			}
			if test.want && (len(entry.Members) != 1 || entry.Members[0] != region.Members[0].Address || entry.UpdatedAt.IsZero()) {
				t.Fatalf("missing observed member: %+v", entry)
			}
			if !test.want && len(entry.Members) != 0 {
				t.Fatalf("unhealthy members advertised: %+v", entry)
			}
		})
	}
}

func TestObservedHealthAdmissionIsReread(t *testing.T) {
	source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: filepath.Join(t.TempDir(), "missing")}
	if _, err := source.ObserveRegionHealth(t.Context()); err == nil {
		t.Fatal("missing admission accepted")
	}
}

func TestObservedHealthRejectsAmbiguousAdmissionConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"regions":[],"regions":[]}`,
		`{"regions":[{"code":"gru","members":[{"id":"gru-1","address":"198.51.100.1","architecture":0}]}]}`,
		`{"regions":[{"code":"gru","latitude":0,"longitude":0,"members":[{"id":"gru-1","address":"198.51.100.1"}]}]}`,
		`{"regions":[{"code":"gru","latitude":0,"longitude":0,"members":[{"id":"sfo-1","address":"198.51.100.1","architecture":0}]}]}`,
		`{"regions":[],"unknown":true}`,
	} {
		t.Run(raw, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "health.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path}
			if _, err := source.configuration(); err == nil {
				t.Fatal("invalid admission configuration accepted")
			}
		})
	}
}

func TestObservedHealthRequiresStartupConfiguration(t *testing.T) {
	if _, err := newObservedKVHealthSource(estate.Default(), nil, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("missing configuration accepted")
	}
}

func TestObservedHealthDoesNotRoutePartiallyObservedPool(t *testing.T) {
	region := healthRegion{Code: "gru", Latitude: new(0.0), Longitude: new(0.0), Members: []healthMember{
		{ID: "gru-1", Address: "198.51.100.1", Architecture: new(runtimeplan.HostArchitectureArm64)},
		{ID: "gru-2", Address: "198.51.100.2", Architecture: new(runtimeplan.HostArchitectureArm64)},
	}}
	path := filepath.Join(t.TempDir(), "health.json")
	raw, _ := json.Marshal(healthObservationConfig{Regions: []healthRegion{region}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reports := []hostagent.NodeStatusReport{{NodeId: "gru-1", State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{ClockMeasured: true, Engine: hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: time.Now().UnixMilli(), LagMeasured: true, LagMS: 42}}}}
	source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path, sample: func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error) { return reports, nil }}
	observed, err := source.ObserveRegionHealth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observed["gru"].Healthy || observed["gru"].LagMeasured {
		t.Fatalf("partially observed pool routed: %+v", observed)
	}
	second := reports[0]
	second.NodeId = "gru-2"
	second.Facts.Engine.LagMeasured = false
	second.Facts.Engine.LagMS = 0
	reports = append(reports, second)
	observed, err = source.ObserveRegionHealth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !observed["gru"].Healthy || observed["gru"].LagMeasured {
		t.Fatalf("unknown lag advertised as measured: %+v", observed)
	}
}
