package app

import (
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestWANHistorySamplesPreserveDirectionTimeAndUnknowns(t *testing.T) {
	now := time.Now().UTC()
	origin := hostload.Origin{Cell: "gru", Environment: "production", Node: "Host-A"}
	for _, test := range []struct {
		name     string
		at       time.Time
		members  float64
		observed bool
	}{
		{"fresh", now.Add(-time.Minute), 3, true},
		{"unanswered", now.Add(-time.Minute), 0, true},
		{"stale original scrape", now.Add(-terrabase.WANFreshFor - time.Second), 3, false},
		{"future original scrape", now.Add(time.Minute), 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := now
			load := hostload.NewAggregator(hostload.AggregatorConfig{Now: func() time.Time { return clock }})
			wan := &terrabase.WANObservation{ObservedAt: test.at, ReceiverRegion: "gru-native-region", Sources: []terrabase.WANSource{{
				SourceRegion: "sfo-1", LagGroups: new(7.0), StalenessSeconds: new(12.5),
				Members: new(test.members), Unregistered: new(2.0), Conflicts: new(1.0), AheadFailuresTotal: new(4.0),
			}}}
			report := hostload.Report{SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: terrabase.Role, WAN: wan,
				TerraBase: &memberstatus.Load{ReplicationLagSeq: 999}}}}
			if err := load.Record(origin, report); err != nil {
				t.Fatal(err)
			}
			want := map[string]float64{
				observability.HistTerraBaseWANObservedAt: float64(test.at.UnixMilli()),
				observability.HistTerraBaseWANLagGroups:  7, observability.HistTerraBaseWANStaleness: 12.5,
				observability.HistTerraBaseWANMembers: test.members, observability.HistTerraBaseWANUnregistered: 2,
				observability.HistTerraBaseWANConflicts: 1, observability.HistTerraBaseWANAheadFailures: 4,
			}
			samples := hostLoadSamples(load)
			found := make(map[string]float64)
			for _, sample := range samples {
				if _, isWAN := want[sample.Metric]; !isWAN {
					if sample.Metric == observability.HistTerraBaseLagSeq && sample.Value != 999 {
						t.Fatal("local sequence lag was relabelled as WAN")
					}
					continue
				}
				if !observability.IsHostMetric(sample.Metric) || sample.Counter {
					t.Fatalf("WAN evidence is not a shared cumulative gauge: %+v", sample)
				}
				labels := make(map[string]string)
				for _, label := range sample.Labels {
					labels[label.Name] = label.Value
				}
				if len(labels) != 5 || labels["member"] != "host-a" || labels["node"] != "Host-A" ||
					labels["role"] != terrabase.Role || labels["receiver_region"] != "gru-native-region" || labels["source_region"] != "sfo-1" {
					t.Fatalf("WAN attribution = %v", labels)
				}
				found[sample.Metric] = sample.Value
			}
			if !test.observed {
				if len(found) != 0 {
					t.Fatalf("fresh receipt refreshed stale source: %v", found)
				}
				return
			}
			if len(found) != len(want) {
				t.Fatalf("incomplete WAN history: %v", found)
			}
			for metric, value := range want {
				if found[metric] != value {
					t.Errorf("%s = %v, want %v", metric, found[metric], value)
				}
			}
			// A newer report without WAN must not copy older WAN into its batch.
			clock = clock.Add(hostload.DefaultMinInterval)
			if err := load.Record(origin, hostload.Report{SchemaVersion: 1}); err != nil {
				t.Fatal(err)
			}
			for _, sample := range hostLoadSamples(load) {
				if _, isWAN := want[sample.Metric]; isWAN {
					t.Fatalf("new batch borrowed absent WAN: %+v", sample)
				}
			}
		})
	}
}
