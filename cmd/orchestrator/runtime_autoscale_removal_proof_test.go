package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

type autoscaleProofGateway struct {
	ocireconcile.ComputeGateway
	members []ocireconcile.ObservedMember
}

func (g *autoscaleProofGateway) ListMembers(context.Context) ([]ocireconcile.ObservedMember, error) {
	return g.members, nil
}
func (g *autoscaleProofGateway) ObserveMember(_ context.Context, id string) (ocireconcile.ObservedMember, error) {
	for _, member := range g.members {
		if member.ID == id {
			return member, nil
		}
	}
	return ocireconcile.ObservedMember{}, errors.New("unknown provider")
}

type autoscaleProofOwnership struct {
	provider.DurableOwnershipEvidence
	records map[string]provider.ProviderOwnershipRecord
}

func (*autoscaleProofOwnership) AuthoritativeDurable() bool { return true }
func (o *autoscaleProofOwnership) Lookup(_ context.Context, id provider.ProviderResourceId) (provider.ProviderOwnershipRecord, bool, error) {
	record, ok := o.records[id.Value]
	return record, ok, nil
}

// This drives the real health adapter, provider/enrollment join, proof producer
// and autoscale controller. No test callback fabricates readiness booleans.
func TestObservedRemovalProofUsesSignedScopeAndExactProviderSurvivors(t *testing.T) {
	for _, scenario := range []string{"empty excluded", "empty seated", "assigned databases", "missing head", "forged head", "foreign scope", "inventory unavailable", "inventory changed", "unreported assignment", "foreign reported database", "missing signed survivor", "provider reincarnation", "missing headroom", "lease lost"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().Add(-time.Second)
			cluster := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
			state := enrollment.State{Records: map[string]enrollment.Record{}}
			gateway := &autoscaleProofGateway{}
			ownership := &autoscaleProofOwnership{records: map[string]provider.ProviderOwnershipRecord{}}
			health := healthRegion{Code: "gru", Latitude: new(0.0), Longitude: new(0.0)}
			reports := []hostagent.NodeStatusReport{}
			identities := []string{}
			for index, id := range []string{"01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAX", "01ARZ3NDEKTSV4RRFFQ69G5FAY"} {
				node := fmt.Sprintf("gru-%d", index+1)
				record := enrollment.Record{NodeID: node, MemberID: id, Environment: "production", Cluster: cluster, Region: "gru", Slot: index + 1, Generation: uint64(index + 7), Public: &enrollment.PublicBootstrap{}}
				state.Records[node] = record
				identity := enrollment.Identity(record, "member")
				identities = append(identities, identity)
				member := ocireconcile.ObservedMember{ID: "instance-" + node, ETag: "etag", CompartmentID: "compartment", Region: "gru", Index: index + 1, LifecycleState: "RUNNING"}
				gateway.members = append(gateway.members, member)
				ownership.records[member.ID] = provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: member.ID}, CompartmentId: provider.ProviderCompartmentId{Value: member.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: record.Generation}, MemberID: id, ServerIdentity: identity}
				health.Members = append(health.Members, healthMember{ID: node, Address: fmt.Sprintf("198.51.100.%d", index+1), Architecture: new(runtimeplan.HostArchitectureArm64)})
				reports = append(reports, hostagent.NodeStatusReport{NodeId: node, State: hostagent.NodeStateServing, Facts: hostagent.HostFacts{Engine: hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: now.UnixMilli()}, Metrics: hostagent.HostMetrics{ObservationSequence: 1, BootGeneration: "boot-" + node, ObservedAtUnixMS: now.UnixMilli(), CPUPercent: 10, MemoryPercent: 10, QueueCapacity: 20, CapacityMeasured: true, CPUCount: 2, CPUBudgetMilli: 2000, AvailableMemoryBytes: 1, AvailableStorageBytes: 1}}})
			}
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			request := placementtransition.Request{OperationID: "accepted", ScopeID: "production/" + cluster, Epoch: 1, Generation: 1, Members: []placementtransition.Member{{Identity: identities[0], Region: "GRU", PlacementDigest: strings.Repeat("a", 64)}, {Identity: identities[1], Region: "GRU", PlacementDigest: strings.Repeat("a", 64)}}}
			if scenario == "empty seated" {
				request.Members[1].Identity = identities[2]
			}
			if scenario == "missing signed survivor" {
				request.Members[1].Identity += "foreign"
			}
			if scenario == "foreign scope" {
				request.ScopeID = "foreign/" + cluster
			}
			digest, err := placementtransition.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			head, err := placementtransition.SignEvidence("authority", key, placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: request, RequestDigest: digest, AuthorityEpoch: 3})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "forged head" {
				head.Signature[0] ^= 1
			}
			record := databaseadmission.Record{State: "ready", DatabaseID: "db", Request: databaseadmission.Request{Environment: "production", TenantID: "tenant", ProjectID: "project", Regions: []string{"GRU"}}, Targets: []databaseadmission.Target{{ServerIdentity: identities[0], Region: "GRU"}, {ServerIdentity: identities[1], Region: "GRU"}}}
			records := []databaseadmission.Record{}
			if scenario == "assigned databases" || scenario == "unreported assignment" {
				records = append(records, record)
			}
			if scenario == "assigned databases" {
				for index := range 2 {
					reports[index].Facts.Engine = hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: now.UnixMilli(), CatchUpComplete: true, AssignmentRevision: "assignment", CatchUpObservedAtUnixMS: uint64(now.UnixMilli()), Databases: []hostagent.DatabaseCatchUpFacts{{Tenant: "tenant", Project: "project", Database: "db", RegionalMeasured: true, CausalMeasured: true, CausalCaughtUp: true, BackupMeasured: true, BackupCaughtUp: true}}}
				}
			}
			if scenario == "foreign reported database" {
				reports[0].Facts.Engine = hostagent.EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: now.UnixMilli(), CatchUpComplete: true, AssignmentRevision: "assignment", CatchUpObservedAtUnixMS: uint64(now.UnixMilli()), Databases: []hostagent.DatabaseCatchUpFacts{{Tenant: "tenant", Project: "project", Database: "foreign", RegionalMeasured: true, CausalMeasured: true, CausalCaughtUp: true, BackupMeasured: true, BackupCaughtUp: true}}}
			}
			if scenario == "provider reincarnation" {
				owned := ownership.records[gateway.members[2].ID]
				owned.Generation.Value++
				ownership.records[gateway.members[2].ID] = owned
			}
			if scenario == "missing headroom" {
				reports[2].Facts.Metrics.CapacityMeasured = false
			}
			path := filepath.Join(t.TempDir(), "health.json")
			encoded, err := json.Marshal(healthObservationConfig{Regions: []healthRegion{health}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			source := &observedKVHealthSource{spec: estate.Spec{Regions: []estate.Region{{Code: "gru"}}}, path: path, sample: func(context.Context, healthRegion) ([]hostagent.NodeStatusReport, error) { return reports, nil }}
			reads := 0
			producer := &productionAutoscaleRemovalProofProducer{scope: "production/" + cluster, epoch: 3, lease: "lease", key: public, head: func(context.Context, string) (placementtransition.Signed, error) {
				if scenario == "missing head" {
					return placementtransition.Signed{}, errors.New("unknown")
				}
				return head, nil
			}, records: func(context.Context) ([]databaseadmission.Record, error) {
				reads++
				if scenario == "inventory unavailable" {
					return nil, errors.New("unknown")
				}
				if scenario == "inventory changed" && reads%2 == 0 {
					return []databaseadmission.Record{record}, nil
				}
				return records, nil
			}, check: func(context.Context) error {
				if scenario == "lease lost" {
					return errors.New("lost")
				}
				return nil
			}}
			adapter := &productionAutoscaleObservationSource{source: source, enrollments: func(context.Context) (enrollment.State, error) { return state, nil }, gateways: map[string]ocireconcile.ComputeGateway{"gru": gateway}, ownership: ownership, environment: "production", cluster: cluster, check: func(context.Context) error { return nil }, proof: producer}
			targets := &runtimeAutoscaleTargets{target: autoscale.Target{Region: "gru", Members: 3}, found: true}
			controller, err := autoscale.New(autoscale.Config{Source: adapter, Targets: targets, Authority: runtimeAutoscaleAuthority{}, MinMembers: 2, MaxMembers: 5, CPUThreshold: 80, MemoryThreshold: 80, HighSamples: 1, LowSamples: 1, ObservationMaxAge: 30 * time.Second, Now: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			// First sample records membership; a later complete low sample may act.
			_, _, _ = controller.Evaluate(t.Context(), "gru")
			for i := range reports {
				reports[i].Facts.Metrics.ObservationSequence++
				reports[i].Facts.Metrics.ObservedAtUnixMS++
			}
			plan, created, err := controller.Evaluate(t.Context(), "gru")
			valid := scenario == "empty excluded" || scenario == "empty seated" || scenario == "assigned databases"
			if valid {
				if err != nil || !created || plan.DesiredMembers != 2 || plan.RemovalResourceID != "instance-gru-3" || plan.RemovalIncarnation != "boot-gru-3" {
					t.Fatalf("real observed proof did not admit exact removal: %+v %v %v", plan, created, err)
				}
				observed, err := adapter.Observe(t.Context(), "gru")
				if err != nil {
					t.Fatal(err)
				}
				if !observed[2].Proof.Removal.NoAssignedData || len(observed[2].Proof.Databases) != 0 || observed[2].Proof.Removal.Member.Generation != 9 || len(observed[2].Proof.Removal.Survivors) != 2 {
					t.Fatalf("empty proof fabricated or lost identity: %+v", observed[2])
				}
			} else if created {
				t.Fatalf("unknown/contradictory proof admitted removal: %+v", plan)
			}
		})
	}
}
