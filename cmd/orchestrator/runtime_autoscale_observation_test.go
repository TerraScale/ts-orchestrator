package main

import (
	"context"
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type autoscaleIdentityGateway struct {
	ocireconcile.ComputeGateway
	listed  []ocireconcile.ObservedMember
	current ocireconcile.ObservedMember
}

func (g *autoscaleIdentityGateway) ListMembers(context.Context) ([]ocireconcile.ObservedMember, error) {
	return g.listed, nil
}
func (g *autoscaleIdentityGateway) ObserveMember(context.Context, string) (ocireconcile.ObservedMember, error) {
	return g.current, nil
}

func TestAutoscaleObservationBindsOnlyCurrentEnrolledOCIIdentity(t *testing.T) {
	for _, scenario := range []string{"valid", "foreign node", "foreign enrollment", "stale generation", "foreign identity", "foreign compartment", "replacement resource", "duplicate slot", "duplicate report", "unpublished enrollment", "lost authority"} {
		t.Run(scenario, func(t *testing.T) {
			record := enrollment.Record{NodeID: "gru-3", MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAB", Environment: "production", Cluster: "cluster", Region: "gru", Slot: 3, Generation: 7, Public: &enrollment.PublicBootstrap{}}
			state := enrollment.State{Records: map[string]enrollment.Record{"gru:3": record}}
			member := ocireconcile.ObservedMember{ID: "ocid1.instance.original", ETag: "etag", Region: "gru", Index: 3, LifecycleState: "RUNNING", CompartmentID: "compartment"}
			gateway := &autoscaleIdentityGateway{listed: []ocireconcile.ObservedMember{member}, current: member}
			gateway.current.Region, gateway.current.Index = "", 0 // Exact OCI reads omit mutable slot tags.
			ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: member.ID}, CellId: provider.ProviderCellId{Value: "gru"}, CompartmentId: provider.ProviderCompartmentId{Value: "compartment"}, Generation: provider.ProviderGeneration{Value: 7}, MemberID: record.MemberID, ServerIdentity: enrollment.Identity(record, "member")}}
			source := &runtimeAutoscaleSource{observations: []autoscale.Observation{{HostID: record.NodeID, EngineID: "untrusted", Authenticated: true}}}
			checks := 0
			adapter := &productionAutoscaleObservationSource{source: source, enrollments: func(context.Context) (enrollment.State, error) { return state, nil }, gateways: map[string]ocireconcile.ComputeGateway{"gru": gateway}, ownership: ownership, environment: "production", cluster: "cluster", check: func(context.Context) error {
				checks++
				if scenario == "lost authority" && checks == 2 {
					return errors.New("lease lost")
				}
				return nil
			}}
			switch scenario {
			case "foreign node":
				source.observations[0].HostID = "gru-other"
			case "foreign enrollment":
				record.Environment = "foreign"
				state.Records["gru:3"] = record
			case "stale generation":
				ownership.record.Generation.Value++
			case "foreign identity":
				ownership.record.ServerIdentity += "foreign"
			case "foreign compartment":
				gateway.current.CompartmentID = "foreign"
			case "replacement resource":
				gateway.current.ID = "ocid1.instance.replacement"
			case "duplicate slot":
				duplicate := member
				duplicate.ID = "ocid1.instance.duplicate"
				gateway.listed = append(gateway.listed, duplicate)
			case "duplicate report":
				source.observations = append(source.observations, source.observations[0])
			case "unpublished enrollment":
				record.Public = nil
				state.Records["gru:3"] = record
			}
			got, err := adapter.Observe(t.Context(), "gru")
			if scenario != "valid" {
				if err == nil || got != nil {
					t.Fatalf("unsafe observation accepted: %+v, %v", got, err)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0].EngineID != ownership.record.ServerIdentity || got[0].MemberSlot != 3 || got[0].ProviderResourceID != member.ID || checks != 2 {
				t.Fatalf("identity join: %+v, %v (checks=%d)", got, err, checks)
			}
			if source.observations[0].EngineID != "untrusted" {
				t.Fatal("adapter mutated shared telemetry")
			}
		})
	}
}
