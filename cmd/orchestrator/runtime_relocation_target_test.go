package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func relocationEnrolledFixture(t *testing.T) (enrollment.Record, ed25519.PublicKey) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"receipt": base64.StdEncoding.EncodeToString(public)}
	for _, role := range []string{"placement", "database"} {
		pair, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		keys[role], err = pair.PublicKey()
		pair.Wipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	return enrollment.Record{NodeID: "gru-3", MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAB", Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FAK", Region: "gru", Slot: 3, Generation: 7, Public: &enrollment.PublicBootstrap{PublicKeys: keys}}, public
}

func TestRelocationTargetAdmitsNewSurvivorOnlyFromExactDurableIdentity(t *testing.T) {
	for _, scenario := range []string{"new survivor", "retired member", "wrong generation", "wrong provider incarnation", "duplicate slot", "missing principal", "invalid receipt key", "lost authority"} {
		t.Run(scenario, func(t *testing.T) {
			record, public := relocationEnrolledFixture(t)
			identity := enrollment.Identity(record, "member")
			state := enrollment.State{Records: map[string]enrollment.Record{"gru:3": record}}
			listed := ocireconcile.ObservedMember{ID: "oci-original", ETag: "etag", CompartmentID: "compartment", Region: "gru", Index: 3, LifecycleState: "RUNNING"}
			gateway := &autoscaleIdentityGateway{listed: []ocireconcile.ObservedMember{listed}, current: listed}
			gateway.current.Region, gateway.current.Index = "", 0
			ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: listed.ID}, CompartmentId: provider.ProviderCompartmentId{Value: listed.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: 7}, MemberID: record.MemberID, ServerIdentity: identity}}
			checks := 0
			factory := &productionRelocationTargets{enrolled: func(context.Context) (enrollment.State, error) { return state, nil }, gateways: map[string]ocireconcile.ComputeGateway{"gru": gateway}, ownership: ownership, environment: record.Environment, cluster: record.Cluster, check: func(context.Context) error {
				checks++
				if scenario == "lost authority" && checks > 2 {
					return errors.New("lease lost")
				}
				return nil
			}}
			switch scenario {
			case "retired member":
				record.Retirement = &enrollment.Retirement{OperationID: "remove", ResourceID: listed.ID}
				state.Records["gru:3"] = record
			case "wrong generation":
				ownership.record.Generation.Value++
			case "wrong provider incarnation":
				gateway.current.ID = "oci-replacement"
			case "duplicate slot":
				gateway.listed = append(gateway.listed, listed)
			case "missing principal":
				delete(record.Public.PublicKeys, "database")
			case "invalid receipt key":
				record.Public.PublicKeys["receipt"] = "unknown"
			}
			target, err := factory.admit(t.Context(), identity)
			if scenario != "new survivor" {
				if err == nil || target != nil {
					t.Fatalf("unsafe target admitted: %+v %v", target, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target.Observed.ResourceID != listed.ID || target.Observed.Slot != 3 || target.Member.MemberID != record.MemberID || target.ReadinessKey.KeyID != identity || !target.ReadinessKey.PublicKey.Equal(public) {
				t.Fatalf("admitted target mismatch: %+v", target)
			}
		})
	}
}

func TestRelocationHistoricalReceiptKeySurvivesProviderRemoval(t *testing.T) {
	record, public := relocationEnrolledFixture(t)
	identity := enrollment.Identity(record, "member")
	record.Retirement = &enrollment.Retirement{OperationID: "remove-original", ResourceID: "oci-original"}
	state := enrollment.State{Retired: map[string]enrollment.Record{"remove-original": record}}
	factory := &productionRelocationTargets{enrolled: func(context.Context) (enrollment.State, error) { return state, nil }, environment: record.Environment, cluster: record.Cluster, check: func(context.Context) error { return nil }}
	key, err := factory.MemberKey(t.Context(), identity)
	if err != nil || !key.Equal(public) {
		t.Fatalf("durable key lost after provider removal: %v", err)
	}
	if _, err := factory.MemberKey(t.Context(), identity+"foreign"); err == nil {
		t.Fatal("receipt-supplied foreign identity trusted")
	}
	state.Records = map[string]enrollment.Record{"gru:3": record}
	if _, err := factory.MemberKey(t.Context(), identity); err == nil {
		t.Fatal("ambiguous enrollment key trusted")
	}
}
