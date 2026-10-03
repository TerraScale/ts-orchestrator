package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// A replacement host carries the next host attempt of the same logical
// member. Once the verifier binds it to the seat's current durable attempt,
// the previous attempt's registration no longer blocks it; another host of
// the same or a newer attempt still does (#127 12096).
func TestReplacementHostRegistersOverASupersededAttempt(t *testing.T) {
	controller, _, _, _, _ := testControllerWithVerifier(t, managedRegistrationVerifierFunc(func(context.Context, Registration) error {
		return nil
	}))
	scope := MemberScope{ClusterID: strings.Repeat("a", 32), TenantID: "018f0000-0000-7000-8000-000000000001",
		DatabaseID: "018f0000-0000-7000-8000-000000000001", ShardID: 1,
		MemberID: "018f0000-0000-7000-8000-000000000001", Incarnation: strings.Repeat("b", 32)}
	registration := func(node string, attempt uint64) Registration {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return Registration{
			Cell: "gru", Node: node, Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
			Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: testNATSUserKey(node), Generation: 1,
			ManagedPlacement: &ManagedPlacementBinding{
				DatabaseID: "db-main", PartitionID: "partition-a", SeatID: "permanent-a", IntentGeneration: 7,
				IntentPayloadDigest: strings.Repeat("c", 64), CanonicalRosterDigest: strings.Repeat("d", 64),
				ManagedHostProfileDigest: strings.Repeat("e", 64),
			},
			ManagedOCI:         &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1.." + node, Owner: "terrascale", FleetGeneration: 4, CreateKey: node},
			ManagedMember:      &ManagedMemberBinding{Scope: scope, HostAttempt: attempt},
			SystemReserveBytes: 1 << 30, Capacity: Capacity{MemoryBytes: 5 << 30},
		}
	}
	if _, err := controller.Register(t.Context(), registration("managed-a1", 1)); err != nil {
		t.Fatalf("initial attempt: %v", err)
	}
	if _, err := controller.Register(t.Context(), registration("managed-twin", 1)); err == nil {
		t.Fatal("a second host of the same attempt registered the member")
	}
	if _, err := controller.Register(t.Context(), registration("managed-a2", 2)); err != nil {
		t.Fatalf("replacement attempt was blocked by the superseded registration: %v", err)
	}
	if _, err := controller.Register(t.Context(), registration("managed-stale", 1)); err == nil {
		t.Fatal("a host of a superseded attempt registered over the replacement")
	}
}
