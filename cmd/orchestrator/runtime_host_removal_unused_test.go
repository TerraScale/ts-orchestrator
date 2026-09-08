package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

func unusedProofFixture(t *testing.T) (placementtransition.Signed, ed25519.PublicKey, hostremoval.RemovalRequest) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := placementtransition.Request{OperationID: "accepted", ScopeID: "production/cluster", Epoch: 1, Generation: 1, Members: []placementtransition.Member{{Identity: "member-one", Region: "GRU", PlacementDigest: strings.Repeat("a", 64)}, {Identity: "member-two", Region: "GRU", PlacementDigest: strings.Repeat("a", 64)}}}
	digest, err := placementtransition.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	proof := placementtransition.Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: request, RequestDigest: digest}
	payload, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	signed := placementtransition.Signed{KeyID: "gru", Payload: payload, Signature: ed25519.Sign(private, append([]byte("terrabase-placement-transition-v1\x00"), payload...))}
	removal := hostremoval.RemovalRequest{OperationID: "remove-unused", Member: hostremoval.MemberObservation{Identity: "member-three", ResourceID: "instance-three", Region: "gru", Slot: 3, Generation: 4}, Generation: 4, Survivors: []hostremoval.MemberObservation{{Identity: "member-one", ResourceID: "instance-one", Region: "gru", Slot: 1, Generation: 1}, {Identity: "member-two", ResourceID: "instance-two", Region: "gru", Slot: 2, Generation: 2}}}
	return signed, public, removal
}
func TestUnusedRemovalRequiresSignedHeadAndSurvivingRF2(t *testing.T) {
	signed, key, request := unusedProofFixture(t)
	if _, err := unusedRemovalProof(signed, key, "production/cluster", request); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"signature", "scope", "generation", "missing_seat", "duplicate", "one_survivor"} {
		t.Run(kind, func(t *testing.T) {
			signed, key, request := unusedProofFixture(t)
			scope := "production/cluster"
			switch kind {
			case "signature":
				signed.Signature[0] ^= 1
			case "scope":
				scope = "foreign/cluster"
			case "generation":
				request.Member.Generation++
			case "missing_seat":
				request.Survivors[0].Identity = "unaccepted-other"
			case "duplicate":
				request.Survivors[1] = request.Survivors[0]
			case "one_survivor":
				request.Survivors = request.Survivors[:1]
			}
			if _, err := unusedRemovalProof(signed, key, scope, request); err == nil {
				t.Fatal("unsafe unused host proof accepted")
			}
		})
	}
}

func TestUnusedRemovalDurableFenceSurvivesUnknownTermination(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	store := openRotationTestLeaseStore(t, t.Context(), connection, true)
	lease := rotationTestLease(1, "global-controller-gru-unused")
	putRotationTestLease(t, t.Context(), store, lease)
	config := authorityjournal.Config{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1, LeaseID: lease.LeaseId, StateKey: "host-removal"}
	admissionConfig := databaseadmission.NATSJournalConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1, LeaseID: lease.LeaseId}
	admission, err := databaseadmission.NewNATSJournal(admissionConfig)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := hostremoval.New(config)
	if err != nil {
		t.Fatal(err)
	}
	signed, key, request := unusedProofFixture(t)
	request.Member.ProviderETag = "etag-three"
	u := &productionUnusedHostRemoval{Scope: "production/cluster", Admission: admission, Removal: journal, ProofKey: key, Check: func(context.Context) error { return nil }, Head: func(context.Context, string) (placementtransition.Signed, error) { return signed, nil }}
	unknown := errors.New("termination submitted but response lost")
	present := true
	calls := 0
	owner := &hostremoval.Owner{Journal: journal,
		Inventory: func(ctx context.Context, r hostremoval.RemovalRequest, _ []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
			revision, handled, err := u.capture(ctx, r)
			if !handled {
				t.Fatal("unused inventory not handled")
			}
			return revision, nil, err
		},
		Replace: func(context.Context, hostremoval.Replacement) error {
			t.Fatal("empty scope fabricated a database replacement")
			return nil
		},
		Revalidate: func(ctx context.Context, operation, member string, revision uint64) error {
			handled, err := u.revalidate(ctx, operation, member, revision)
			if !handled {
				t.Fatal("unused proof missing")
			}
			return err
		},
		Fence: func(ctx context.Context, operation, member string, replacements []hostremoval.Replacement) error {
			if len(replacements) != 0 {
				t.Fatal("unexpected replacement")
			}
			retained, err := journal.Load(ctx, operation)
			if err != nil {
				return err
			}
			_, err = u.revalidate(ctx, operation, member, retained.InventoryRevision)
			return err
		},
		Observe:              func(context.Context, string) (bool, error) { return present, nil },
		Terminate:            func(context.Context, string) error { calls++; present = false; return unknown },
		ReconcileTermination: func(context.Context, string) error { return nil },
	}
	if err := owner.RemoveMember(t.Context(), request.OperationID, request.Member, request.Generation, request.Survivors...); !errors.Is(err, unknown) {
		t.Fatal("lost termination outcome not retained", err)
	}
	// Recreate the durable admission client before resuming the fenced removal.
	admission, err = databaseadmission.NewNATSJournal(admissionConfig)
	if err != nil {
		t.Fatal(err)
	}
	u.Admission = admission
	if err := admission.BeginPlacementRelocation(t.Context(), "unrelated", nil); !errors.Is(err, databaseadmission.ErrConflict) {
		t.Fatal("unknown termination released admission fence", err)
	}
	if err := owner.RemoveMember(t.Context(), request.OperationID, request.Member, request.Generation, request.Survivors...); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("terminal retry resubmitted DELETE")
	}
	retained, err := journal.Load(t.Context(), request.OperationID)
	if err != nil || retained.Stage != hostremoval.StageComplete {
		t.Fatal("terminal removal missing", err)
	}
	if err := admission.FinishPlacementRelocation(t.Context(), request.OperationID+"/placement"); err != nil {
		t.Fatal(err)
	}
	if err := admission.BeginPlacementRelocation(t.Context(), "next-operation", nil); err != nil {
		t.Fatal("terminal removal kept admission frozen", err)
	}
}
