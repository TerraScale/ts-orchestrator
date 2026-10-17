package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestSignedPlacementUsesBusinessKeyInRealAuthorityLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := newAuthenticatedNATS(t, "gru").start(t, ctx, natscell.Config{
		Cell: "gru", Instance: "placement-authority", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: "0000000000RSVEVH5A778HC7A2", Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	epoch := control.Current().Epoch
	if !control.Current().CanMutate() || epoch == 0 {
		t.Fatalf("R1 lab authority did not acquire a mutable lease: %+v", control.Current())
	}

	policy, privateKey := newPlacementAdmissionPolicy(t)
	intent := testManagedPlacementIntent()
	if intent.DatabaseID != "0000000000JJVVW9EMWY1PE1VX" || intent.DatabaseID == intent.CanonicalRoster.DatabaseID {
		t.Fatalf("fixture conflates business key and canonical TerraBase database ID: %+v", intent)
	}
	sign := func(intent placement.Intent) []byte {
		t.Helper()
		payload, err := protocol.EncodeJSON(intent)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
			Region: "gru", Kind: "placement.intent", Actor: "ops",
			OperationID: intent.OperationID(), Generation: intent.Generation, Epoch: epoch,
		}, now, now.Add(time.Minute), privateKey)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := sign(intent)
	receipt, err := verifyAndApplyPlacement(ctx, wire, "gru", policy, control)
	if err != nil || receipt.Sequence == 0 || receipt.DatabaseID != intent.DatabaseID {
		t.Fatalf("signed placement did not commit through real authority: receipt=%+v err=%v", receipt, err)
	}
	entry, err := control.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || entry.SubjectKey != intent.DatabaseID+"."+intent.PartitionID || entry.Sequence != receipt.Sequence || !bytes.Equal(entry.OriginalWire, wire) {
		t.Fatalf("runtime read did not return the business-key record: entry=%+v err=%v", entry, err)
	}
	reader, err := authority.OpenReader(ctx, broker.JetStream(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reader.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || persisted.Sequence != entry.Sequence || !bytes.Equal(persisted.Payload, entry.Payload) || !bytes.Equal(persisted.OriginalWire, wire) {
		t.Fatalf("independent authority reader lost the ordered-log record: entry=%+v err=%v", persisted, err)
	}
	var original protocol.Envelope
	if err := protocol.DecodeStrict(persisted.OriginalWire, &original, maxPlacementWireBytes); err != nil {
		t.Fatal(err)
	}
	trusted, ok := policy.trusted(original.KeyID)
	if !ok {
		t.Fatal("retained ingress lost its actual admission signing key")
	}
	if err := protocol.VerifyEnvelope(original, protocol.EnvelopeScope{
		Region: "gru", Kind: "placement.intent", Actor: "ops", OperationID: intent.OperationID(),
		Generation: intent.Generation, Epoch: epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		t.Fatalf("retained original ingress no longer authenticates: %v", err)
	}
	entry.OriginalWire[0] ^= 1
	persisted.OriginalWire[0] ^= 1
	retained, err := reader.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || !bytes.Equal(retained.OriginalWire, wire) {
		t.Fatalf("caller mutation changed durable original ingress: err=%v", err)
	}
	decoded, err := placement.DecodeCommittedIntent(persisted.Payload)
	if err != nil || decoded.DatabaseID != intent.DatabaseID ||
		decoded.CanonicalRoster.DatabaseID != intent.CanonicalRoster.DatabaseID ||
		decoded.CanonicalRoster.DatabaseID == decoded.DatabaseID {
		t.Fatalf("committed payload lost distinct business and canonical identities: intent=%+v err=%v", decoded, err)
	}
	admitted, err := placement.NewAuthorityIntentReader(reader, "gru", oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	intents, err := admitted.ListPlacementIntents(ctx, "gru")
	if err != nil || len(intents) != 1 || intents[0].PayloadDigest() != decoded.PayloadDigest() {
		t.Fatalf("placement reader did not decode the real committed log: intents=%+v err=%v", intents, err)
	}
	repeated, err := verifyAndApplyPlacement(ctx, wire, "gru", policy, control)
	if err != nil || repeated.Sequence != receipt.Sequence {
		t.Fatalf("idempotent signed admission changed the log sequence: receipt=%+v err=%v", repeated, err)
	}
	reissued := sign(intent)
	if bytes.Equal(reissued, wire) {
		t.Fatal("reissued fixture did not change signed ingress")
	}
	if _, err := verifyAndApplyPlacement(ctx, reissued, "gru", policy, control); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("fresh signed envelope replaced original provenance: %v", err)
	}
	if _, err := control.CommitSignedPlacementIntent(ctx, epoch, intent.DatabaseID, intent.PartitionID,
		intent.OperationID(), receipt.Sequence, retained.Payload, reissued); !errors.Is(err, authority.ErrOperationConflict) {
		t.Fatalf("same-operation append replaced original provenance: %v", err)
	}
	if _, err := control.CommitPlacementIntent(ctx, epoch, intent.DatabaseID, intent.PartitionID,
		intent.OperationID(), receipt.Sequence, retained.Payload); !errors.Is(err, authority.ErrOperationConflict) {
		t.Fatalf("payload-only replay discarded original provenance: %v", err)
	}

	wrong := intent
	wrong.DatabaseID = strings.ToLower(intent.CanonicalRoster.DatabaseID)
	if _, err := verifyAndApplyPlacement(ctx, sign(wrong), "gru", policy, control); err == nil {
		t.Fatal("uppercase UUID was accepted as the lowercase business key")
	}
	if _, err := control.ReadPlacementIntent(ctx, wrong.DatabaseID, wrong.PartitionID); err == nil {
		t.Fatal("authority accepted the uppercase UUID as a placement subject key")
	}
	entries, err := reader.ListPlacementIntents(ctx)
	if err != nil || len(entries) != 1 || entries[0].SubjectKey != entry.SubjectKey || entries[0].Sequence != receipt.Sequence || !bytes.Equal(entries[0].OriginalWire, wire) {
		t.Fatalf("rejected business key changed the ordered log: entries=%+v err=%v", entries, err)
	}
	entries[0].OriginalWire[0] ^= 1
	retained, err = reader.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || !bytes.Equal(retained.OriginalWire, wire) {
		t.Fatalf("listed ingress aliases durable original bytes: err=%v", err)
	}
	legacy := intent
	legacy.PartitionID = "0000000000RSVEVH5A778HC7A2"
	legacyPayload, err := protocol.EncodeJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CommitPlacementIntent(ctx, epoch, legacy.DatabaseID, legacy.PartitionID,
		legacy.OperationID(), 0, legacyPayload); err != nil {
		t.Fatalf("retain historical payload-only placement: %v", err)
	}
	if _, err := verifyAndApplyPlacement(ctx, sign(legacy), "gru", policy, control); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("historical payload acquired fresh original ingress: %v", err)
	}
	historical, err := reader.ReadPlacementIntent(ctx, legacy.DatabaseID, legacy.PartitionID)
	if err != nil || len(historical.OriginalWire) != 0 || !bytes.Equal(historical.Payload, legacyPayload) {
		t.Fatalf("historical evidence was rewritten: err=%v", err)
	}
}
