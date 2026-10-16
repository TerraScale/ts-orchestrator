package app

import (
	"bytes"
	"context"
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
	if err != nil || entry.SubjectKey != intent.DatabaseID+"."+intent.PartitionID || entry.Sequence != receipt.Sequence {
		t.Fatalf("runtime read did not return the business-key record: entry=%+v err=%v", entry, err)
	}
	reader, err := authority.OpenReader(ctx, broker.JetStream(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reader.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || persisted.Sequence != entry.Sequence || !bytes.Equal(persisted.Payload, entry.Payload) {
		t.Fatalf("independent authority reader lost the ordered-log record: entry=%+v err=%v", persisted, err)
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

	wrong := intent
	wrong.DatabaseID = strings.ToLower(intent.CanonicalRoster.DatabaseID)
	if _, err := verifyAndApplyPlacement(ctx, sign(wrong), "gru", policy, control); err == nil {
		t.Fatal("uppercase UUID was accepted as the lowercase business key")
	}
	if _, err := control.ReadPlacementIntent(ctx, wrong.DatabaseID, wrong.PartitionID); err == nil {
		t.Fatal("authority accepted the uppercase UUID as a placement subject key")
	}
	entries, err := reader.ListPlacementIntents(ctx)
	if err != nil || len(entries) != 1 || entries[0].SubjectKey != entry.SubjectKey || entries[0].Sequence != receipt.Sequence {
		t.Fatalf("rejected business key changed the ordered log: entries=%+v err=%v", entries, err)
	}
}
