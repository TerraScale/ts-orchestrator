package app

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestDirectChannelPublicationRetainsSignerOrderingAcrossRollback(t *testing.T) {
	f := newChannelFixture(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("legacy")))
	f.consume(t)
	keyID, err := trust.KeyID(f.signer.leaf.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	public, err := trust.EncodeDelegatedPublicKey(f.signer.leaf.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema,
		Namespace: "channel-order", Bucket: "gru-1-head", Region: "GRU", Role: "orchestrator",
		Environment: "production", SignerKeyID: keyID, SignerPublicKey: public, SequenceFloor: 1000}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 1000,
			IssuedAt: f.signer.now, EvidenceSHA256: strings.Repeat("b", 64)})
	}
	signed, err := release.SignSequenceMigration(migration, f.signer.now, f.signer.root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(sequence uint64, run int64, binary string) releasechannel.Status {
		t.Helper()
		f.setChannel(t, f.signer.channelSequenced(t, "GRU", run, []byte(binary), sequence, wire))
		return f.consume(t)
	}
	if status := publish(1001, 1, "first sequence"); status.State == releasechannel.StateFailed || status.ReleaseSequence != 1001 {
		t.Fatalf("smaller CI run did not advance signer sequence: %+v", status)
	}
	if _, err := f.store.RollbackRelease(t.Context(), 7, 1, "operator", f.signer.now); err != nil {
		t.Fatal(err)
	}
	// Reopening uses only durable JetStream state, with no remembered channel floor.
	f.store, err = rollout.OpenStore(t.Context(), f.js, "gru", 1, rolloutTestFence{epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	for _, incoming := range []releasechannel.Channel{
		f.signer.channelSequenced(t, "GRU", 1, []byte("first sequence"), 1001, wire),
		f.signer.channelSequenced(t, "GRU", 2, []byte("equivocation"), 1001, wire),
		f.signer.channel(t, "GRU", 2000, []byte("legacy bypass")),
	} {
		f.setChannel(t, incoming)
		if status := f.consume(t); status.State != releasechannel.StateFailed {
			t.Fatalf("direct channel write escaped retained ordering: %+v", status)
		}
		if desired, _, err := f.store.Desired(t.Context()); err != nil || desired.Generation() != 3 || desired.OrderingFloor.ReleaseSequence != 1001 {
			t.Fatalf("refused channel changed durable desired state: %+v error=%v", desired, err)
		}
	}
	if status := publish(1002, 2, "newer sequence"); status.State == releasechannel.StateFailed {
		t.Fatalf("newer signed sequence did not advance after rollback: %+v", status)
	}
}
