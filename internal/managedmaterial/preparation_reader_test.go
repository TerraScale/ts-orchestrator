package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestPreparationReaderAuthenticatesCurrentReceiptWithPublicKeyOnly(t *testing.T) {
	service, spec, objects, receipts := preparationFixture(t)
	want, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	key := service.ControllerKey.Public().(ed25519.PublicKey)
	reader, err := NewPreparationReader(service.Repository.config, objects, receipts, key, service.AllowedSubnetCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.service.ControllerKey) != 0 || reader.service.Fencer != nil || reader.service.Repository.fencer != nil {
		t.Fatal("public reader retained signing or mutation authority")
	}
	got, err := reader.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil || got.Signature != want.Signature || got.Object != want.Object {
		t.Fatalf("public reader lost exact committed generation: %+v, %v", got, err)
	}
	wire, err := protocol.EncodeJSON(got)
	if err != nil || bytes.Contains(wire, []byte(`"ciphertext"`)) || bytes.Contains(wire, []byte(`"Contents"`)) ||
		bytes.Contains(wire, []byte(`"Retained"`)) || bytes.Contains(wire, []byte(`"AuthoritySigner"`)) {
		t.Fatal("public current response exposed confidential bundle fields", err)
	}
	client := &floorReadObjectClient{ObjectClient: objects}
	reader.service.Repository.client = client
	originalEntry := *receipts.entry
	client.duringRead = func() { receipts.entry.Sequence++ }
	if _, err := reader.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID); err == nil {
		t.Fatal("same material bytes under a later R3 sequence retained current read authority")
	}
	*receipts.entry = originalEntry
	readCtx, stop := context.WithCancel(t.Context())
	client.duringRead = stop
	if _, err := reader.Current(readCtx, spec.PlacementDatabaseID, spec.PartitionID); err == nil {
		t.Fatal("cancelled original read returned public material")
	}
	stop()
	if _, err := reader.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID); err != nil {
		t.Fatal("current public reader failed after the cancelled attempt", err)
	}
	foreign, err := NewPreparationReader(service.Repository.config, objects, receipts, bytes.Repeat([]byte{1}, ed25519.PublicKeySize), service.AllowedSubnetCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID); err == nil {
		t.Fatal("foreign public key authenticated the material")
	}
	objects.body[0] ^= 1
	if _, err := reader.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID); err == nil {
		t.Fatal("changed OCI bytes authenticated under the committed receipt")
	}
	if objects.putCount != 1 || receipts.commitCount != 1 {
		t.Fatalf("reader mutated material: puts=%d commits=%d", objects.putCount, receipts.commitCount)
	}
}
