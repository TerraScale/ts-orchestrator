package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
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
