package keylease

import (
	"context"
	"testing"
	"time"
)

func TestDestructionSurvivesRestartAndRefusesLateIssuance(t *testing.T) {
	config, catalog := fixture(t)
	entry := catalog.Entries[0]
	now := time.Now().UTC()
	receipt, err := destroyDatabase(t.Context(), config.CatalogPath, entry.Binding.Scope(), "delete-operation", now)
	if err != nil || receipt.RemovedCopies != 1 || !receipt.LeasesExpireAt.Equal(now.Add(1800*time.Second)) {
		t.Fatalf("invalid local destruction receipt: %+v %v", receipt, err)
	}
	stored, err := ReadCatalog(config.CatalogPath)
	if err != nil || len(stored.Entries) != 0 || len(stored.Tombstones) != 1 {
		t.Fatal("wrappers retained or tombstone lost")
	}
	replay, err := DestroyDatabase(t.Context(), config.CatalogPath, entry.Binding.Scope(), "delete-operation")
	if err != nil || !sameTombstone(receipt, replay) {
		t.Fatal("restart changed destruction horizon")
	}
	if _, err := DestroyDatabase(t.Context(), config.CatalogPath, entry.Binding.Scope(), "other-operation"); err == nil {
		t.Fatal("operation identity changed")
	}
	if err := MergeEntries(config.CatalogPath, []Entry{entry}); err == nil {
		t.Fatal("late wrapped delivery resurrected database")
	}
	if err := WriteCatalog(config.CatalogPath, catalog); err == nil {
		t.Fatal("stale full-catalog write erased tombstone")
	}
	target := ProvisionTarget{Binding: entry.Binding, CryptoEndpoint: entry.CryptoEndpoint, KEKID: entry.KEKID, KEKVersionID: entry.KEKVersionID, LeaseSeconds: entry.LeaseSeconds, NotAfter: entry.NotAfter}
	target.Binding.KeyVersion = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	if err := provision(t.Context(), config.CatalogPath, []ProvisionTarget{target}, func(context.Context, ProvisionTarget, []byte) (string, error) {
		t.Fatal("destroyed database reached Vault issuance")
		return "", nil
	}); err == nil {
		t.Fatal("new key version resurrected database")
	}
	if err := InitializeCatalog(config.CatalogPath); err != nil {
		t.Fatal(err)
	}
	stored, err = ReadCatalog(config.CatalogPath)
	if err != nil || len(stored.Tombstones) != 1 {
		t.Fatal("initialization erased tombstone")
	}
}
