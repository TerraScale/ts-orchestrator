package keylease

import (
	"errors"
	"testing"
	"time"
)

func TestWriteCatalogHeldLockRefusesThenSucceedsAfterRelease(t *testing.T) {
	config, catalog := fixture(t)

	unlock, err := catalogLock(config.CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = WriteCatalog(config.CatalogPath, catalog)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("WriteCatalog with held lock error = %v, want ErrUnavailable", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("held-lock write took %s; lock contention must fail immediately", elapsed)
	}

	unlock()
	catalog.Entries[0].Revoked = true
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatalf("WriteCatalog after lock release: %v", err)
	}
	stored, err := ReadCatalog(config.CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Entries[0].Revoked {
		t.Fatal("catalog update was not committed after lock release")
	}
}
